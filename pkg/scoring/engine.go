// Package scoring implements the deterministic Lumen scoring engine.
//
// The engine is stateless: construct one Engine with a RuleStore and OverlayStore,
// then call Score for each assessment. It is safe for concurrent use after construction.
package scoring

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/Qwentrix/lumen-scoring/pkg/rules"
	"github.com/Qwentrix/lumen-scoring/pkg/types"
)

// Engine is the stateless scoring engine. Construct with NewEngine.
type Engine struct {
	ruleStore    *rules.RuleStore
	overlayStore *rules.OverlayStore
}

// NewEngine constructs a scoring engine with the provided rule and overlay stores.
// Both stores must be non-nil; returns an error if either is nil.
func NewEngine(ruleStore *rules.RuleStore, overlayStore *rules.OverlayStore) (*Engine, error) {
	if ruleStore == nil {
		return nil, fmt.Errorf("scoring: ruleStore must not be nil")
	}
	if overlayStore == nil {
		return nil, fmt.Errorf("scoring: overlayStore must not be nil")
	}
	return &Engine{
		ruleStore:    ruleStore,
		overlayStore: overlayStore,
	}, nil
}

// Score runs the deterministic scoring algorithm against the provided input
// and returns a fully populated ReportPayload.
//
// The algorithm is documented in docs-2026/assessment-tool/02-design.md §7
// (internal monorepo) and in docs/METHODOLOGY.md in the public scanner repo.
// No ML, no randomness. Same input always produces the same output.
func (e *Engine) Score(input types.ScoringInput) (*types.ReportPayload, error) {
	overlay := e.overlayStore.ByID(input.Industry)
	if overlay == nil {
		// Fall back to all-1.0 multipliers when the industry has no overlay.
		// This keeps the engine functional during content bootstrapping.
		overlay = &rules.IndustryOverlay{
			ID:          input.Industry,
			DisplayName: input.Industry,
		}
	}

	// Evaluate all rules and collect triggered findings.
	triggered := e.evaluateRules(input, overlay)

	// Compute per-domain scores and explain traces.
	domainResults := make([]types.DomainResult, 0, len(types.AllDomains))
	domainScores := make(map[types.DomainID]int, len(types.AllDomains))

	for _, domainID := range types.AllDomains {
		result := computeDomainResult(domainID, triggered, floorLoss(input, domainID))
		domainResults = append(domainResults, result)
		domainScores[domainID] = result.Score
	}

	// Sort domain results by overlay weight descending (highest-weight domain first)
	// to match the PDF and web presentation order.
	sort.Slice(domainResults, func(i, j int) bool {
		wi := overlay.DomainMultiplier(domainResults[i].DomainID)
		wj := overlay.DomainMultiplier(domainResults[j].DomainID)
		return wi > wj
	})

	// Compute overall weighted mean score.
	overallScore := computeOverallScore(domainScores, overlay)
	overallGrade := types.Grade(overallScore)

	// Build top-3 risks: sort all triggered findings by contribution desc, severity desc.
	allFindings := make([]types.FindingResult, 0, len(triggered))
	for _, f := range triggered {
		allFindings = append(allFindings, f)
	}
	sortFindingsByContribution(allFindings)
	topN := 3
	if len(allFindings) < topN {
		topN = len(allFindings)
	}
	topRisks := allFindings[:topN]

	// Build what-to-fix-first (top-5, deduped by remediation text).
	whatToFixFirst := buildRemediations(allFindings, 5)

	// Build framework coverage summary.
	frameworkSummary := buildFrameworkSummary(allFindings)

	return &types.ReportPayload{
		AssessmentID:     input.AssessmentID,
		GeneratedAt:      time.Now().UTC(),
		Industry:         input.Industry,
		CompanySize:      input.CompanySize,
		OverallScore:     overallScore,
		OverallGrade:     overallGrade,
		Domains:          domainResults,
		TopRisks:         topRisks,
		WhatToFixFirst:   whatToFixFirst,
		FrameworkSummary: frameworkSummary,
		ScannerUsed:      input.ScannerFindings != nil,
	}, nil
}

// evaluateRules tests every rule in the store against the input and returns
// the map of triggered findings indexed by rule ID.
func (e *Engine) evaluateRules(
	input types.ScoringInput,
	overlay *rules.IndustryOverlay,
) map[string]types.FindingResult {
	triggered := make(map[string]types.FindingResult)

	for _, rule := range e.ruleStore.All() {
		triggeredBy := evaluateDetect(rule, input)
		if len(triggeredBy) == 0 {
			continue
		}

		industryMult := rule.IndustryMultiplier(input.Industry)
		sevFactor := types.SeverityFactor(rule.Severity)
		contribution := rule.DefaultWeight * industryMult * sevFactor
		// Cap individual contribution at 1.0 (a single finding cannot exceed full loss).
		if contribution > 1.0 {
			contribution = 1.0
		}

		// Copy framework refs from rule to finding.
		frameworks := make([]types.FrameworkRef, len(rule.Frameworks))
		copy(frameworks, rule.Frameworks)

		// Collect Micelium product names for the alignment bonus in buildRemediations.
		var miceliumProducts []string
		for _, p := range rule.MiceliumProducts {
			if p.Product != "" {
				miceliumProducts = append(miceliumProducts, p.Product)
			}
		}

		triggered[rule.ID] = types.FindingResult{
			RuleID:             rule.ID,
			Domain:             rule.Domain,
			Title:              rule.Title,
			Severity:           rule.Severity,
			DefaultWeight:      rule.DefaultWeight,
			IndustryMultiplier: industryMult,
			SeverityFactor:     sevFactor,
			Contribution:       contribution,
			TriggeredBy:        triggeredBy,
			Frameworks:         frameworks,
			RemediationPlain:   rule.RemediationPlain,
			MiceliumProducts:   miceliumProducts,
		}
		_ = overlay // overlay is already consumed via rule.IndustryMultiplier above
	}
	return triggered
}

// evaluateDetect checks whether a rule's detect conditions fire against the input.
// Returns a slice of the triggering condition keys (question IDs or probe keys),
// or nil if the rule does not fire.
func evaluateDetect(rule *rules.FindingRule, input types.ScoringInput) []string {
	var triggeredBy []string

	// Evaluate questionnaire conditions.
	for _, cond := range rule.Detect.Questionnaire {
		key, op, val, err := parseCondition(string(cond))
		if err != nil {
			continue
		}
		if op != "==" {
			continue // only == is supported for questionnaire conditions in v1
		}
		if answer, ok := input.Answers[key]; ok && answer == val {
			triggeredBy = append(triggeredBy, key)
		}
	}

	// Evaluate scanner conditions if scanner findings are present.
	if input.ScannerFindings != nil {
		for _, cond := range rule.Detect.Scanner {
			key, _, _, err := parseCondition(string(cond))
			if err != nil {
				continue
			}
			if evalScannerCondition(cond, input.ScannerFindings) {
				triggeredBy = append(triggeredBy, key)
			}
		}
	}

	return triggeredBy
}

// computeDomainResult builds a DomainResult from the set of triggered findings
// for a single domain. floor is the minimum loss for this domain (from floorLoss);
// pass 0 to get the original full-assessment behaviour.
func computeDomainResult(
	domainID types.DomainID,
	triggered map[string]types.FindingResult,
	floor float64,
) types.DomainResult {
	var domainFindings []types.FindingResult
	for _, f := range triggered {
		if f.Domain == domainID {
			domainFindings = append(domainFindings, f)
		}
	}

	// Sort by contribution desc, then severity desc, then RuleID asc for stability.
	sortFindingsByContribution(domainFindings)

	// Sum contributions; cap at 1.0.
	var rawLoss float64
	for _, f := range domainFindings {
		rawLoss += f.Contribution
	}
	cappedLoss := math.Min(1.0, rawLoss)
	if floor > cappedLoss {
		cappedLoss = floor
	}
	score := int(math.Round(100.0 * (1.0 - cappedLoss)))
	grade := types.Grade(score)

	// Build explain steps.
	steps := make([]types.ExplainStep, 0, len(domainFindings))
	for _, f := range domainFindings {
		steps = append(steps, types.ExplainStep{
			FindingID:             f.RuleID,
			Title:                 f.Title,
			Severity:              f.Severity,
			DefaultWeight:         f.DefaultWeight,
			IndustryMultiplier:    f.IndustryMultiplier,
			SeverityFactor:        f.SeverityFactor,
			EffectiveContribution: f.Contribution,
			TriggeredBy:           f.TriggeredBy,
			Frameworks:            f.Frameworks,
		})
	}

	formula := "100 * (1 - min(1.0, Σ contributions))"
	if floor > 0 {
		formula = "100 * (1 - max(floor, min(1.0, Σ contributions)))"
	}
	explain := types.DomainExplain{
		DomainID:    domainID,
		Formula:     formula,
		Steps:       steps,
		RawLoss:     rawLoss,
		CappedLoss:  cappedLoss,
		DomainScore: score,
	}

	return types.DomainResult{
		DomainID:     domainID,
		Score:        score,
		Grade:        grade,
		PlainSummary: domainPlainSummary(domainID, grade, len(domainFindings)),
		Findings:     domainFindings,
		Explain:      explain,
	}
}

// floorLoss returns floor*(1-answered/total) for a domain, or 0 when no floor/coverage.
// It is used by the spine/preliminary funnel path to prevent sparse answer sets from
// scoring falsely high. When DomainCoverage or Floors is nil the function returns 0,
// making the full-assessment path byte-for-byte unchanged.
func floorLoss(input types.ScoringInput, d types.DomainID) float64 {
	f, ok := input.Floors[d]
	if !ok || f <= 0 {
		return 0
	}
	cov, ok := input.DomainCoverage[d]
	if !ok || cov.Total <= 0 {
		return 0
	}
	frac := float64(cov.Answered) / float64(cov.Total)
	if frac < 0 {
		frac = 0
	}
	if frac > 1 {
		frac = 1
	}
	return f * (1 - frac)
}

// computeOverallScore computes the overall weighted-mean score across all five domains.
func computeOverallScore(
	domainScores map[types.DomainID]int,
	overlay *rules.IndustryOverlay,
) int {
	var weightedSum, totalWeight float64
	for _, domainID := range types.AllDomains {
		score := domainScores[domainID]
		weight := overlay.DomainMultiplier(domainID)
		weightedSum += float64(score) * weight
		totalWeight += weight
	}
	if totalWeight == 0 {
		return 0
	}
	return int(math.Round(weightedSum / totalWeight))
}

// alignmentBonus returns 1.2 if the finding references any Micelium product, else 1.0.
// Used by buildRemediations to weight the what-to-fix-first ordering per design §7.
func alignmentBonus(f types.FindingResult) float64 {
	if len(f.MiceliumProducts) > 0 {
		return 1.2
	}
	return 1.0
}

// buildRemediations constructs the top-N "what to fix first" remediation list.
// Deduplicates by plain-text remediation content; applies a 1.2× alignment bonus
// for findings that reference any Micelium product (design §7: sort by
// contribution × alignmentBonus before selecting top-N).
func buildRemediations(findings []types.FindingResult, topN int) []types.Remediation {
	// Sort by contribution × alignmentBonus descending (stable to preserve RuleID tie-break).
	sorted := make([]types.FindingResult, len(findings))
	copy(sorted, findings)
	sort.SliceStable(sorted, func(i, j int) bool {
		wi := sorted[i].Contribution * alignmentBonus(sorted[i])
		wj := sorted[j].Contribution * alignmentBonus(sorted[j])
		if wi != wj {
			return wi > wj
		}
		return sorted[i].RuleID < sorted[j].RuleID
	})

	seen := make(map[string]bool)
	result := make([]types.Remediation, 0, topN)

	for _, f := range sorted {
		if len(result) >= topN {
			break
		}
		key := f.RemediationPlain
		if key == "" {
			key = f.RuleID
		}
		if seen[key] {
			continue
		}
		seen[key] = true

		result = append(result, types.Remediation{
			RuleID:           f.RuleID,
			Title:            f.Title,
			Domain:           f.Domain,
			Priority:         len(result) + 1,
			RemediationPlain: f.RemediationPlain,
			Contribution:     f.Contribution,
		})
	}
	return result
}

// buildFrameworkSummary aggregates framework references from all triggered findings,
// grouped by framework family (the prefix before the first space in the ID).
func buildFrameworkSummary(findings []types.FindingResult) []types.FrameworkCoverage {
	familyMap := make(map[string]map[string]types.FrameworkRef)

	for _, f := range findings {
		for _, fw := range f.Frameworks {
			family := frameworkFamily(fw.ID)
			if familyMap[family] == nil {
				familyMap[family] = make(map[string]types.FrameworkRef)
			}
			familyMap[family][fw.ID] = fw
		}
	}

	result := make([]types.FrameworkCoverage, 0, len(familyMap))
	for family, controls := range familyMap {
		refs := make([]types.FrameworkRef, 0, len(controls))
		for _, ref := range controls {
			refs = append(refs, ref)
		}
		sort.Slice(refs, func(i, j int) bool { return refs[i].ID < refs[j].ID })
		result = append(result, types.FrameworkCoverage{
			FrameworkID: family,
			Controls:    refs,
		})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].FrameworkID < result[j].FrameworkID })
	return result
}

// sortFindingsByContribution sorts findings by contribution desc, severity desc, RuleID asc.
func sortFindingsByContribution(findings []types.FindingResult) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Contribution != findings[j].Contribution {
			return findings[i].Contribution > findings[j].Contribution
		}
		si := types.SeverityFactor(findings[i].Severity)
		sj := types.SeverityFactor(findings[j].Severity)
		if si != sj {
			return si > sj
		}
		return findings[i].RuleID < findings[j].RuleID
	})
}

// domainPlainSummary returns a one-sentence domain result summary.
// Placeholder — real summaries are driven by content (YAML) in v1.1.
func domainPlainSummary(domain types.DomainID, grade string, findingsCount int) string {
	if findingsCount == 0 {
		return fmt.Sprintf("No issues detected in %s — grade %s.", domain, grade)
	}
	return fmt.Sprintf("%d issue(s) detected in %s — grade %s.", findingsCount, domain, grade)
}

// frameworkFamily extracts a short family label from a framework citation ID.
// e.g. "EU AI Act Art. 26" -> "EU AI Act"
// e.g. "NIST CSF RS.MI-3"  -> "NIST CSF"
// e.g. "HIPAA 164.312(a)(1)" -> "HIPAA"
// Falls back to the full ID if no space is found.
func frameworkFamily(id string) string {
	for i, ch := range id {
		if ch == ' ' {
			prefix := id[:i]
			switch prefix {
			case "NIST":
				// Extend one more word: "NIST CSF", "NIST SP", "NIST AI".
				rest := id[i+1:]
				for j, c := range rest {
					if c == ' ' {
						return id[:i+1+j]
					}
				}
				// Only two tokens total (e.g. "NIST CSF") — return the whole string.
				return id
			case "EU":
				// Extend TWO more words to reach "EU AI Act".
				rest := id[i+1:]
				firstSpace := -1
				for j, c := range rest {
					if c == ' ' {
						firstSpace = j
						break
					}
				}
				if firstSpace < 0 {
					// Only "EU <word>", no second extension possible.
					return id
				}
				rest2 := rest[firstSpace+1:]
				for j, c := range rest2 {
					if c == ' ' {
						return id[:i+1+firstSpace+1+j]
					}
				}
				// Three tokens total (e.g. "EU AI Act") — return everything so far.
				return id[:i+1+firstSpace+1+len(rest2)]
			}
			return prefix
		}
	}
	return id
}
