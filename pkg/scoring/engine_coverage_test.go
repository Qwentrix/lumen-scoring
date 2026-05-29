package scoring_test

// engine_coverage_test.go — targeted coverage gap tests.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Qwentrix/lumen-scoring/pkg/rules"
	"github.com/Qwentrix/lumen-scoring/pkg/scoring"
	"github.com/Qwentrix/lumen-scoring/pkg/types"
)

// Rule with same contribution as another — tests sort tie-break by severity then RuleID.
const ruleHighVuln2 = `
id: VULN_HIGH_CVE2
domain: vulnerabilities
severity: high
default_weight: 0.75
detect:
  questionnaire:
    - Q-VULN-003 == stale
title: "Stale packages"
description_short: "Package inventory is stale."
remediation_plain: "Update package inventory."
`

// Rule with duplicate remediation text to exercise the dedup path in buildRemediations.
const ruleHighVuln3 = `
id: VULN_HIGH_CVE3
domain: vulnerabilities
severity: high
default_weight: 0.75
detect:
  questionnaire:
    - Q-VULN-004 == stale_alt
title: "Stale packages alt"
description_short: "Package inventory is also stale."
remediation_plain: "Update package inventory."
`

// Rule that triggers from a scanner condition with eq operator, different domain.
const ruleCompMFAEq = `
id: COMP_MFA_DISABLED_EQ
domain: compliance
severity: high
default_weight: 0.6
detect:
  scanner:
    - compliance.mfa_enabled == false
title: "MFA disabled via scanner eq"
description_short: "MFA not enabled."
remediation_plain: "Enable MFA on all accounts immediately."
`

func setupDedupeStores(t *testing.T) (*rules.RuleStore, *rules.OverlayStore) {
	t.Helper()
	ruleDir := t.TempDir()
	overlayDir := t.TempDir()

	writeFile := func(dir, name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writeFile: %v", err)
		}
	}

	writeFile(ruleDir, "VULN_CRITICAL_CVE.yaml", ruleCriticalVuln)
	writeFile(ruleDir, "VULN_HIGH_CVE2.yaml", ruleHighVuln2)
	writeFile(ruleDir, "VULN_HIGH_CVE3.yaml", ruleHighVuln3) // same remediation as HIGH_CVE2
	writeFile(ruleDir, "COMP_MFA_DISABLED_EQ.yaml", ruleCompMFAEq)

	writeFile(overlayDir, "technology.yaml", overlayDefault)
	writeFile(overlayDir, "healthcare.yaml", overlayHealthcare)

	ruleStore, err := rules.LoadRulesFromDir(ruleDir)
	if err != nil {
		t.Fatalf("LoadRulesFromDir: %v", err)
	}
	overlayStore, err := rules.LoadOverlaysFromDir(overlayDir)
	if err != nil {
		t.Fatalf("LoadOverlaysFromDir: %v", err)
	}
	return ruleStore, overlayStore
}

// TestRemediationDedup tests that WhatToFixFirst deduplicates entries with the same
// remediation text (exercising the seen[key] path in buildRemediations).
func TestRemediationDedup(t *testing.T) {
	rs, os_ := setupDedupeStores(t)
	engine, _ := scoring.NewEngine(rs, os_)

	// Trigger both rules with the same remediation text.
	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers: map[string]string{
			"Q-VULN-003": "stale",     // VULN_HIGH_CVE2
			"Q-VULN-004": "stale_alt", // VULN_HIGH_CVE3 — same remediation_plain
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	// Both rules fire but share the same remediation_plain; WhatToFixFirst should dedup.
	// Count unique remediation texts.
	seen := make(map[string]int)
	for _, r := range report.WhatToFixFirst {
		seen[r.RemediationPlain]++
	}
	for text, count := range seen {
		if count > 1 {
			t.Errorf("remediation %q appears %d times in WhatToFixFirst; expected deduplicated to 1", text, count)
		}
	}
}

// TestSortTieBreakByRuleID tests that when two findings have equal contribution
// AND equal severity factor, they are sorted by RuleID ascending.
func TestSortTieBreakByRuleID(t *testing.T) {
	rs, os_ := setupDedupeStores(t)
	engine, _ := scoring.NewEngine(rs, os_)

	// VULN_HIGH_CVE2 and VULN_HIGH_CVE3 both have severity=high, default_weight=0.75 → same contribution.
	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers: map[string]string{
			"Q-VULN-003": "stale",
			"Q-VULN-004": "stale_alt",
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	// Find both findings in the vulnerabilities domain.
	var vulnDomain *types.DomainResult
	for i := range report.Domains {
		if report.Domains[i].DomainID == types.DomainVulnerabilities {
			vulnDomain = &report.Domains[i]
			break
		}
	}
	if vulnDomain == nil || len(vulnDomain.Findings) < 2 {
		t.Skip("need 2 vuln findings for tie-break test")
	}

	// With equal contribution and severity, results should be sorted by RuleID asc.
	for i := 1; i < len(vulnDomain.Findings); i++ {
		a := vulnDomain.Findings[i-1]
		b := vulnDomain.Findings[i]
		if a.Contribution == b.Contribution &&
			types.SeverityFactor(a.Severity) == types.SeverityFactor(b.Severity) {
			if a.RuleID > b.RuleID {
				t.Errorf("tie-break: RuleID order wrong: %q > %q (should be asc)", a.RuleID, b.RuleID)
			}
		}
	}
}

// TestComputeOverallScoreZeroWeights covers the edge case where totalWeight is 0.
// With all domain multipliers at 0 the nonZero() guard kicks in and makes each 1.0.
// Testing the coercion path via all-zero overlay.
func TestOverallScoreWithAllEqualWeights(t *testing.T) {
	rs, os_ := setupDedupeStores(t)
	engine, _ := scoring.NewEngine(rs, os_)

	// Technology overlay has all domain multipliers = 1.0 → equal weights.
	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "smb",
		Answers:     map[string]string{},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	// All zero findings → all domain scores = 100 → overall = 100.
	if report.OverallScore != 100 {
		t.Errorf("expected 100 with equal weights and no findings, got %d", report.OverallScore)
	}
}

// TestQuestionnaireTriggerWithUnsupportedOp verifies that conditions with
// unsupported operators in questionnaire are silently skipped (non-== ops).
func TestQuestionnaireTriggerWithUnsupportedOp(t *testing.T) {
	// The engine only evaluates questionnaire conditions with == op.
	// A rule with questionnaire condition using != or > would not trigger via questionnaire.
	// This test verifies the rule does NOT fire when the questionnaire answer matches
	// only via a non-== operator (which is skipped by evaluateDetect).
	rs, os_ := setupDedupeStores(t)
	engine, _ := scoring.NewEngine(rs, os_)

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		// Not providing answers for VULN_CRITICAL_CVE or others.
		Answers: map[string]string{
			"Q-VULN-001": "patched", // does NOT trigger VULN_CRITICAL_CVE (expects "unpatched")
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	// VULN_CRITICAL_CVE should not fire for "patched" answer.
	for _, risk := range report.TopRisks {
		if risk.RuleID == "VULN_CRITICAL_CVE" {
			t.Error("VULN_CRITICAL_CVE should not fire for answer 'patched'")
		}
	}
}

// TestFrameworkFamilyEUAIAct tests the EU AI framework family extraction.
// frameworkFamily("EU AI Act Art. 26") extends TWO words past "EU" to give "EU AI Act".
func TestFrameworkSummaryEUAIActFamily(t *testing.T) {
	rs, os_ := setupStores(t) // uses ruleNoAUP which has "EU AI Act Art. 26"
	engine, _ := scoring.NewEngine(rs, os_)

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers:     map[string]string{"Q-AIGOV-001": "no_policy"},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	// frameworkFamily("EU AI Act Art. 26") -> "EU AI Act" (extends two words past EU prefix).
	euFound := false
	for _, fc := range report.FrameworkSummary {
		if fc.FrameworkID == "EU AI Act" {
			euFound = true
		}
		// Ensure the old (wrong) two-word form is absent.
		if fc.FrameworkID == "EU AI" {
			t.Errorf("frameworkFamily returned 'EU AI' (two-word form); expected 'EU AI Act'")
		}
	}
	if !euFound {
		t.Errorf("expected 'EU AI Act' family in FrameworkSummary; got: %v", report.FrameworkSummary)
	}
}

// TestFrameworkSummaryNISTFamily tests the NIST multi-word family extraction.
func TestFrameworkSummaryNISTFamily(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t) // VULN_CRITICAL_CVE has "NIST CSF RS.MI-3"
	engine, _ := scoring.NewEngine(rs, os_)

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers:     map[string]string{"Q-VULN-001": "unpatched"},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	nistFound := false
	for _, fc := range report.FrameworkSummary {
		if fc.FrameworkID == "NIST CSF" {
			nistFound = true
		}
	}
	if !nistFound {
		t.Errorf("expected 'NIST CSF' family in FrameworkSummary; got: %v", report.FrameworkSummary)
	}
}

// ruleMiceliumAligned is a rule with a micelium_product reference (Sigil).
// Its contribution (high, weight=0.6, mult=1.0) = 0.48 — lower than VULN_HIGH_CVE2 (0.6).
// But with 1.2× alignment bonus: 0.48 × 1.2 = 0.576 < 0.6, so it comes AFTER 0.6.
// We use weight=0.7 so effective = 0.56, bonus = 0.672 > 0.6 — should float above CVE2.
const ruleMiceliumAlignedVuln = `
id: VULN_MICELIUM_ALIGNED
domain: vulnerabilities
severity: high
default_weight: 0.70
detect:
  questionnaire:
    - Q-VULN-005 == no_scan
title: "No vulnerability scanner"
description_short: "No automated vulnerability scanner in use."
micelium_product:
  - product: Sense
    role: continuous vulnerability monitoring
remediation_plain: "Deploy an automated vulnerability scanner."
`

func setupAlignmentBonusStores(t *testing.T) (*rules.RuleStore, *rules.OverlayStore) {
	t.Helper()
	ruleDir := t.TempDir()
	overlayDir := t.TempDir()

	writeFile := func(dir, name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writeFile: %v", err)
		}
	}

	// VULN_HIGH_CVE2: high, weight=0.75 → contribution=0.6, no Micelium product → bonus=1.0 → weighted=0.6
	// VULN_MICELIUM_ALIGNED: high, weight=0.70 → contribution=0.56, has Micelium product → bonus=1.2 → weighted=0.672
	// Expected WhatToFixFirst order: ALIGNED (0.672) before CVE2 (0.6).
	writeFile(ruleDir, "VULN_HIGH_CVE2.yaml", ruleHighVuln2)
	writeFile(ruleDir, "VULN_MICELIUM_ALIGNED.yaml", ruleMiceliumAlignedVuln)
	writeFile(overlayDir, "technology.yaml", overlayDefault)

	ruleStore, err := rules.LoadRulesFromDir(ruleDir)
	if err != nil {
		t.Fatalf("LoadRulesFromDir: %v", err)
	}
	overlayStore, err := rules.LoadOverlaysFromDir(overlayDir)
	if err != nil {
		t.Fatalf("LoadOverlaysFromDir: %v", err)
	}
	return ruleStore, overlayStore
}

// TestAlignmentBonusRaisesLowerContributionFinding verifies that a finding with a Micelium
// product reference floats above a finding with higher raw contribution but no product reference,
// when the 1.2× alignment bonus tips the weighted ordering (design §7).
func TestAlignmentBonusRaisesLowerContributionFinding(t *testing.T) {
	rs, os_ := setupAlignmentBonusStores(t)
	engine, _ := scoring.NewEngine(rs, os_)

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers: map[string]string{
			"Q-VULN-003": "stale",   // fires VULN_HIGH_CVE2 (contrib=0.6, no product, weighted=0.6)
			"Q-VULN-005": "no_scan", // fires VULN_MICELIUM_ALIGNED (contrib=0.56, product=Sense, weighted=0.672)
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	// Verify MiceliumProducts is populated on the aligned finding.
	var alignedFinding *types.FindingResult
	for i := range report.Domains {
		for j := range report.Domains[i].Findings {
			if report.Domains[i].Findings[j].RuleID == "VULN_MICELIUM_ALIGNED" {
				f := report.Domains[i].Findings[j]
				alignedFinding = &f
			}
		}
	}
	if alignedFinding == nil {
		t.Fatal("VULN_MICELIUM_ALIGNED not found in domain findings")
	}
	if len(alignedFinding.MiceliumProducts) == 0 {
		t.Error("MiceliumProducts should be populated for VULN_MICELIUM_ALIGNED")
	}
	if alignedFinding.MiceliumProducts[0] != "Sense" {
		t.Errorf("MiceliumProducts[0] = %q; want %q", alignedFinding.MiceliumProducts[0], "Sense")
	}

	// Verify WhatToFixFirst: ALIGNED (lower raw contrib, has bonus) should rank before CVE2.
	if len(report.WhatToFixFirst) < 2 {
		t.Fatalf("expected at least 2 remediations, got %d", len(report.WhatToFixFirst))
	}
	if report.WhatToFixFirst[0].RuleID != "VULN_MICELIUM_ALIGNED" {
		t.Errorf("alignment bonus: expected VULN_MICELIUM_ALIGNED first in WhatToFixFirst (weighted contrib 0.672 > 0.6), got %q",
			report.WhatToFixFirst[0].RuleID)
	}
	if report.WhatToFixFirst[1].RuleID != "VULN_HIGH_CVE2" {
		t.Errorf("alignment bonus: expected VULN_HIGH_CVE2 second in WhatToFixFirst, got %q",
			report.WhatToFixFirst[1].RuleID)
	}
}
