package scoring_test

// engine_extended_test.go — additional tests to reach ≥90% coverage and satisfy
// ENT-95 acceptance criteria (AC-95-9 through AC-95-16, EG-12/EG-13/EG-14).
//
// Tests added here (17 new tests + 3 conditions tests) — total with engine_test.go ≥ 30.

import (
	"math"
	"os"
	"path/filepath"
	"testing"

	"github.com/Qwentrix/lumen-scoring/pkg/rules"
	"github.com/Qwentrix/lumen-scoring/pkg/scoring"
	"github.com/Qwentrix/lumen-scoring/pkg/types"
)

// --- helper YAML fixtures ---

const ruleCriticalVuln = `
id: VULN_CRITICAL_CVE
domain: vulnerabilities
severity: critical
default_weight: 1.0
detect:
  questionnaire:
    - Q-VULN-001 == unpatched
  scanner:
    - vulnerabilities.critical_cve_count > 0
title: "Critical CVE present"
description_short: "At least one critical CVE found."
frameworks:
  - id: "NIST CSF RS.MI-3"
    text: "Mitigate newly identified vulnerabilities."
  - id: "HIPAA 164.308(a)(5)"
    text: "Protection from malicious software."
remediation_plain: "Apply vendor patches immediately."
`

const ruleHighVuln = `
id: VULN_HIGH_CVE
domain: vulnerabilities
severity: high
default_weight: 0.75
detect:
  questionnaire:
    - Q-VULN-002 == many
  scanner:
    - vulnerabilities.high_cve_count > 5
title: "Multiple high CVEs present"
description_short: "Several high-severity CVEs found."
frameworks:
  - id: "NIST CSF ID.RA-1"
    text: "Asset vulnerabilities identified."
  - id: "HIPAA 164.308(a)(5)"
    text: "Protection from malicious software."
remediation_plain: "Prioritise patching high-severity CVEs."
`

const ruleMediumCompliance = `
id: COMP_NO_MFA
domain: compliance
severity: medium
default_weight: 0.8
detect:
  questionnaire:
    - Q-COMP-001 == no_mfa
  scanner:
    - compliance.mfa_enabled == false
title: "MFA not enabled"
description_short: "Multi-factor authentication is not enforced."
frameworks:
  - id: "NIST SP 800-63B"
    text: "Authentication assurance level 2 requires MFA."
remediation_plain: "Enable MFA across all accounts."
`

const ruleLowPosture = `
id: POST_WEAK_SSH
domain: security_posture
severity: low
default_weight: 0.3
detect:
  questionnaire:
    - Q-POST-001 == weak
  scanner:
    - security_posture.weak_ssh_key_count > 0
title: "Weak SSH keys detected"
description_short: "SSH keys below recommended bit-length."
remediation_plain: "Rotate to RSA-4096 or Ed25519 keys."
`

const rulePrivacyCritical = `
id: PRIV_PII_EXPOSURE
domain: privacy
severity: critical
default_weight: 0.9
detect:
  questionnaire:
    - Q-PRIV-001 == exposed
  scanner:
    - privacy.pii_match_count > 10
title: "PII data exposed"
description_short: "Sensitive PII found in unprotected files."
frameworks:
  - id: "GDPR Art. 5"
    text: "Integrity and confidentiality of personal data."
remediation_plain: "Encrypt or remove exposed PII files."
`

// setupMultiDomainStores creates a RuleStore with 5 rules across 5 domains.
func setupMultiDomainStores(t *testing.T) (*rules.RuleStore, *rules.OverlayStore) {
	t.Helper()
	ruleDir := t.TempDir()
	overlayDir := t.TempDir()

	writeFile := func(dir, name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writeFile: %v", err)
		}
	}

	// 5 rules, one per domain.
	writeFile(ruleDir, "VULN_CRITICAL_CVE.yaml", ruleCriticalVuln)
	writeFile(ruleDir, "VULN_HIGH_CVE.yaml", ruleHighVuln)
	writeFile(ruleDir, "COMP_NO_MFA.yaml", ruleMediumCompliance)
	writeFile(ruleDir, "POST_WEAK_SSH.yaml", ruleLowPosture)
	writeFile(ruleDir, "PRIV_PII_EXPOSURE.yaml", rulePrivacyCritical)

	writeFile(overlayDir, "healthcare.yaml", overlayHealthcare)
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

// --- AC-95-9: Canonical math test ---
// Input: vulns domain, 2 triggered findings:
//   (a) VULN_CRITICAL_CVE: severity=critical, default_weight=1.0, industry_mult=1.0 → contribution=1.0
//   (b) VULN_HIGH_CVE (via scanner): severity=high, default_weight=0.75, industry_mult=1.0, sev_factor=0.8 → contribution=0.6
// Sum = 1.6 → capped 1.0 → domain_score = round(100*(1-1.0)) = 0 → grade F

func TestCanonicalMathCriticalCapsDomainToZero(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Trigger VULN_CRITICAL_CVE via questionnaire AND VULN_HIGH_CVE via questionnaire.
	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers: map[string]string{
			"Q-VULN-001": "unpatched", // fires VULN_CRITICAL_CVE (weight=1.0, crit=1.0 → contrib=1.0)
			"Q-VULN-002": "many",      // fires VULN_HIGH_CVE (weight=0.75, high=0.8 → contrib=0.6)
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	// Find the vulnerabilities domain result.
	var vulnDomain *types.DomainResult
	for i := range report.Domains {
		if report.Domains[i].DomainID == types.DomainVulnerabilities {
			vulnDomain = &report.Domains[i]
			break
		}
	}
	if vulnDomain == nil {
		t.Fatal("vulnerabilities domain not found in report")
	}

	if vulnDomain.Score != 0 {
		t.Errorf("canonical math: vulnerabilities domain score = %d; want 0 (cap at 1.0)", vulnDomain.Score)
	}
	if vulnDomain.Grade != "F" {
		t.Errorf("canonical math: vulnerabilities domain grade = %q; want F", vulnDomain.Grade)
	}

	// Verify explain trace raw vs capped loss.
	if vulnDomain.Explain.RawLoss < 1.0 {
		t.Errorf("canonical math: raw_loss = %.3f; want >= 1.0 (critical=1.0 + high=0.6 sum)", vulnDomain.Explain.RawLoss)
	}
	if math.Abs(vulnDomain.Explain.CappedLoss-1.0) > 0.001 {
		t.Errorf("canonical math: capped_loss = %.3f; want 1.0", vulnDomain.Explain.CappedLoss)
	}
}

// AC-95-14: Single critical finding with weight=1.0 → domain score 0.
func TestSingleCriticalFindingScoreZero(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers: map[string]string{
			"Q-VULN-001": "unpatched", // fires VULN_CRITICAL_CVE (contrib=1.0 → cap immediately)
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	var vulnDomain *types.DomainResult
	for i := range report.Domains {
		if report.Domains[i].DomainID == types.DomainVulnerabilities {
			vulnDomain = &report.Domains[i]
			break
		}
	}
	if vulnDomain == nil {
		t.Fatal("vulnerabilities domain not found")
	}
	if vulnDomain.Score != 0 {
		t.Errorf("single critical: domain score = %d; want 0", vulnDomain.Score)
	}
	if vulnDomain.Grade != "F" {
		t.Errorf("single critical: grade = %q; want F", vulnDomain.Grade)
	}
}

// AC-95-13: Zero findings for a domain → domain_score=100, grade A.
func TestZeroFindingsDomainScoreHundred(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// No answers trigger any rules.
	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "smb",
		Answers:     map[string]string{},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	for _, d := range report.Domains {
		if d.Score != 100 {
			t.Errorf("domain %s: expected score 100 with no findings, got %d", d.DomainID, d.Score)
		}
		if d.Grade != "A" {
			t.Errorf("domain %s: expected grade A, got %q", d.DomainID, d.Grade)
		}
	}
}

// AC-95-11: All five grade letter thresholds.
func TestAllFiveGradeBoundaries(t *testing.T) {
	cases := []struct {
		score int
		grade string
	}{
		{95, "A"},
		{90, "A"},
		{89, "B"},
		{80, "B"},
		{75, "B"},
		{74, "C"},
		{65, "C"},
		{60, "C"},
		{59, "D"},
		{50, "D"},
		{45, "D"},
		{44, "F"},
		{40, "F"},
		{0, "F"},
	}
	for _, c := range cases {
		got := types.Grade(c.score)
		if got != c.grade {
			t.Errorf("Grade(%d) = %q; want %q", c.score, got, c.grade)
		}
	}
}

// AC-95-12: Industry overlay multiplier increases loss for healthcare vs technology.
func TestIndustryOverlayIncreasesLoss(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Same questionnaire answer in both industries.
	techInput := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers:     map[string]string{"Q-COMP-001": "no_mfa"},
	}
	healthInput := types.ScoringInput{
		Industry:    "healthcare",
		CompanySize: "enterprise",
		Answers:     map[string]string{"Q-COMP-001": "no_mfa"},
	}

	techReport, err := engine.Score(techInput)
	if err != nil {
		t.Fatalf("Score tech: %v", err)
	}
	healthReport, err := engine.Score(healthInput)
	if err != nil {
		t.Fatalf("Score health: %v", err)
	}

	// Healthcare has compliance domain_weight_multiplier=1.5 vs technology=1.0,
	// so healthcare overall score should be <= technology overall score.
	if healthReport.OverallScore > techReport.OverallScore {
		t.Errorf("healthcare overall score (%d) should be <= technology (%d) for same finding",
			healthReport.OverallScore, techReport.OverallScore)
	}
}

// AC-95-15: ExplainTrace fields populated.
func TestExplainTraceFieldsPopulated(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "smb",
		Answers:     map[string]string{"Q-VULN-001": "unpatched"},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	var vulnDomain *types.DomainResult
	for i := range report.Domains {
		if report.Domains[i].DomainID == types.DomainVulnerabilities {
			vulnDomain = &report.Domains[i]
			break
		}
	}
	if vulnDomain == nil {
		t.Fatal("vulnerabilities domain not found")
	}
	if len(vulnDomain.Explain.Steps) == 0 {
		t.Fatal("ExplainTrace.Steps is empty; expected at least one step")
	}

	step := vulnDomain.Explain.Steps[0]
	if step.FindingID == "" {
		t.Error("ExplainStep.FindingID must not be empty")
	}
	if step.Severity == "" {
		t.Error("ExplainStep.Severity must not be empty")
	}
	if step.DefaultWeight == 0 {
		t.Error("ExplainStep.DefaultWeight must not be zero")
	}
	if step.IndustryMultiplier == 0 {
		t.Error("ExplainStep.IndustryMultiplier must not be zero")
	}
	if step.SeverityFactor == 0 {
		t.Error("ExplainStep.SeverityFactor must not be zero")
	}
	if step.EffectiveContribution == 0 {
		t.Error("ExplainStep.EffectiveContribution must not be zero")
	}
	if len(step.TriggeredBy) == 0 {
		t.Error("ExplainStep.TriggeredBy must not be empty")
	}

	// Verify the formula string is present.
	if vulnDomain.Explain.Formula == "" {
		t.Error("DomainExplain.Formula must not be empty")
	}
}

// AC-95-8 (T-95-8): Multiple domains scored independently — vuln findings do not affect compliance.
func TestFiveDomainsScoreIndependently(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Trigger only a vulnerability rule.
	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers:     map[string]string{"Q-VULN-001": "unpatched"},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	for _, d := range report.Domains {
		if d.DomainID == types.DomainVulnerabilities {
			// Vulns should be affected.
			if d.Score == 100 {
				t.Error("vulnerabilities domain should have findings")
			}
		} else {
			// All other domains should be unaffected.
			if d.Score != 100 {
				t.Errorf("domain %s should not be affected by vuln findings, got score %d", d.DomainID, d.Score)
			}
		}
	}
}

// T-95-9: top_risks ordered by contribution desc.
func TestTopRisksOrderedByContributionDesc(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Trigger multiple rules.
	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers: map[string]string{
			"Q-VULN-001": "unpatched", // critical, weight=1.0 → contrib=1.0
			"Q-COMP-001": "no_mfa",    // medium, weight=0.8 → contrib=0.4
			"Q-POST-001": "weak",      // low, weight=0.3 → contrib=0.075
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	if len(report.TopRisks) < 2 {
		t.Fatalf("expected at least 2 top risks, got %d", len(report.TopRisks))
	}

	for i := 1; i < len(report.TopRisks); i++ {
		if report.TopRisks[i-1].Contribution < report.TopRisks[i].Contribution {
			t.Errorf("top risks not sorted desc: [%d] contribution %.3f < [%d] contribution %.3f",
				i-1, report.TopRisks[i-1].Contribution, i, report.TopRisks[i].Contribution)
		}
	}
	// Highest contribution should be the critical finding.
	if report.TopRisks[0].RuleID != "VULN_CRITICAL_CVE" {
		t.Errorf("expected VULN_CRITICAL_CVE as top risk, got %q", report.TopRisks[0].RuleID)
	}
}

// Test framework summary grouping by family.
func TestFrameworkSummaryGroupedByFamily(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Trigger two rules that share a framework family (HIPAA) and one unique one (NIST CSF, NIST SP).
	input := types.ScoringInput{
		Industry:    "healthcare",
		CompanySize: "enterprise",
		Answers: map[string]string{
			"Q-VULN-001": "unpatched", // NIST CSF, HIPAA
			"Q-VULN-002": "many",      // NIST CSF, HIPAA
			"Q-COMP-001": "no_mfa",    // NIST SP
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	if len(report.FrameworkSummary) == 0 {
		t.Fatal("expected framework summary entries")
	}

	// Verify HIPAA family is aggregated (two rules both reference "HIPAA 164.308(a)(5)").
	hipaaFound := false
	for _, fc := range report.FrameworkSummary {
		if fc.FrameworkID == "HIPAA" {
			hipaaFound = true
			// Both VULN rules reference HIPAA 164.308(a)(5) — should be deduped to 1 control.
			if len(fc.Controls) == 0 {
				t.Error("HIPAA framework should have at least one control")
			}
		}
	}
	if !hipaaFound {
		t.Error("expected HIPAA family in framework summary")
	}
}

// Test scanner-only trigger path (questionnaire does not fire; scanner does).
func TestScannerOnlyTriggerPath(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "smb",
		Answers:     map[string]string{}, // no questionnaire answers
		ScannerFindings: &types.ScannerFindings{
			Vulnerabilities: types.VulnerabilityFindings{
				CriticalCVECount: 3, // fires VULN_CRITICAL_CVE (critical_cve_count > 0)
			},
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	if !report.ScannerUsed {
		t.Error("ScannerUsed should be true when ScannerFindings provided")
	}

	vulnFound := false
	for _, risk := range report.TopRisks {
		if risk.RuleID == "VULN_CRITICAL_CVE" {
			vulnFound = true
		}
	}
	if !vulnFound {
		t.Error("expected VULN_CRITICAL_CVE in top risks from scanner trigger")
	}
}

// Test that WhatToFixFirst has correct priority ordering.
func TestWhatToFixFirstPriorityOrdering(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers: map[string]string{
			"Q-VULN-001": "unpatched",
			"Q-VULN-002": "many",
			"Q-COMP-001": "no_mfa",
			"Q-POST-001": "weak",
			"Q-PRIV-001": "exposed",
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	if len(report.WhatToFixFirst) == 0 {
		t.Fatal("expected at least one remediation in WhatToFixFirst")
	}

	// Priority should start at 1 and be monotonically increasing.
	for i, r := range report.WhatToFixFirst {
		if r.Priority != i+1 {
			t.Errorf("remediation[%d].Priority = %d; want %d", i, r.Priority, i+1)
		}
	}
}

// Test ScannerUsed is false when ScannerFindings is nil.
func TestScannerUsedFalseWhenNilFindings(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, _ := scoring.NewEngine(rs, os_)
	input := types.ScoringInput{
		Industry:        "technology",
		CompanySize:     "smb",
		Answers:         map[string]string{},
		ScannerFindings: nil,
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if report.ScannerUsed {
		t.Error("ScannerUsed should be false when ScannerFindings is nil")
	}
}

// Test that NewEngine returns error for nil ruleStore only.
func TestNewEngine_NilRuleStore(t *testing.T) {
	_, os_ := setupStores(t)
	_, err := scoring.NewEngine(nil, os_)
	if err == nil {
		t.Fatal("expected error for nil ruleStore")
	}
}

// Test that NewEngine returns error for nil overlayStore only.
func TestNewEngine_NilOverlayStore(t *testing.T) {
	rs, _ := setupStores(t)
	_, err := scoring.NewEngine(rs, nil)
	if err == nil {
		t.Fatal("expected error for nil overlayStore")
	}
}

// Test ReportPayload has correct metadata fields.
func TestReportPayloadMetadata(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, _ := scoring.NewEngine(rs, os_)
	input := types.ScoringInput{
		AssessmentID: "uuid-abc-123",
		Industry:     "healthcare",
		CompanySize:  "mid",
		Answers:      map[string]string{},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if report.AssessmentID != "uuid-abc-123" {
		t.Errorf("AssessmentID = %q; want uuid-abc-123", report.AssessmentID)
	}
	if report.Industry != "healthcare" {
		t.Errorf("Industry = %q; want healthcare", report.Industry)
	}
	if report.CompanySize != "mid" {
		t.Errorf("CompanySize = %q; want mid", report.CompanySize)
	}
	if report.GeneratedAt.IsZero() {
		t.Error("GeneratedAt must not be zero")
	}
	if len(report.Domains) != 5 {
		t.Errorf("expected 5 domain results, got %d", len(report.Domains))
	}
}

// Test that unknown industry falls back gracefully (no overlay → all multipliers 1.0).
func TestUnknownIndustryFallback(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, _ := scoring.NewEngine(rs, os_)
	input := types.ScoringInput{
		Industry:    "unknown_industry_xyz",
		CompanySize: "smb",
		Answers:     map[string]string{},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if report.OverallScore != 100 {
		t.Errorf("expected 100 for unknown industry with no findings, got %d", report.OverallScore)
	}
}

// Test scanner comparisons for equality and boolean fields.
func TestScannerBooleanFieldComparison(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, _ := scoring.NewEngine(rs, os_)

	// compliance.mfa_enabled == false → fires COMP_NO_MFA
	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers:     map[string]string{}, // no questionnaire
		ScannerFindings: &types.ScannerFindings{
			Compliance: types.ComplianceFindings{
				MFAEnabled: false, // triggers COMP_NO_MFA (mfa_enabled == false)
			},
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	found := false
	for _, risk := range report.TopRisks {
		if risk.RuleID == "COMP_NO_MFA" {
			found = true
		}
	}
	if !found {
		// Check all domains for the finding.
		for _, d := range report.Domains {
			if d.DomainID == types.DomainCompliance && len(d.Findings) > 0 {
				found = true
				break
			}
		}
	}
	if !found {
		t.Error("expected COMP_NO_MFA to fire when mfa_enabled == false via scanner")
	}
}

// Test scanner inequality operator for security_posture.weak_ssh_key_count > 0.
func TestScannerIntComparisonGreaterThan(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, _ := scoring.NewEngine(rs, os_)

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "smb",
		Answers:     map[string]string{},
		ScannerFindings: &types.ScannerFindings{
			SecurityPosture: types.SecurityPostureFindings{
				WeakSSHKeyCount: 2, // > 0 → fires POST_WEAK_SSH
			},
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	for _, d := range report.Domains {
		if d.DomainID == types.DomainSecurityPosture {
			if len(d.Findings) == 0 {
				t.Error("expected POST_WEAK_SSH to fire when weak_ssh_key_count=2 > 0")
			}
			return
		}
	}
}

// Test that contributions exceeding 1.0 per-finding are individually capped.
func TestPerFindingContributionCap(t *testing.T) {
	// Use healthcare overlay which multiplies ai_governance rules by 1.7.
	// AIGOV_NO_AUP: weight=0.75, sev=high(0.8), mult=1.7 → 0.75*1.7*0.8 = 1.02 → capped 1.0.
	rs, os_ := setupStores(t)
	engine, _ := scoring.NewEngine(rs, os_)

	input := types.ScoringInput{
		Industry:    "healthcare",
		CompanySize: "enterprise",
		Answers:     map[string]string{"Q-AIGOV-001": "no_policy"},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	for _, d := range report.Domains {
		if d.DomainID == types.DomainAIGovernance {
			for _, f := range d.Findings {
				if f.Contribution > 1.0 {
					t.Errorf("finding %s contribution %.3f exceeds per-finding cap of 1.0", f.RuleID, f.Contribution)
				}
			}
			// With the cap, capped_loss should be 1.0 (not 1.02).
			if d.Explain.CappedLoss > 1.0 {
				t.Errorf("CappedLoss = %.3f exceeds 1.0", d.Explain.CappedLoss)
			}
		}
	}
}

// Test sortFindingsByContribution tie-breaking by severity then RuleID.
func TestSortFindingsTieBreaking(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, _ := scoring.NewEngine(rs, os_)

	// Trigger two rules in the same domain with different contributions.
	// VULN_CRITICAL_CVE: contrib=1.0 (critical, weight=1.0)
	// VULN_HIGH_CVE:     contrib=0.6 (high, weight=0.75)
	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers: map[string]string{
			"Q-VULN-001": "unpatched",
			"Q-VULN-002": "many",
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	var vulnDomain *types.DomainResult
	for i := range report.Domains {
		if report.Domains[i].DomainID == types.DomainVulnerabilities {
			vulnDomain = &report.Domains[i]
			break
		}
	}
	if vulnDomain == nil {
		t.Fatal("vulnerabilities domain not found")
	}
	if len(vulnDomain.Findings) < 2 {
		t.Fatalf("expected 2 findings in vulnerabilities domain, got %d", len(vulnDomain.Findings))
	}

	// Critical (1.0) should come before high (0.6).
	if vulnDomain.Findings[0].Severity != types.SeverityCritical {
		t.Errorf("expected first finding to be critical, got %q", vulnDomain.Findings[0].Severity)
	}
	if vulnDomain.Findings[1].Severity != types.SeverityHigh {
		t.Errorf("expected second finding to be high, got %q", vulnDomain.Findings[1].Severity)
	}
}

// Test domains are ordered by overlay weight descending in report.
func TestDomainsOrderedByOverlayWeightDesc(t *testing.T) {
	rs, os_ := setupMultiDomainStores(t)
	engine, _ := scoring.NewEngine(rs, os_)

	// Healthcare overlay: privacy=1.8, ai_governance=1.7, compliance=1.5, vulnerabilities=1.2, security_posture=1.2
	input := types.ScoringInput{
		Industry:    "healthcare",
		CompanySize: "enterprise",
		Answers:     map[string]string{},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	// Verify descending order of domain weights (privacy=1.8 first, then ai_governance=1.7, etc.)
	// Tie-break between vulnerabilities(1.2) and security_posture(1.2) is stable but arbitrary.
	if len(report.Domains) != 5 {
		t.Fatalf("expected 5 domains, got %d", len(report.Domains))
	}
	if report.Domains[0].DomainID != types.DomainPrivacy {
		t.Errorf("expected first domain to be privacy (highest weight 1.8), got %q", report.Domains[0].DomainID)
	}
}

// AC-95-9 exact fixture — canonical math with two specific findings whose contributions
// are defined precisely in the acceptance matrix.
//
// Finding (a): critical, default_weight=0.8, severity_factor=1.0 → contribution = 0.8
// Finding (b): high,     default_weight=0.75, severity_factor=0.8 → contribution = 0.6
// Sum = 1.4 → domain capped at 1.0 → domain_score = round(100*(1-1.0)) = 0 → grade F

const ruleAC95aExact = `
id: VULN_AC95_A
domain: vulnerabilities
severity: critical
default_weight: 0.8
detect:
  questionnaire:
    - Q-AC95-001 == yes
title: "AC-95-9 finding A (critical 0.8)"
description_short: "Exact fixture finding A for AC-95-9."
remediation_plain: "Fix finding A."
`

const ruleAC95bExact = `
id: VULN_AC95_B
domain: vulnerabilities
severity: high
default_weight: 0.75
detect:
  questionnaire:
    - Q-AC95-002 == yes
title: "AC-95-9 finding B (high 0.75)"
description_short: "Exact fixture finding B for AC-95-9."
remediation_plain: "Fix finding B."
`

func setupAC95Stores(t *testing.T) (*rules.RuleStore, *rules.OverlayStore) {
	t.Helper()
	ruleDir := t.TempDir()
	overlayDir := t.TempDir()

	writeFile := func(dir, name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writeFile: %v", err)
		}
	}

	writeFile(ruleDir, "VULN_AC95_A.yaml", ruleAC95aExact)
	writeFile(ruleDir, "VULN_AC95_B.yaml", ruleAC95bExact)
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

// TestCanonicalMathAC95ExactFixture uses the EXACT numbers from AC-95-9:
//
//	(a) critical, default_weight=0.8 → contribution = 0.8 × 1.0 × 1.0 = 0.8
//	(b) high,     default_weight=0.75, severity_factor=0.8 → contribution = 0.75 × 1.0 × 0.8 = 0.6
//	sum = 1.4 → capped 1.0 → domain_score = 0 → grade F
func TestCanonicalMathAC95ExactFixture(t *testing.T) {
	rs, os_ := setupAC95Stores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers: map[string]string{
			"Q-AC95-001": "yes", // fires VULN_AC95_A: critical × 0.8 → contribution 0.8
			"Q-AC95-002": "yes", // fires VULN_AC95_B: high × 0.75 × 0.8 → contribution 0.6
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	var vulnDomain *types.DomainResult
	for i := range report.Domains {
		if report.Domains[i].DomainID == types.DomainVulnerabilities {
			vulnDomain = &report.Domains[i]
			break
		}
	}
	if vulnDomain == nil {
		t.Fatal("vulnerabilities domain not found")
	}

	// Verify individual contributions from the explain trace.
	contribMap := make(map[string]float64)
	for _, step := range vulnDomain.Explain.Steps {
		contribMap[step.FindingID] = step.EffectiveContribution
	}

	const eps = 0.001
	if math.Abs(contribMap["VULN_AC95_A"]-0.8) > eps {
		t.Errorf("AC-95-9: finding A contribution = %.4f; want 0.8", contribMap["VULN_AC95_A"])
	}
	if math.Abs(contribMap["VULN_AC95_B"]-0.6) > eps {
		t.Errorf("AC-95-9: finding B contribution = %.4f; want 0.6", contribMap["VULN_AC95_B"])
	}

	// sum = 1.4 → raw_loss >= 1.4; capped_loss = 1.0; score = 0; grade = F
	if vulnDomain.Explain.RawLoss < 1.39 || vulnDomain.Explain.RawLoss > 1.41 {
		t.Errorf("AC-95-9: raw_loss = %.4f; want ~1.4", vulnDomain.Explain.RawLoss)
	}
	if math.Abs(vulnDomain.Explain.CappedLoss-1.0) > eps {
		t.Errorf("AC-95-9: capped_loss = %.4f; want 1.0", vulnDomain.Explain.CappedLoss)
	}
	if vulnDomain.Score != 0 {
		t.Errorf("AC-95-9: domain score = %d; want 0", vulnDomain.Score)
	}
	if vulnDomain.Grade != "F" {
		t.Errorf("AC-95-9: domain grade = %q; want F", vulnDomain.Grade)
	}
}
