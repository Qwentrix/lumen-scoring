package scoring_test

// engine_ent103_test.go — isolating test for the ENT-103 invariant.
//
// ENT-103 invariant: the overlay-level domain_weight_multipliers differentiate
// industries in computeOverallScore ONLY when domain scores are UNEQUAL. This
// test constructs asymmetric domain scores (high privacy loss, low elsewhere)
// and asserts that healthcare (privacy multiplier = 1.8) and technology
// (privacy multiplier = 1.1) produce DIFFERENT overall scores — proving the
// domain_weight_multiplier path is active and effective.
//
// If this test fails it means either:
//   (a) the overlay is not being applied in computeOverallScore, or
//   (b) the domain score differences are cancelling out the multiplier effect
//       (which would indicate a scoring engine regression).

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Qwentrix/lumen-scoring/pkg/rules"
	"github.com/Qwentrix/lumen-scoring/pkg/scoring"
	"github.com/Qwentrix/lumen-scoring/pkg/types"
)

// overlayHealthcareENT103 is a minimal healthcare overlay with a high privacy
// multiplier (1.8) and a low vulnerability multiplier (1.0). Keeps the other
// domains close to 1.0 to isolate the privacy dimension.
const overlayHealthcareENT103 = `
id: healthcare
display_name: Healthcare
domain_weight_multipliers:
  vulnerabilities: 1.0
  compliance: 1.0
  ai_governance: 1.0
  security_posture: 1.0
  privacy: 1.8
`

// overlayTechnologyENT103 is a minimal technology overlay with a low privacy
// multiplier (1.1) — much lower than healthcare's 1.8. All other domains are
// also 1.0, isolating the privacy dimension contrast.
const overlayTechnologyENT103 = `
id: technology
display_name: Technology
domain_weight_multipliers:
  vulnerabilities: 1.0
  compliance: 1.0
  ai_governance: 1.0
  security_posture: 1.0
  privacy: 1.1
`

// rulePrivacyHighENT103 is a privacy-domain rule with a high default weight so
// that a single questionnaire answer produces a large privacy domain loss while
// leaving the other four domains untouched (asymmetric domain scores).
const rulePrivacyHighENT103 = `
id: PRIV_ENT103_HIGH
domain: privacy
severity: critical
default_weight: 0.9
detect:
  questionnaire:
    - Q-ENT103-PRIV == exposed
title: "ENT-103 privacy loss probe"
description_short: "High privacy loss used to isolate domain_weight_multiplier path."
remediation_plain: "Encrypt or restrict exposed PII."
`

// setupENT103Stores creates the rule and overlay stores for the ENT-103 invariant test.
func setupENT103Stores(t *testing.T) (*rules.RuleStore, *rules.OverlayStore) {
	t.Helper()
	ruleDir := t.TempDir()
	overlayDir := t.TempDir()

	writeFile := func(dir, name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writeFile: %v", err)
		}
	}

	writeFile(ruleDir, "PRIV_ENT103_HIGH.yaml", rulePrivacyHighENT103)
	writeFile(overlayDir, "healthcare.yaml", overlayHealthcareENT103)
	writeFile(overlayDir, "technology.yaml", overlayTechnologyENT103)

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

// TestENT103_DomainWeightMultiplierDifferentiatesIndustries isolates the
// domain_weight_multiplier path in computeOverallScore.
//
// Setup: one privacy rule (PRIV_ENT103_HIGH, critical weight=0.9) triggered
// by a questionnaire answer. This produces:
//   - privacy domain: score < 100 (loss from the finding)
//   - all other four domains: score = 100 (no findings)
//
// Because domain scores are asymmetric (privacy != others), the
// domain_weight_multiplier difference (healthcare=1.8 vs technology=1.1)
// gives the privacy domain more weight in healthcare's weighted mean,
// pulling healthcare's overall score below technology's.
//
// Asserts: healthcare.OverallScore < technology.OverallScore, proving the
// domain_weight_multiplier path is active and carrying industry differentiation.
func TestENT103_DomainWeightMultiplierDifferentiatesIndustries(t *testing.T) {
	rs, os_ := setupENT103Stores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Trigger the high-weight privacy rule in both industries.
	healthcareInput := types.ScoringInput{
		Industry:    "healthcare",
		CompanySize: "enterprise",
		Answers:     map[string]string{"Q-ENT103-PRIV": "exposed"},
	}
	technologyInput := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers:     map[string]string{"Q-ENT103-PRIV": "exposed"},
	}

	healthcareReport, err := engine.Score(healthcareInput)
	if err != nil {
		t.Fatalf("Score(healthcare): %v", err)
	}
	technologyReport, err := engine.Score(technologyInput)
	if err != nil {
		t.Fatalf("Score(technology): %v", err)
	}

	// Sanity: both reports should have a privacy finding.
	var healthPrivScore, techPrivScore int
	for _, d := range healthcareReport.Domains {
		if d.DomainID == types.DomainPrivacy {
			healthPrivScore = d.Score
		}
	}
	for _, d := range technologyReport.Domains {
		if d.DomainID == types.DomainPrivacy {
			techPrivScore = d.Score
		}
	}
	if healthPrivScore == 100 {
		t.Fatal("ENT-103: expected healthcare privacy domain to have a finding (score < 100); check rule fixture")
	}
	if techPrivScore == 100 {
		t.Fatal("ENT-103: expected technology privacy domain to have a finding (score < 100); check rule fixture")
	}
	// Both industries use the same rule with no per-rule industry_overlay, so the
	// per-domain scores should be identical.
	if healthPrivScore != techPrivScore {
		t.Errorf("ENT-103: per-domain privacy scores differ (healthcare=%d, technology=%d); expected equal (no per-rule overlay in this fixture)",
			healthPrivScore, techPrivScore)
	}

	// Core assertion: because the privacy domain score is the same in both
	// industries but the privacy domain_weight_multiplier differs (1.8 vs 1.1),
	// the weighted mean (computeOverallScore) must produce a lower overall score
	// for healthcare.
	//
	// Mathematically: with four domains at 100 and one privacy domain at score P,
	// overall = (4×100×1.0 + P×privacy_mult) / (4×1.0 + privacy_mult).
	// healthcare overall = (400 + P×1.8) / (4+1.8)   < technology overall = (400 + P×1.1) / (4+1.1)
	// because privacy_mult=1.8 > 1.1 and P < 100, giving privacy more weight in
	// healthcare's denominator relative to the perfect-scoring domains.
	if healthcareReport.OverallScore >= technologyReport.OverallScore {
		t.Errorf("ENT-103 domain_weight_multiplier path FAILED: "+
			"healthcare overall score (%d) should be < technology overall score (%d) "+
			"when privacy domain score (%d) < 100 and healthcare privacy multiplier (1.8) > technology (1.1)",
			healthcareReport.OverallScore, technologyReport.OverallScore, healthPrivScore)
	}
}
