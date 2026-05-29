package scoring_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Qwentrix/lumen-scoring/pkg/rules"
	"github.com/Qwentrix/lumen-scoring/pkg/scoring"
	"github.com/Qwentrix/lumen-scoring/pkg/types"
)

// fixture data for tests.
const ruleNoAUP = `
id: AIGOV_NO_AUP
domain: ai_governance
severity: high
default_weight: 0.75
detect:
  questionnaire:
    - Q-AIGOV-001 == no_policy
  scanner:
    - aigov.shadow_ai_apps_count > 2
title: "No AI acceptable-use policy"
description_short: "No written AI policy for employee LLM use."
frameworks:
  - id: "EU AI Act Art. 26"
    text: "Deployer obligations: documented use-policy"
industry_overlays:
  healthcare:
    weight_multiplier: 1.7
  default:
    weight_multiplier: 1.0
remediation_plain: "Write a one-page acceptable-use policy."
`

const overlayHealthcare = `
id: healthcare
display_name: Healthcare
domain_weight_multipliers:
  vulnerabilities: 1.2
  compliance: 1.5
  ai_governance: 1.7
  security_posture: 1.2
  privacy: 1.8
`

const overlayDefault = `
id: technology
display_name: Technology
domain_weight_multipliers:
  vulnerabilities: 1.0
  compliance: 1.0
  ai_governance: 1.0
  security_posture: 1.0
  privacy: 1.0
`

func setupStores(t *testing.T) (*rules.RuleStore, *rules.OverlayStore) {
	t.Helper()
	ruleDir := t.TempDir()
	overlayDir := t.TempDir()

	writeFile := func(dir, name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatalf("writeFile: %v", err)
		}
	}

	writeFile(ruleDir, "AIGOV_NO_AUP.yaml", ruleNoAUP)
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

func TestNewEngine_NilStores(t *testing.T) {
	_, err := scoring.NewEngine(nil, nil)
	if err == nil {
		t.Fatal("expected error for nil stores")
	}
}

func TestScore_NoFindings(t *testing.T) {
	rs, os_ := setupStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Answer that does not trigger the rule.
	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "smb",
		Answers:     map[string]string{"Q-AIGOV-001": "yes_full"},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if report.OverallScore != 100 {
		t.Errorf("expected overall score 100 with no findings, got %d", report.OverallScore)
	}
	if report.OverallGrade != "A" {
		t.Errorf("expected grade A, got %q", report.OverallGrade)
	}
}

func TestScore_QuestionnaireTrigger(t *testing.T) {
	rs, os_ := setupStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers:     map[string]string{"Q-AIGOV-001": "no_policy"},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if report.OverallScore == 100 {
		t.Error("expected score below 100 when rule is triggered")
	}
	if len(report.TopRisks) == 0 {
		t.Error("expected at least one top risk")
	}
	if report.TopRisks[0].RuleID != "AIGOV_NO_AUP" {
		t.Errorf("expected top risk AIGOV_NO_AUP, got %q", report.TopRisks[0].RuleID)
	}
}

func TestScore_ScannerTrigger(t *testing.T) {
	rs, os_ := setupStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Questionnaire does NOT trigger, but scanner findings do.
	input := types.ScoringInput{
		Industry:    "healthcare",
		CompanySize: "mid",
		Answers:     map[string]string{"Q-AIGOV-001": "yes_full"},
		ScannerFindings: &types.ScannerFindings{
			AIGovernance: types.AIGovernanceFindings{
				ShadowAIAppsCount: 5, // > 2 threshold
			},
		},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if len(report.TopRisks) == 0 {
		t.Error("expected at least one top risk from scanner")
	}
	if report.ScannerUsed != true {
		t.Error("expected ScannerUsed=true")
	}
}

func TestScore_HealthcareIndustryMultiplierIncreasesSeverity(t *testing.T) {
	rs, os_ := setupStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	baseInput := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "enterprise",
		Answers:     map[string]string{"Q-AIGOV-001": "no_policy"},
	}
	heavyInput := types.ScoringInput{
		Industry:    "healthcare",
		CompanySize: "enterprise",
		Answers:     map[string]string{"Q-AIGOV-001": "no_policy"},
	}

	baseReport, _ := engine.Score(baseInput)
	heavyReport, _ := engine.Score(heavyInput)

	// Healthcare has a 1.7x multiplier on ai_governance, so the ai_governance domain
	// score should be the same or lower, and the overall score should be lower for healthcare
	// because ai_governance also gets a domain weight multiplier of 1.7 vs 1.0 for technology.
	if heavyReport.OverallScore > baseReport.OverallScore {
		t.Errorf("healthcare score (%d) should be <= technology score (%d) for same finding",
			heavyReport.OverallScore, baseReport.OverallScore)
	}
}

func TestScore_GradeBoundaries(t *testing.T) {
	cases := []struct {
		score int
		grade string
	}{
		{100, "A"}, {90, "A"}, {89, "B"}, {75, "B"},
		{74, "C"}, {60, "C"}, {59, "D"}, {45, "D"}, {44, "F"}, {0, "F"},
	}
	for _, c := range cases {
		got := types.Grade(c.score)
		if got != c.grade {
			t.Errorf("Grade(%d) = %q; want %q", c.score, got, c.grade)
		}
	}
}

func TestScore_NoAnswers(t *testing.T) {
	rs, os_ := setupStores(t)
	engine, err := scoring.NewEngine(rs, os_)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "smb",
		Answers:     map[string]string{},
	}
	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}
	if report.OverallScore != 100 {
		t.Errorf("expected 100 for no answers, got %d", report.OverallScore)
	}
}

func TestScore_AssessmentIDPassthrough(t *testing.T) {
	rs, os_ := setupStores(t)
	engine, _ := scoring.NewEngine(rs, os_)
	input := types.ScoringInput{
		AssessmentID: "test-uuid-1234",
		Industry:     "technology",
		CompanySize:  "smb",
		Answers:      map[string]string{},
	}
	report, _ := engine.Score(input)
	if report.AssessmentID != "test-uuid-1234" {
		t.Errorf("expected AssessmentID passthrough, got %q", report.AssessmentID)
	}
}
