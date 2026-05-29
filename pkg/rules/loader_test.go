package rules_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Qwentrix/lumen-scoring/pkg/rules"
)

const validRuleYAML = `
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

const validOverlayYAML = `
id: healthcare
display_name: Healthcare
domain_weight_multipliers:
  vulnerabilities: 1.2
  compliance: 1.5
  ai_governance: 1.7
  security_posture: 1.2
  privacy: 1.8
primary_frameworks:
  - HIPAA
  - HITECH
`

func writeTempYAML(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("writeTempYAML: %v", err)
	}
}

func TestLoadRulesFromDir_ValidRule(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "AIGOV_NO_AUP.yaml", validRuleYAML)

	store, err := rules.LoadRulesFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.Count() != 1 {
		t.Fatalf("expected 1 rule, got %d", store.Count())
	}
	rule := store.ByID("AIGOV_NO_AUP")
	if rule == nil {
		t.Fatal("expected rule AIGOV_NO_AUP to be present")
	}
	if rule.Title != "No AI acceptable-use policy" {
		t.Errorf("unexpected title: %q", rule.Title)
	}
}

func TestLoadRulesFromDir_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	store, err := rules.LoadRulesFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.Count() != 0 {
		t.Fatalf("expected 0 rules, got %d", store.Count())
	}
}

func TestLoadRulesFromDir_MissingID(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "bad.yaml", `
domain: ai_governance
severity: high
default_weight: 0.5
title: "No ID"
`)
	_, err := rules.LoadRulesFromDir(dir)
	if err == nil {
		t.Fatal("expected error for rule with missing id, got nil")
	}
}

func TestLoadRulesFromDir_InvalidWeight(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "bad.yaml", `
id: BAD_WEIGHT
domain: compliance
severity: high
default_weight: 0.0
title: "Zero weight"
`)
	_, err := rules.LoadRulesFromDir(dir)
	if err == nil {
		t.Fatal("expected error for rule with zero default_weight, got nil")
	}
}

func TestLoadRulesFromDir_DuplicateID(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "rule_a.yaml", validRuleYAML)
	writeTempYAML(t, dir, "rule_b.yaml", validRuleYAML) // same id
	_, err := rules.LoadRulesFromDir(dir)
	if err == nil {
		t.Fatal("expected error for duplicate rule ID, got nil")
	}
}

func TestLoadOverlaysFromDir_ValidOverlay(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "healthcare.yaml", validOverlayYAML)

	store, err := rules.LoadOverlaysFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.Count() != 1 {
		t.Fatalf("expected 1 overlay, got %d", store.Count())
	}
	overlay := store.ByID("healthcare")
	if overlay == nil {
		t.Fatal("expected overlay 'healthcare' to be present")
	}
}

func TestLoadOverlaysFromDir_NonexistentDir(t *testing.T) {
	_, err := rules.LoadOverlaysFromDir("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Fatal("expected error for nonexistent directory, got nil")
	}
}
