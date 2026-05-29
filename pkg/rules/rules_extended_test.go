package rules_test

// rules_extended_test.go — additional tests to cover DomainMultiplier, nonZero,
// IndustryMultiplier, All(), and loader edge cases.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Qwentrix/lumen-scoring/pkg/rules"
	"github.com/Qwentrix/lumen-scoring/pkg/types"
)

// --- IndustryMultiplier ---

func TestIndustryMultiplier_SpecificIndustry(t *testing.T) {
	rule := &rules.FindingRule{
		IndustryOverlays: map[string]rules.IndustryOverrideEntry{
			"healthcare": {WeightMultiplier: 1.7},
			"default":    {WeightMultiplier: 1.0},
		},
	}
	if got := rule.IndustryMultiplier("healthcare"); got != 1.7 {
		t.Errorf("IndustryMultiplier(healthcare) = %.2f; want 1.7", got)
	}
}

func TestIndustryMultiplier_FallsBackToDefault(t *testing.T) {
	rule := &rules.FindingRule{
		IndustryOverlays: map[string]rules.IndustryOverrideEntry{
			"default": {WeightMultiplier: 1.3},
		},
	}
	if got := rule.IndustryMultiplier("financial"); got != 1.3 {
		t.Errorf("IndustryMultiplier(financial) = %.2f; want 1.3 (default)", got)
	}
}

func TestIndustryMultiplier_FallsBackTo1WhenNoDefault(t *testing.T) {
	rule := &rules.FindingRule{
		IndustryOverlays: map[string]rules.IndustryOverrideEntry{
			"healthcare": {WeightMultiplier: 1.7},
		},
	}
	if got := rule.IndustryMultiplier("financial"); got != 1.0 {
		t.Errorf("IndustryMultiplier(financial) = %.2f; want 1.0 (no default overlay)", got)
	}
}

func TestIndustryMultiplier_NilOverlays(t *testing.T) {
	rule := &rules.FindingRule{
		IndustryOverlays: nil,
	}
	if got := rule.IndustryMultiplier("healthcare"); got != 1.0 {
		t.Errorf("IndustryMultiplier with nil overlays = %.2f; want 1.0", got)
	}
}

// --- DomainMultiplier ---

func TestDomainMultiplier_AllDomains(t *testing.T) {
	overlay := &rules.IndustryOverlay{
		DomainWeightMultipliers: rules.DomainWeightMultipliers{
			Vulnerabilities: 1.2,
			Compliance:      1.5,
			AIGovernance:    1.7,
			SecurityPosture: 1.1,
			Privacy:         1.8,
		},
	}
	cases := []struct {
		domain types.DomainID
		want   float64
	}{
		{types.DomainVulnerabilities, 1.2},
		{types.DomainCompliance, 1.5},
		{types.DomainAIGovernance, 1.7},
		{types.DomainSecurityPosture, 1.1},
		{types.DomainPrivacy, 1.8},
	}
	for _, c := range cases {
		if got := overlay.DomainMultiplier(c.domain); got != c.want {
			t.Errorf("DomainMultiplier(%s) = %.2f; want %.2f", c.domain, got, c.want)
		}
	}
}

func TestDomainMultiplier_ZeroValueCoercedToOne(t *testing.T) {
	// If a domain multiplier is omitted (zero value in YAML), it must default to 1.0.
	overlay := &rules.IndustryOverlay{
		DomainWeightMultipliers: rules.DomainWeightMultipliers{
			// All zero — nonZero() should return 1.0 for each.
		},
	}
	for _, d := range types.AllDomains {
		if got := overlay.DomainMultiplier(d); got != 1.0 {
			t.Errorf("DomainMultiplier(%s) with zero value = %.2f; want 1.0", d, got)
		}
	}
}

func TestDomainMultiplier_UnknownDomainReturnsOne(t *testing.T) {
	overlay := &rules.IndustryOverlay{}
	if got := overlay.DomainMultiplier("nonexistent_domain"); got != 1.0 {
		t.Errorf("DomainMultiplier(unknown) = %.2f; want 1.0", got)
	}
}

// --- RuleStore and OverlayStore All() methods ---

func TestRuleStoreAll(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "AIGOV_NO_AUP.yaml", validRuleYAML)

	store, err := rules.LoadRulesFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	all := store.All()
	if len(all) != 1 {
		t.Fatalf("expected 1 rule from All(), got %d", len(all))
	}
	if all[0].ID != "AIGOV_NO_AUP" {
		t.Errorf("All()[0].ID = %q; want AIGOV_NO_AUP", all[0].ID)
	}
}

func TestOverlayStoreAll(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "healthcare.yaml", validOverlayYAML)

	store, err := rules.LoadOverlaysFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	all := store.All()
	if len(all) != 1 {
		t.Fatalf("expected 1 overlay from All(), got %d", len(all))
	}
	if all[0].ID != "healthcare" {
		t.Errorf("All()[0].ID = %q; want healthcare", all[0].ID)
	}
}

// --- Loader edge cases ---

func TestLoadRulesFromDir_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	// Write deliberately broken YAML.
	path := filepath.Join(dir, "broken.yaml")
	if err := os.WriteFile(path, []byte("id: [not: valid: yaml\n"), 0o644); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	_, err := rules.LoadRulesFromDir(dir)
	if err == nil {
		t.Fatal("expected error for malformed YAML rule, got nil")
	}
}

func TestLoadOverlaysFromDir_MalformedYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "broken.yaml")
	if err := os.WriteFile(path, []byte("id: [not: valid\n"), 0o644); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	_, err := rules.LoadOverlaysFromDir(dir)
	if err == nil {
		t.Fatal("expected error for malformed YAML overlay, got nil")
	}
}

func TestLoadOverlaysFromDir_MissingDisplayName(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "bad.yaml", `
id: healthcare
# display_name omitted intentionally
domain_weight_multipliers:
  vulnerabilities: 1.0
`)
	_, err := rules.LoadOverlaysFromDir(dir)
	if err == nil {
		t.Fatal("expected error for overlay missing display_name")
	}
}

func TestLoadOverlaysFromDir_MissingID(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "bad.yaml", `
display_name: "Healthcare"
domain_weight_multipliers:
  vulnerabilities: 1.0
`)
	_, err := rules.LoadOverlaysFromDir(dir)
	if err == nil {
		t.Fatal("expected error for overlay missing id")
	}
}

func TestLoadRulesFromDir_MissingDomain(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "bad.yaml", `
id: SOME_RULE
severity: high
default_weight: 0.5
title: "Missing domain"
`)
	_, err := rules.LoadRulesFromDir(dir)
	if err == nil {
		t.Fatal("expected error for rule missing domain")
	}
}

func TestLoadRulesFromDir_MissingSeverity(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "bad.yaml", `
id: SOME_RULE
domain: vulnerabilities
default_weight: 0.5
title: "Missing severity"
`)
	_, err := rules.LoadRulesFromDir(dir)
	if err == nil {
		t.Fatal("expected error for rule missing severity")
	}
}

func TestLoadRulesFromDir_WeightTooHigh(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "bad.yaml", `
id: BAD_WEIGHT_HIGH
domain: compliance
severity: high
default_weight: 1.5
title: "Weight exceeds 1.0"
`)
	_, err := rules.LoadRulesFromDir(dir)
	if err == nil {
		t.Fatal("expected error for rule with default_weight > 1.0")
	}
}

func TestLoadOverlaysFromDir_DuplicateOverlayID(t *testing.T) {
	dir := t.TempDir()
	writeTempYAML(t, dir, "a.yaml", validOverlayYAML)
	writeTempYAML(t, dir, "b.yaml", validOverlayYAML) // same id "healthcare"
	_, err := rules.LoadOverlaysFromDir(dir)
	if err == nil {
		t.Fatal("expected error for duplicate overlay ID")
	}
}

func TestRuleStoreByID_NotFound(t *testing.T) {
	dir := t.TempDir()
	store, err := rules.LoadRulesFromDir(dir)
	if err != nil {
		t.Fatalf("LoadRulesFromDir: %v", err)
	}
	if store.ByID("NONEXISTENT") != nil {
		t.Error("expected nil for nonexistent rule ID")
	}
}

func TestOverlayStoreByID_NotFound(t *testing.T) {
	dir := t.TempDir()
	store, err := rules.LoadOverlaysFromDir(dir)
	if err != nil {
		t.Fatalf("LoadOverlaysFromDir: %v", err)
	}
	if store.ByID("nonexistent") != nil {
		t.Error("expected nil for nonexistent overlay ID")
	}
}

// Test that non-YAML files in a directory are silently ignored.
func TestLoadRulesFromDir_IgnoresNonYAMLFiles(t *testing.T) {
	dir := t.TempDir()
	// Write a non-YAML file.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# ignored"), 0o644); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	writeTempYAML(t, dir, "AIGOV_NO_AUP.yaml", validRuleYAML)

	store, err := rules.LoadRulesFromDir(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if store.Count() != 1 {
		t.Errorf("expected 1 rule (README.md ignored), got %d", store.Count())
	}
}
