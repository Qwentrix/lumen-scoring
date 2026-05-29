// Package rules provides YAML rule and overlay loading for the lumen-scoring engine.
//
// Rules live in qwen-web/lumen/content/rules/ (the canonical content repository).
// This package parses them into in-memory structs for use by the scoring engine.
// It does not bundle any content — callers supply the path to an extracted content bundle.
package rules

import "github.com/Qwentrix/lumen-scoring/pkg/types"

// DetectCondition is a single boolean expression that determines whether a rule fires.
// The expression language is intentionally simple: "<key> <op> <value>".
//
// For questionnaire expressions: key = question ID, op = "==", value = answer value.
//   Example: "Q-AIGOV-001 == no_policy"
//
// For scanner expressions: key = "<domain>.<probe_field>", op = ">" / "<" / "==" / "!=",
// value = numeric or boolean literal.
//   Example: "aigov.shadow_ai_apps_count > 2"
type DetectCondition string

// RuleDetect groups the questionnaire and scanner detect conditions for a rule.
// Both slices are evaluated independently; if either list has a matching condition
// the rule fires (OR across lists; conditions within a list are ANDed).
type RuleDetect struct {
	// Questionnaire holds conditions evaluated against questionnaire answer values.
	Questionnaire []DetectCondition `yaml:"questionnaire"`
	// Scanner holds conditions evaluated against ScannerFindings field values.
	// Empty slice means the rule does not trigger from scanner data alone.
	Scanner []DetectCondition `yaml:"scanner"`
}

// IndustryOverrideEntry is the per-industry weight adjustment for a specific rule.
type IndustryOverrideEntry struct {
	// WeightMultiplier is applied to the rule's DefaultWeight for this industry.
	// 1.0 = no change; >1.0 = more severe in this industry.
	WeightMultiplier float64 `yaml:"weight_multiplier"`
}

// MiceliumProductRef links a finding to a Micelium product that addresses it.
type MiceliumProductRef struct {
	// Product is the Micelium product name, e.g. "Sigil" or "Sense".
	Product string `yaml:"product"`
	// Role describes how this product addresses the finding.
	Role string `yaml:"role"`
}

// FindingRule is the in-memory representation of a single rule YAML file.
type FindingRule struct {
	// ID is the unique rule identifier, e.g. "AIGOV_NO_AUP".
	ID string `yaml:"id"`
	// Domain is the scoring domain this rule contributes to.
	Domain types.DomainID `yaml:"domain"`
	// Severity is the rule's base severity level.
	Severity types.Severity `yaml:"severity"`
	// DefaultWeight is the base contribution weight (0.0–1.0) before overlay multiplication.
	DefaultWeight float64 `yaml:"default_weight"`
	// Detect holds the conditions that trigger this rule.
	Detect RuleDetect `yaml:"detect"`
	// Title is the short human-readable rule title.
	Title string `yaml:"title"`
	// DescriptionShort is a one-sentence summary of the finding.
	DescriptionShort string `yaml:"description_short"`
	// DescriptionLong is the full technical description of the risk.
	DescriptionLong string `yaml:"description_long"`
	// Frameworks lists the compliance and regulatory framework references.
	Frameworks []types.FrameworkRef `yaml:"frameworks"`
	// MiceliumProducts lists the Micelium products that address this finding.
	MiceliumProducts []MiceliumProductRef `yaml:"micelium_product"`
	// IndustryOverlays provides per-industry weight multipliers for this rule.
	// The special key "default" is used when no industry-specific entry exists.
	IndustryOverlays map[string]IndustryOverrideEntry `yaml:"industry_overlays"`
	// RemediationPlain is a plain-language remediation suggestion.
	RemediationPlain string `yaml:"remediation_plain"`
	// RemediationTechnical is the technical remediation guidance.
	RemediationTechnical string `yaml:"remediation_technical"`
}

// IndustryMultiplier returns the effective weight multiplier for this rule
// given an industry ID. Falls back to the "default" overlay entry, then to 1.0.
func (r *FindingRule) IndustryMultiplier(industry string) float64 {
	if entry, ok := r.IndustryOverlays[industry]; ok {
		return entry.WeightMultiplier
	}
	if entry, ok := r.IndustryOverlays["default"]; ok {
		return entry.WeightMultiplier
	}
	return 1.0
}
