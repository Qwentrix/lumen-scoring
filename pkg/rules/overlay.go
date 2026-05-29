package rules

import "github.com/Qwentrix/lumen-scoring/pkg/types"

// DomainWeightMultipliers holds the per-domain weight adjustments for an industry.
// These multipliers are applied when computing the overall weighted-mean score.
type DomainWeightMultipliers struct {
	Vulnerabilities   float64 `yaml:"vulnerabilities"`
	Compliance        float64 `yaml:"compliance"`
	AIGovernance      float64 `yaml:"ai_governance"`
	SecurityPosture   float64 `yaml:"security_posture"`
	Privacy           float64 `yaml:"privacy"`
}

// LeadProduct links an industry overlay to the primary Micelium products for that vertical.
type LeadProduct struct {
	Product  string `yaml:"product"`
	Emphasis string `yaml:"emphasis"`
}

// IndustryOverlay is the in-memory representation of a single overlay YAML file.
type IndustryOverlay struct {
	// ID is the industry identifier, e.g. "healthcare".
	ID string `yaml:"id"`
	// DisplayName is the human-readable industry name.
	DisplayName string `yaml:"display_name"`
	// DomainWeightMultipliers adjusts how much each domain contributes to the overall score.
	DomainWeightMultipliers DomainWeightMultipliers `yaml:"domain_weight_multipliers"`
	// PrimaryFrameworks lists the dominant regulatory frameworks for this industry.
	PrimaryFrameworks []string `yaml:"primary_frameworks"`
	// LeadMiceliumProducts lists the most relevant Micelium products for this vertical.
	LeadMiceliumProducts []LeadProduct `yaml:"lead_micelium_products"`
}

// DomainMultiplier returns the weight multiplier for a specific domain.
// Returns 1.0 for any unrecognised domain ID.
func (o *IndustryOverlay) DomainMultiplier(domain types.DomainID) float64 {
	switch domain {
	case types.DomainVulnerabilities:
		return nonZero(o.DomainWeightMultipliers.Vulnerabilities)
	case types.DomainCompliance:
		return nonZero(o.DomainWeightMultipliers.Compliance)
	case types.DomainAIGovernance:
		return nonZero(o.DomainWeightMultipliers.AIGovernance)
	case types.DomainSecurityPosture:
		return nonZero(o.DomainWeightMultipliers.SecurityPosture)
	case types.DomainPrivacy:
		return nonZero(o.DomainWeightMultipliers.Privacy)
	default:
		return 1.0
	}
}

// nonZero returns v if v > 0, otherwise 1.0.
// This guards against YAML files that omit a multiplier (zero value) from
// inadvertently zeroing out a domain's contribution to the overall score.
func nonZero(v float64) float64 {
	if v <= 0 {
		return 1.0
	}
	return v
}
