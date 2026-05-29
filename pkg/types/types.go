// Package types defines the public data types for the lumen-scoring engine.
//
// These types are shared between lumen-api (the server-side scoring service) and the
// lumen scanner CLI, ensuring identical in-memory representations on both sides.
package types

import "time"

// DomainID is one of the five security assessment domains.
type DomainID string

const (
	DomainVulnerabilities DomainID = "vulnerabilities"
	DomainCompliance      DomainID = "compliance"
	DomainAIGovernance    DomainID = "ai_governance"
	DomainSecurityPosture DomainID = "security_posture"
	DomainPrivacy         DomainID = "privacy"
)

// AllDomains is the canonical ordered list of scoring domains.
var AllDomains = []DomainID{
	DomainVulnerabilities,
	DomainCompliance,
	DomainAIGovernance,
	DomainSecurityPosture,
	DomainPrivacy,
}

// Severity represents the finding severity level as declared in a rule's YAML.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// SeverityFactor maps a Severity to its numeric contribution multiplier.
// These values are the single source of truth; the grade thresholds in Grade()
// are the other half of the scoring contract.
func SeverityFactor(s Severity) float64 {
	switch s {
	case SeverityCritical:
		return 1.0
	case SeverityHigh:
		return 0.8
	case SeverityMedium:
		return 0.5
	case SeverityLow:
		return 0.25
	default:
		return 0.0
	}
}

// Grade converts a 0–100 score to a letter grade.
// These buckets are the single source of truth for both the backend engine and the
// qwen-web front-end (lib/lumen/score-formatter.ts must mirror them exactly).
func Grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 45:
		return "D"
	default:
		return "F"
	}
}

// FrameworkRef is a reference to a compliance or regulatory framework triggered by a finding.
type FrameworkRef struct {
	// ID is the canonical citation identifier, e.g. "EU AI Act Art. 26" or "NIST AI RMF GOVERN-1.1".
	ID string `json:"id" yaml:"id"`
	// Text is a short description of the specific control or obligation.
	Text string `json:"text" yaml:"text"`
}

// ScoringInput is the full set of data required to run the scoring engine.
type ScoringInput struct {
	// AssessmentID is an optional pre-generated UUID supplied by the caller
	// (lumen-api uses the Redis session UUID; the scanner CLI generates one locally).
	// When empty, ReportPayload.AssessmentID will also be empty.
	// This field is intentionally omitted from JSON to avoid leaking internal IDs
	// in scanner hybrid uploads.
	AssessmentID string `json:"-"`
	// Industry is the selected industry ID, e.g. "healthcare" or "financial".
	Industry string `json:"industry"`
	// CompanySize is one of "individual", "smb", "mid", "enterprise".
	CompanySize string `json:"company_size"`
	// Answers maps QuestionID to the selected AnswerValue from the questionnaire.
	// Example: {"Q-AIGOV-001": "no_policy", "Q-COMP-003": "yes_full"}
	Answers map[string]string `json:"answers"`
	// ScannerFindings holds structured outputs from the local scanner probes.
	// If nil, only the questionnaire path is evaluated.
	ScannerFindings *ScannerFindings `json:"scanner_findings,omitempty"`
}

// ScannerFindings contains structured probe outputs from the lumen scanner CLI.
// Each field mirrors a probe domain and holds the raw observation values used by
// rule detect.scanner expressions.
type ScannerFindings struct {
	// Vulnerabilities holds software inventory and CVE-match outputs.
	Vulnerabilities VulnerabilityFindings `json:"vulnerabilities"`
	// Compliance holds OS-level compliance probe outputs.
	Compliance ComplianceFindings `json:"compliance"`
	// AIGovernance holds shadow-AI and LLM-egress probe outputs.
	AIGovernance AIGovernanceFindings `json:"ai_governance"`
	// SecurityPosture holds SSH, password manager, and port probe outputs.
	SecurityPosture SecurityPostureFindings `json:"security_posture"`
	// Privacy holds DLP / PII scan outputs.
	Privacy PrivacyFindings `json:"privacy"`
}

// VulnerabilityFindings captures the vulnerability probe results.
type VulnerabilityFindings struct {
	// TotalPackages is the count of installed packages or applications enumerated.
	TotalPackages int `json:"total_packages"`
	// CriticalCVECount is the number of matched critical-severity CVEs.
	CriticalCVECount int `json:"critical_cve_count"`
	// HighCVECount is the number of matched high-severity CVEs.
	HighCVECount int `json:"high_cve_count"`
	// DaysSinceLastUpdate is the number of days since the last OS/package update was applied.
	DaysSinceLastUpdate int `json:"days_since_last_update"`
}

// ComplianceFindings captures the compliance probe results.
type ComplianceFindings struct {
	// MFAEnabled indicates whether multi-factor authentication is enforced org-wide.
	MFAEnabled bool `json:"mfa_enabled"`
	// DiskEncryptionEnabled indicates whether full-disk encryption is active.
	DiskEncryptionEnabled bool `json:"disk_encryption_enabled"`
	// FirewallEnabled indicates whether the host firewall is active and configured.
	FirewallEnabled bool `json:"firewall_enabled"`
	// ScreenLockEnabled indicates whether automatic screen lock is configured.
	ScreenLockEnabled bool `json:"screen_lock_enabled"`
	// ScreenLockTimeoutSeconds is the idle timeout in seconds before the screen locks.
	ScreenLockTimeoutSeconds int `json:"screen_lock_timeout_seconds"`
}

// AIGovernanceFindings captures the AI governance probe results.
type AIGovernanceFindings struct {
	// ShadowAIAppsCount is the number of detected local LLM or AI-assistant applications.
	ShadowAIAppsCount int `json:"shadow_ai_apps_count"`
	// BrowserExtensionsAICount is the number of detected AI-assistant browser extensions.
	BrowserExtensionsAICount int `json:"browser_extensions_ai_count"`
	// LLMEgressProcessesCount is the number of processes with active connections to LLM API endpoints.
	LLMEgressProcessesCount int `json:"llm_egress_processes_count"`
	// MCPServersRunning is the count of detected Model Context Protocol server processes.
	MCPServersRunning int `json:"mcp_servers_running"`
}

// SecurityPostureFindings captures the security posture probe results.
type SecurityPostureFindings struct {
	// SSHKeysCount is the number of SSH private keys found in ~/.ssh.
	SSHKeysCount int `json:"ssh_keys_count"`
	// WeakSSHKeyCount is the number of SSH keys below recommended bit-length thresholds.
	WeakSSHKeyCount int `json:"weak_ssh_key_count"`
	// PasswordManagerDetected indicates whether a password manager agent was found.
	PasswordManagerDetected bool `json:"password_manager_detected"`
	// ListeningPortsCount is the number of TCP/UDP ports listening on non-loopback interfaces.
	ListeningPortsCount int `json:"listening_ports_count"`
}

// PrivacyFindings captures the privacy / DLP probe results.
type PrivacyFindings struct {
	// PIIMatchCount is the number of PII pattern matches found in ~/Documents.
	PIIMatchCount int `json:"pii_match_count"`
	// FilesScannedCount is the total number of files the DLP scanner inspected.
	FilesScannedCount int `json:"files_scanned_count"`
}

// FindingResult describes a single triggered rule and its contribution to the score.
type FindingResult struct {
	// RuleID is the finding rule identifier, e.g. "AIGOV_NO_AUP".
	RuleID string `json:"rule_id"`
	// Domain is the scoring domain this finding belongs to.
	Domain DomainID `json:"domain"`
	// Title is the short human-readable rule title.
	Title string `json:"title"`
	// Severity is the finding severity as declared in the rule YAML.
	Severity Severity `json:"severity"`
	// DefaultWeight is the rule's base weight (0.0–1.0) before overlay multiplication.
	DefaultWeight float64 `json:"default_weight"`
	// IndustryMultiplier is the overlay-adjusted multiplier applied to DefaultWeight.
	IndustryMultiplier float64 `json:"industry_multiplier"`
	// SeverityFactor is the numeric multiplier derived from Severity.
	SeverityFactor float64 `json:"severity_factor"`
	// Contribution is DefaultWeight × IndustryMultiplier × SeverityFactor (0.0–1.0).
	Contribution float64 `json:"contribution"`
	// TriggeredBy lists the question IDs or scanner probe keys that fired this rule.
	TriggeredBy []string `json:"triggered_by"`
	// Frameworks lists the compliance and regulatory framework references.
	Frameworks []FrameworkRef `json:"frameworks"`
	// RemediationPlain is a plain-language remediation suggestion.
	RemediationPlain string `json:"remediation_plain"`
}

// ExplainStep is one term in the explainability trace for a domain's "Why?" panel.
type ExplainStep struct {
	// FindingID is the rule ID of this contribution.
	FindingID string `json:"finding_id"`
	// Title is the short rule title.
	Title string `json:"title"`
	// Severity of the finding.
	Severity Severity `json:"severity"`
	// DefaultWeight before overlay.
	DefaultWeight float64 `json:"default_weight"`
	// IndustryMultiplier applied.
	IndustryMultiplier float64 `json:"industry_multiplier"`
	// SeverityFactor applied.
	SeverityFactor float64 `json:"severity_factor"`
	// EffectiveContribution is the final numeric contribution of this finding.
	EffectiveContribution float64 `json:"effective_contribution"`
	// TriggeredBy lists the triggering question or probe keys.
	TriggeredBy []string `json:"triggered_by"`
	// Frameworks attached to this finding.
	Frameworks []FrameworkRef `json:"frameworks"`
}

// DomainExplain is the full explainability trace for one domain.
type DomainExplain struct {
	// DomainID identifies the domain.
	DomainID DomainID `json:"domain_id"`
	// Formula is a human-readable description of the scoring formula.
	Formula string `json:"formula"`
	// Steps is the per-finding contribution list, sorted by EffectiveContribution desc.
	Steps []ExplainStep `json:"steps"`
	// RawLoss is the sum of all contributions before capping.
	RawLoss float64 `json:"raw_loss"`
	// CappedLoss is min(1.0, RawLoss).
	CappedLoss float64 `json:"capped_loss"`
	// DomainScore is round(100 * (1 - CappedLoss)).
	DomainScore int `json:"domain_score"`
}

// DomainResult is the per-domain scoring output.
type DomainResult struct {
	// DomainID identifies the domain.
	DomainID DomainID `json:"domain_id"`
	// Score is the 0–100 domain score.
	Score int `json:"score"`
	// Grade is the letter grade for this domain.
	Grade string `json:"grade"`
	// PlainSummary is a one-sentence narrative of the domain result.
	PlainSummary string `json:"plain_summary"`
	// Findings is the list of triggered rules, severity-sorted.
	Findings []FindingResult `json:"findings"`
	// Explain is the full explainability trace for the "Why?" panel.
	Explain DomainExplain `json:"explain"`
}

// Remediation is a prioritised fix recommendation included in the "What to fix first" section.
type Remediation struct {
	// RuleID of the source finding.
	RuleID string `json:"rule_id"`
	// Title of the finding.
	Title string `json:"title"`
	// Domain this remediation belongs to.
	Domain DomainID `json:"domain"`
	// Priority is a 1-based rank (1 = highest priority).
	Priority int `json:"priority"`
	// RemediationPlain is the actionable plain-language fix.
	RemediationPlain string `json:"remediation_plain"`
	// Contribution of the underlying finding.
	Contribution float64 `json:"contribution"`
}

// FrameworkCoverage aggregates the framework references triggered across all findings.
type FrameworkCoverage struct {
	// FrameworkID is the framework family label, e.g. "HIPAA" or "EU AI Act".
	FrameworkID string `json:"framework_id"`
	// Controls is the list of specific controls triggered within this framework.
	Controls []FrameworkRef `json:"controls"`
}

// ReportPayload is the complete scoring output returned by Engine.Score.
// It is also the input to the lumen-api PDF template and to the web app's Tier 1 result page.
type ReportPayload struct {
	// AssessmentID is a UUID assigned by the caller (lumen-api or scanner CLI).
	AssessmentID string `json:"assessment_id"`
	// GeneratedAt is the UTC timestamp of when scoring was performed.
	GeneratedAt time.Time `json:"generated_at"`
	// Industry is the industry ID used for overlay selection.
	Industry string `json:"industry"`
	// CompanySize is the company-size bucket used for question applicability.
	CompanySize string `json:"company_size"`
	// OverallScore is the weighted mean of all domain scores (0–100).
	OverallScore int `json:"overall_score"`
	// OverallGrade is the letter grade for the overall score.
	OverallGrade string `json:"overall_grade"`
	// Domains contains the per-domain results, ordered by overlay weight descending.
	Domains []DomainResult `json:"domains"`
	// TopRisks is the top-3 findings sorted by contribution desc, then severity desc.
	TopRisks []FindingResult `json:"top_risks"`
	// WhatToFixFirst is the top-5 prioritised remediation steps.
	WhatToFixFirst []Remediation `json:"what_to_fix_first"`
	// FrameworkSummary lists all triggered framework references grouped by family.
	FrameworkSummary []FrameworkCoverage `json:"framework_summary"`
	// ScannerUsed indicates whether scanner probe findings contributed to the score.
	ScannerUsed bool `json:"scanner_used"`
}
