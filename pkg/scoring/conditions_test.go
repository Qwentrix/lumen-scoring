package scoring

// conditions_test.go — white-box tests for the unexported condition-evaluation functions.
// Lives in package scoring (not scoring_test) to access unexported symbols.

import (
	"testing"

	"github.com/Qwentrix/lumen-scoring/pkg/rules"
	"github.com/Qwentrix/lumen-scoring/pkg/types"
)

// --- parseCondition ---

func TestParseCondition_EqualOp(t *testing.T) {
	key, op, val, err := parseCondition("Q-AIGOV-001 == no_policy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "Q-AIGOV-001" || op != "==" || val != "no_policy" {
		t.Errorf("parseCondition returned (%q, %q, %q)", key, op, val)
	}
}

func TestParseCondition_GTOp(t *testing.T) {
	key, op, val, err := parseCondition("vulnerabilities.critical_cve_count > 0")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != "vulnerabilities.critical_cve_count" || op != ">" || val != "0" {
		t.Errorf("parseCondition returned (%q, %q, %q)", key, op, val)
	}
}

func TestParseCondition_GEOp(t *testing.T) {
	_, op, _, err := parseCondition("x >= 5")
	if err != nil || op != ">=" {
		t.Errorf("expected >= op, got %q err %v", op, err)
	}
}

func TestParseCondition_LEOp(t *testing.T) {
	_, op, _, err := parseCondition("x <= 5")
	if err != nil || op != "<=" {
		t.Errorf("expected <= op, got %q err %v", op, err)
	}
}

func TestParseCondition_LTOp(t *testing.T) {
	_, op, _, err := parseCondition("x < 5")
	if err != nil || op != "<" {
		t.Errorf("expected < op, got %q err %v", op, err)
	}
}

func TestParseCondition_NEOp(t *testing.T) {
	_, op, _, err := parseCondition("x != y")
	if err != nil || op != "!=" {
		t.Errorf("expected != op, got %q err %v", op, err)
	}
}

func TestParseCondition_NoOperator(t *testing.T) {
	_, _, _, err := parseCondition("no operator here")
	if err == nil {
		t.Fatal("expected error for condition with no operator")
	}
}

func TestParseCondition_EmptyKey(t *testing.T) {
	_, _, _, err := parseCondition("== value")
	if err == nil {
		t.Fatal("expected error for empty key")
	}
}

func TestParseCondition_EmptyValue(t *testing.T) {
	_, _, _, err := parseCondition("key ==")
	if err == nil {
		t.Fatal("expected error for empty value")
	}
}

// --- compareInt ---

func TestCompareInt_AllOps(t *testing.T) {
	cases := []struct {
		v       int64
		op      string
		literal string
		want    bool
	}{
		{5, "==", "5", true},
		{5, "==", "4", false},
		{5, "!=", "4", true},
		{5, "!=", "5", false},
		{5, ">", "4", true},
		{5, ">", "5", false},
		{5, "<", "6", true},
		{5, "<", "5", false},
		{5, ">=", "5", true},
		{5, ">=", "6", false},
		{5, "<=", "5", true},
		{5, "<=", "4", false},
		{5, "==", "not_a_number", false}, // invalid literal
		{5, "??", "5", false},            // unknown operator
	}
	for _, c := range cases {
		got := compareInt(c.v, c.op, c.literal)
		if got != c.want {
			t.Errorf("compareInt(%d, %q, %q) = %v; want %v", c.v, c.op, c.literal, got, c.want)
		}
	}
}

// --- compareBool ---

func TestCompareBool_EqualOp(t *testing.T) {
	if !compareBool(true, "==", "true") {
		t.Error("compareBool(true == true) should be true")
	}
	if compareBool(true, "==", "false") {
		t.Error("compareBool(true == false) should be false")
	}
}

func TestCompareBool_NotEqualOp(t *testing.T) {
	if !compareBool(false, "!=", "true") {
		t.Error("compareBool(false != true) should be true")
	}
	if compareBool(true, "!=", "true") {
		t.Error("compareBool(true != true) should be false")
	}
}

func TestCompareBool_InvalidLiteral(t *testing.T) {
	if compareBool(true, "==", "not_bool") {
		t.Error("compareBool with invalid literal should return false")
	}
}

func TestCompareBool_UnsupportedOp(t *testing.T) {
	if compareBool(true, ">", "false") {
		t.Error("compareBool with unsupported op > should return false")
	}
}

// --- compareValues ---

func TestCompareValues_IntType(t *testing.T) {
	if !compareValues(int(5), "==", "5") {
		t.Error("compareValues(int(5), ==, 5) should be true")
	}
}

func TestCompareValues_Int64Type(t *testing.T) {
	if !compareValues(int64(10), ">", "9") {
		t.Error("compareValues(int64(10), >, 9) should be true")
	}
}

func TestCompareValues_BoolType(t *testing.T) {
	if !compareValues(false, "==", "false") {
		t.Error("compareValues(false, ==, false) should be true")
	}
}

func TestCompareValues_StringFallbackEqual(t *testing.T) {
	if !compareValues("hello", "==", "hello") {
		t.Error("compareValues string fallback == should work")
	}
}

func TestCompareValues_StringFallbackNotEqual(t *testing.T) {
	if !compareValues("hello", "!=", "world") {
		t.Error("compareValues string fallback != should work")
	}
}

func TestCompareValues_StringFallbackInvalidOp(t *testing.T) {
	if compareValues("hello", ">", "world") {
		t.Error("compareValues string fallback with unsupported op should return false")
	}
}

// --- scannerFieldValue ---

func TestScannerFieldValue_ValidDomain(t *testing.T) {
	sf := &types.ScannerFindings{
		Vulnerabilities: types.VulnerabilityFindings{CriticalCVECount: 7},
	}
	val, ok := scannerFieldValue("vulnerabilities.critical_cve_count", sf)
	if !ok {
		t.Fatal("expected ok=true for vulnerabilities.critical_cve_count")
	}
	if val.(int) != 7 {
		t.Errorf("expected 7, got %v", val)
	}
}

func TestScannerFieldValue_AigovAlias(t *testing.T) {
	sf := &types.ScannerFindings{
		AIGovernance: types.AIGovernanceFindings{ShadowAIAppsCount: 3},
	}
	val, ok := scannerFieldValue("ai_governance.shadow_ai_apps_count", sf)
	if !ok {
		t.Fatal("expected ok=true for ai_governance.shadow_ai_apps_count")
	}
	if val.(int) != 3 {
		t.Errorf("expected 3, got %v", val)
	}
}

func TestScannerFieldValue_AigovShortAlias(t *testing.T) {
	sf := &types.ScannerFindings{
		AIGovernance: types.AIGovernanceFindings{ShadowAIAppsCount: 5},
	}
	val, ok := scannerFieldValue("aigov.shadow_ai_apps_count", sf)
	if !ok {
		t.Fatal("expected ok=true for aigov alias")
	}
	if val.(int) != 5 {
		t.Errorf("expected 5, got %v", val)
	}
}

func TestScannerFieldValue_PostureAlias(t *testing.T) {
	sf := &types.ScannerFindings{
		SecurityPosture: types.SecurityPostureFindings{WeakSSHKeyCount: 2},
	}
	val, ok := scannerFieldValue("posture.weak_ssh_key_count", sf)
	if !ok {
		t.Fatal("expected ok=true for posture alias")
	}
	if val.(int) != 2 {
		t.Errorf("expected 2, got %v", val)
	}
}

func TestScannerFieldValue_PrivacyDomain(t *testing.T) {
	sf := &types.ScannerFindings{
		Privacy: types.PrivacyFindings{PIIMatchCount: 15},
	}
	val, ok := scannerFieldValue("privacy.pii_match_count", sf)
	if !ok {
		t.Fatal("expected ok=true for privacy.pii_match_count")
	}
	if val.(int) != 15 {
		t.Errorf("expected 15, got %v", val)
	}
}

func TestScannerFieldValue_UnknownDomain(t *testing.T) {
	sf := &types.ScannerFindings{}
	_, ok := scannerFieldValue("unknown_domain.field", sf)
	if ok {
		t.Error("expected ok=false for unknown domain")
	}
}

func TestScannerFieldValue_UnknownField(t *testing.T) {
	sf := &types.ScannerFindings{}
	_, ok := scannerFieldValue("vulnerabilities.nonexistent_field", sf)
	if ok {
		t.Error("expected ok=false for nonexistent field")
	}
}

func TestScannerFieldValue_MissingDotSeparator(t *testing.T) {
	sf := &types.ScannerFindings{}
	_, ok := scannerFieldValue("nodot", sf)
	if ok {
		t.Error("expected ok=false for key without dot separator")
	}
}

func TestScannerFieldValue_BoolField(t *testing.T) {
	sf := &types.ScannerFindings{
		Compliance: types.ComplianceFindings{MFAEnabled: true},
	}
	val, ok := scannerFieldValue("compliance.mfa_enabled", sf)
	if !ok {
		t.Fatal("expected ok=true for compliance.mfa_enabled")
	}
	if val.(bool) != true {
		t.Errorf("expected true, got %v", val)
	}
}

// --- evalScannerCondition ---

func TestEvalScannerCondition_ValidMatch(t *testing.T) {
	sf := &types.ScannerFindings{
		Vulnerabilities: types.VulnerabilityFindings{HighCVECount: 10},
	}
	cond := rules.DetectCondition("vulnerabilities.high_cve_count > 5")
	if !evalScannerCondition(cond, sf) {
		t.Error("expected condition to match: high_cve_count=10 > 5")
	}
}

func TestEvalScannerCondition_NoMatch(t *testing.T) {
	sf := &types.ScannerFindings{
		Vulnerabilities: types.VulnerabilityFindings{HighCVECount: 2},
	}
	cond := rules.DetectCondition("vulnerabilities.high_cve_count > 5")
	if evalScannerCondition(cond, sf) {
		t.Error("expected condition NOT to match: high_cve_count=2 > 5")
	}
}

func TestEvalScannerCondition_ParseError(t *testing.T) {
	sf := &types.ScannerFindings{}
	cond := rules.DetectCondition("no_operator_here")
	if evalScannerCondition(cond, sf) {
		t.Error("malformed condition should return false")
	}
}

func TestEvalScannerCondition_UnknownKey(t *testing.T) {
	sf := &types.ScannerFindings{}
	cond := rules.DetectCondition("unknown.field == 1")
	if evalScannerCondition(cond, sf) {
		t.Error("unknown field should return false")
	}
}
