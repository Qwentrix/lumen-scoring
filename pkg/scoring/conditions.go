package scoring

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/Qwentrix/lumen-scoring/pkg/rules"
	"github.com/Qwentrix/lumen-scoring/pkg/types"
)

// parseCondition parses a detect condition string of the form "<key> <op> <value>"
// into its three components. Returns an error if the string is malformed.
//
// Supported operators: ==, !=, >, <, >=, <=
func parseCondition(cond string) (key, op, val string, err error) {
	for _, candidate := range []string{">=", "<=", "!=", "==", ">", "<"} {
		idx := strings.Index(cond, candidate)
		if idx < 0 {
			continue
		}
		key = strings.TrimSpace(cond[:idx])
		op = candidate
		val = strings.TrimSpace(cond[idx+len(candidate):])
		if key == "" || val == "" {
			return "", "", "", fmt.Errorf("conditions: malformed expression %q", cond)
		}
		return key, op, val, nil
	}
	return "", "", "", fmt.Errorf("conditions: no operator found in %q", cond)
}

// evalScannerCondition evaluates a scanner detect condition against the provided findings.
//
// Scanner condition keys use dot notation: "<domain>.<field>".
// e.g. "aigov.shadow_ai_apps_count > 2"
//      "compliance.mfa_enabled == true"
//
// Supported field types: int (numeric comparisons), bool (== / != only).
// Returns false on any parse or lookup error — unknown probes do not trigger rules.
func evalScannerCondition(cond rules.DetectCondition, sf *types.ScannerFindings) bool {
	key, op, val, err := parseCondition(string(cond))
	if err != nil {
		return false
	}

	fieldVal, found := scannerFieldValue(key, sf)
	if !found {
		return false
	}

	return compareValues(fieldVal, op, val)
}

// scannerFieldValue extracts the numeric or boolean value for a scanner field key.
// Returns (value, true) if the key is known, (nil, false) otherwise.
func scannerFieldValue(key string, sf *types.ScannerFindings) (interface{}, bool) {
	// Use reflection on the ScannerFindings struct to look up fields by their json tag.
	// This avoids a giant switch statement and stays in sync with the struct definition.
	parts := strings.SplitN(key, ".", 2)
	if len(parts) != 2 {
		return nil, false
	}
	domain, fieldName := parts[0], parts[1]

	var domainStruct interface{}
	switch domain {
	case "vulnerabilities":
		domainStruct = sf.Vulnerabilities
	case "compliance":
		domainStruct = sf.Compliance
	case "ai_governance", "aigov":
		domainStruct = sf.AIGovernance
	case "security_posture", "posture":
		domainStruct = sf.SecurityPosture
	case "privacy":
		domainStruct = sf.Privacy
	case "cloud":
		// ENT-118 cloud findings are opt-in. When no provider was actually scanned,
		// every field is its zero value (e.g. root_mfa_enabled=false), which would
		// FALSELY fire `cloud.* == false` rules (CLOUD_ROOT_NO_MFA, CLOUD_NO_AUDIT_LOGGING)
		// on a normal scan. Treat all cloud fields as "not present" unless a provider
		// was scanned, so cloud rules fire only when --include-cloud actually ran.
		//
		// This guard protects ALL cloud rules regardless of operator, including future
		// ones — it must live here, not in the rule's `scanner:` list, because scanner
		// conditions within a rule are OR-ed (engine.go appends to triggeredBy on ANY
		// match), so a `cloud.scanned == true` guard in the rule list cannot express it.
		//
		// ProvidersScanned is the reliable signal: the scanner populates it only for
		// providers that completed a real scan, so an empty slice means cloud was never
		// touched and every cloud.* field must read as "not present".
		if len(sf.Cloud.ProvidersScanned) == 0 {
			return nil, false
		}
		domainStruct = sf.Cloud
	default:
		return nil, false
	}

	return reflectFieldByJSONTag(domainStruct, fieldName)
}

// reflectFieldByJSONTag finds a struct field by its json tag name and returns its value.
func reflectFieldByJSONTag(s interface{}, jsonTag string) (interface{}, bool) {
	rv := reflect.ValueOf(s)
	if rv.Kind() == reflect.Ptr {
		if rv.IsNil() {
			return nil, false
		}
		rv = rv.Elem()
	}
	if rv.Kind() != reflect.Struct {
		return nil, false
	}

	rt := rv.Type()
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		tag := field.Tag.Get("json")
		// Strip options like ",omitempty".
		if idx := strings.Index(tag, ","); idx >= 0 {
			tag = tag[:idx]
		}
		if tag == jsonTag {
			return rv.Field(i).Interface(), true
		}
	}
	return nil, false
}

// compareValues compares a runtime field value to a literal string value using op.
// Supports int64 and bool comparisons. Returns false on type mismatch.
func compareValues(fieldVal interface{}, op, literal string) bool {
	switch v := fieldVal.(type) {
	case int:
		return compareInt(int64(v), op, literal)
	case int64:
		return compareInt(v, op, literal)
	case bool:
		return compareBool(v, op, literal)
	default:
		// For other types, fall back to string equality.
		if op == "==" {
			return fmt.Sprintf("%v", fieldVal) == literal
		}
		if op == "!=" {
			return fmt.Sprintf("%v", fieldVal) != literal
		}
		return false
	}
}

func compareInt(v int64, op, literal string) bool {
	n, err := strconv.ParseInt(literal, 10, 64)
	if err != nil {
		return false
	}
	switch op {
	case "==":
		return v == n
	case "!=":
		return v != n
	case ">":
		return v > n
	case "<":
		return v < n
	case ">=":
		return v >= n
	case "<=":
		return v <= n
	default:
		return false
	}
}

func compareBool(v bool, op, literal string) bool {
	b, err := strconv.ParseBool(literal)
	if err != nil {
		return false
	}
	switch op {
	case "==":
		return v == b
	case "!=":
		return v != b
	default:
		return false
	}
}
