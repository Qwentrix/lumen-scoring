// lumen-lint validates Lumen content YAML files (rules, overlays, and questions)
// against the lumen-scoring schemas.
//
// Usage (directory mode — validates all files in a directory):
//
//	lumen-lint --rules <dir> [--overlays <dir>] [--questions <dir>] [--strict]
//
// Usage (per-file validation mode):
//
//	lumen-lint validate --schema {rules|overlays|questions} <file.yaml>
//
// Exit codes:
//
//	0  All files are valid.
//	1  One or more validation errors found.
//	2  Usage / flag error.
//
// This binary is used by:
//   - qwen-web CI: validates content/rules/, content/overlays/, and content/questions/
//     before publishing a bundle to S3.
//   - lumen scanner update: validates the downloaded bundle before installing it.
//
// The canonical binary name for GitHub Release assets is:
//
//	lumen-lint-<os>-<arch>  (e.g. lumen-lint-linux-amd64, lumen-lint-darwin-arm64)
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/Qwentrix/lumen-scoring/pkg/rules"
	"gopkg.in/yaml.v3"
)

func main() {
	os.Exit(run(os.Args[1:]))
}

// run is the testable entry-point. Returns 0 on success, 1 on validation error,
// 2 on usage error.
func run(args []string) int {
	// Dispatch the "validate" subcommand before flag parsing.
	if len(args) > 0 && args[0] == "validate" {
		return runValidate(args[1:])
	}

	fs := flag.NewFlagSet("lumen-lint", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	rulesDir := fs.String("rules", "", "path to directory containing rule YAML files")
	overlaysDir := fs.String("overlays", "", "path to directory containing overlay YAML files")
	questionsDir := fs.String("questions", "", "path to directory containing question YAML files")
	strict := fs.Bool("strict", false, "fail if no files are found in a supplied directory")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	// At least one directory must be provided.
	if *rulesDir == "" && *overlaysDir == "" && *questionsDir == "" {
		fmt.Fprintln(os.Stderr, "lumen-lint: at least one of --rules, --overlays, or --questions is required")
		fs.Usage()
		return 2
	}

	ok := true

	// Validate rules directory.
	if *rulesDir != "" {
		fmt.Printf("lumen-lint: validating rules in %q ...\n", *rulesDir)
		ruleStore, err := rules.LoadRulesFromDir(*rulesDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lumen-lint: rules validation FAILED:\n%v\n", err)
			ok = false
		} else {
			fmt.Printf("lumen-lint: %d rule(s) OK\n", ruleStore.Count())
			if *strict && ruleStore.Count() == 0 {
				fmt.Fprintln(os.Stderr, "lumen-lint: --strict: no rule files found in "+*rulesDir)
				ok = false
			}
		}
	}

	// Validate overlays directory.
	if *overlaysDir != "" {
		fmt.Printf("lumen-lint: validating overlays in %q ...\n", *overlaysDir)
		overlayStore, err := rules.LoadOverlaysFromDir(*overlaysDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lumen-lint: overlays validation FAILED:\n%v\n", err)
			ok = false
		} else {
			fmt.Printf("lumen-lint: %d overlay(s) OK\n", overlayStore.Count())
			if *strict && overlayStore.Count() == 0 {
				fmt.Fprintln(os.Stderr, "lumen-lint: --strict: no overlay files found in "+*overlaysDir)
				ok = false
			}
		}
	}

	// Validate questions directory.
	if *questionsDir != "" {
		fmt.Printf("lumen-lint: validating questions in %q ...\n", *questionsDir)
		count, errs := validateQuestionsDir(*questionsDir)
		if len(errs) > 0 {
			fmt.Fprintf(os.Stderr, "lumen-lint: questions validation FAILED:\n  %s\n",
				strings.Join(errs, "\n  "))
			ok = false
		} else {
			fmt.Printf("lumen-lint: %d question file(s) OK\n", count)
			if *strict && count == 0 {
				fmt.Fprintln(os.Stderr, "lumen-lint: --strict: no question files found in "+*questionsDir)
				ok = false
			}
		}
	}

	if !ok {
		fmt.Fprintln(os.Stderr, "lumen-lint: FAILED")
		return 1
	}

	fmt.Println("lumen-lint: all files valid")
	return 0
}

// runValidate implements the "validate" subcommand.
//
// Usage: lumen-lint validate --schema {rules|overlays|questions} <file.yaml>
//
// Validates a single YAML file and exits non-zero with a precise error on failure.
// This satisfies AC-95-7/8 (T-95-11..14): per-file validation mode.
func runValidate(args []string) int {
	fs := flag.NewFlagSet("lumen-lint validate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	schema := fs.String("schema", "", "schema type: rules | overlays | questions")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if *schema == "" {
		fmt.Fprintln(os.Stderr, "lumen-lint validate: --schema is required (rules|overlays|questions)")
		fs.Usage()
		return 2
	}

	switch *schema {
	case "rules", "overlays", "questions":
		// valid
	default:
		fmt.Fprintf(os.Stderr, "lumen-lint validate: unknown --schema %q (must be rules, overlays, or questions)\n", *schema)
		return 2
	}

	filePath := fs.Arg(0)
	if filePath == "" {
		fmt.Fprintf(os.Stderr, "lumen-lint validate: file path argument required\n")
		fs.Usage()
		return 2
	}

	var errs []string
	switch *schema {
	case "rules":
		errs = validateSingleRuleFile(filePath)
	case "overlays":
		errs = validateSingleOverlayFile(filePath)
	case "questions":
		errs = validateQuestionFile(filePath)
	}

	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, e)
		}
		fmt.Fprintln(os.Stderr, "lumen-lint validate: FAILED")
		return 1
	}

	fmt.Printf("lumen-lint validate: %s OK\n", filePath)
	return 0
}

// validateSingleRuleFile validates a single rule YAML file.
// Returns a slice of error strings, or nil if valid.
func validateSingleRuleFile(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("%s: read error: %v", path, err)}
	}

	var rule rules.FindingRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return []string{fmt.Sprintf("%s: YAML parse error: %v", path, err)}
	}

	var errs []string
	if rule.ID == "" {
		errs = append(errs, fmt.Sprintf("%s: id: required", path))
	}
	validDomains := map[string]bool{
		"vulnerabilities":  true,
		"compliance":       true,
		"ai_governance":    true,
		"security_posture": true,
		"privacy":          true,
	}
	if rule.Domain == "" {
		errs = append(errs, fmt.Sprintf("%s: domain: required", path))
	} else if !validDomains[string(rule.Domain)] {
		errs = append(errs, fmt.Sprintf("%s: domain: invalid value %q (must be one of: vulnerabilities, compliance, ai_governance, security_posture, privacy)", path, rule.Domain))
	}
	validSeverities := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
	}
	if rule.Severity == "" {
		errs = append(errs, fmt.Sprintf("%s: severity: required", path))
	} else if !validSeverities[string(rule.Severity)] {
		errs = append(errs, fmt.Sprintf("%s: severity: invalid value %q (must be one of: critical, high, medium, low)", path, rule.Severity))
	}
	if rule.DefaultWeight <= 0 || rule.DefaultWeight > 1.0 {
		errs = append(errs, fmt.Sprintf("%s: default_weight: required and must satisfy 0 < weight <= 1.0 (got %v)", path, rule.DefaultWeight))
	}
	if rule.Title == "" {
		errs = append(errs, fmt.Sprintf("%s: title: required", path))
	}
	return errs
}

// validateSingleOverlayFile validates a single overlay YAML file.
// Returns a slice of error strings, or nil if valid.
func validateSingleOverlayFile(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("%s: read error: %v", path, err)}
	}

	// Use the same struct the loader uses so field names stay in sync.
	type overlayFile struct {
		ID          string             `yaml:"id"`
		DisplayName string             `yaml:"display_name"`
		DomainMults map[string]float64 `yaml:"domain_weight_multipliers"`
	}

	var o overlayFile
	if err := yaml.Unmarshal(data, &o); err != nil {
		return []string{fmt.Sprintf("%s: YAML parse error: %v", path, err)}
	}

	var errs []string
	if o.ID == "" {
		errs = append(errs, fmt.Sprintf("%s: id: required", path))
	}
	if o.DisplayName == "" {
		errs = append(errs, fmt.Sprintf("%s: display_name: required", path))
	}
	return errs
}

// questionFile is the in-memory representation of a question YAML file.
// Fields mirror the questions.schema.yaml definition.
type questionFile struct {
	Domain    string           `yaml:"domain"`
	Version   int              `yaml:"version"`
	Questions []questionEntry  `yaml:"questions"`
}

type questionEntry struct {
	ID                    string              `yaml:"id"`
	Text                  string              `yaml:"text"`
	ApplicableIndustries  []string            `yaml:"applicable_industries"`
	ApplicableSizes       []string            `yaml:"applicable_sizes"`
	AnswerOptions         []answerOption      `yaml:"answer_options"`
	AnswerFindings        map[string][]string `yaml:"answer_findings"`
	DepthLevel            string              `yaml:"depth_level"`
	EstimatedSeconds      int                 `yaml:"estimated_seconds"`
}

type answerOption struct {
	Value string `yaml:"value"`
	Label string `yaml:"label"`
}

// validateQuestionsDir reads all *.yaml files in dir, validates each question file,
// and returns the count of valid files and any errors.
func validateQuestionsDir(dir string) (int, []string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, []string{fmt.Sprintf("questions: reading directory %q: %v", dir, err)}
	}

	var errs []string
	count := 0

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if fileErrs := validateQuestionFile(path); len(fileErrs) > 0 {
			errs = append(errs, fileErrs...)
		} else {
			count++
		}
	}
	return count, errs
}

// validateQuestionFile parses and validates a single question YAML file.
// Returns a slice of error strings, or nil if valid.
func validateQuestionFile(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return []string{fmt.Sprintf("%s: read error: %v", path, err)}
	}

	var qf questionFile
	if err := yaml.Unmarshal(data, &qf); err != nil {
		return []string{fmt.Sprintf("%s: YAML parse error: %v", path, err)}
	}

	var errs []string

	// Validate top-level required fields.
	validDomains := map[string]bool{
		"vulnerabilities": true,
		"compliance":      true,
		"ai_governance":   true,
		"security_posture": true,
		"privacy":         true,
	}
	if qf.Domain == "" {
		errs = append(errs, fmt.Sprintf("%s: domain: required", path))
	} else if !validDomains[qf.Domain] {
		errs = append(errs, fmt.Sprintf("%s: domain: invalid value %q (must be one of: vulnerabilities, compliance, ai_governance, security_posture, privacy)", path, qf.Domain))
	}

	if qf.Version == 0 {
		errs = append(errs, fmt.Sprintf("%s: version: required (must be > 0)", path))
	}

	if len(qf.Questions) == 0 {
		errs = append(errs, fmt.Sprintf("%s: questions: must contain at least one question", path))
	}

	// Validate each question entry.
	seenIDs := make(map[string]bool)
	for i, q := range qf.Questions {
		prefix := fmt.Sprintf("%s: questions[%d]", path, i)
		if q.ID == "" {
			errs = append(errs, fmt.Sprintf("%s: id: required", prefix))
		} else if seenIDs[q.ID] {
			errs = append(errs, fmt.Sprintf("%s: id %q: duplicate", prefix, q.ID))
		} else {
			seenIDs[q.ID] = true
		}
		if q.Text == "" {
			errs = append(errs, fmt.Sprintf("%s: text: required", prefix))
		}
		if q.DepthLevel != "" && q.DepthLevel != "triage" && q.DepthLevel != "deepdive" {
			errs = append(errs, fmt.Sprintf("%s: depth_level: invalid value %q (must be triage or deepdive)", prefix, q.DepthLevel))
		}
	}

	return errs
}
