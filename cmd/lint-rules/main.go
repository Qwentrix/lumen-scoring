// lint-rules validates Lumen content YAML files (rules and overlays) against
// the lumen-scoring schema.
//
// Usage:
//
//	lint-rules --rules <dir> [--overlays <dir>] [--strict]
//
// Exit codes:
//
//	0  All files are valid.
//	1  One or more validation errors found.
//	2  Usage / flag error.
//
// This binary is used by:
//   - qwen-web CI: validates content/rules/ and content/overlays/ before publishing a bundle to S3.
//   - lumen-api startup: called as a library function (not this binary) before content hot-swap.
//   - lumen scanner update: validates the downloaded bundle before installing it.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Qwentrix/lumen-scoring/pkg/rules"
)

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("lint-rules", flag.ContinueOnError)
	rulesDir := fs.String("rules", "", "path to directory containing rule YAML files (required)")
	overlaysDir := fs.String("overlays", "", "path to directory containing overlay YAML files (optional)")
	strict := fs.Bool("strict", false, "fail if no rule or overlay files are found (useful in CI)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		// flag package prints usage automatically on error.
		return 2
	}

	if *rulesDir == "" {
		fmt.Fprintln(os.Stderr, "lint-rules: --rules is required")
		fs.Usage()
		return 2
	}

	ok := true

	// Validate rules.
	fmt.Printf("lint-rules: loading rules from %q ...\n", *rulesDir)
	ruleStore, err := rules.LoadRulesFromDir(*rulesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lint-rules: rules validation failed:\n%v\n", err)
		ok = false
	} else {
		fmt.Printf("lint-rules: %d rule(s) OK\n", ruleStore.Count())
		if *strict && ruleStore.Count() == 0 {
			fmt.Fprintln(os.Stderr, "lint-rules: --strict: no rule files found")
			ok = false
		}
	}

	// Validate overlays (optional).
	if *overlaysDir != "" {
		fmt.Printf("lint-rules: loading overlays from %q ...\n", *overlaysDir)
		overlayStore, overlayErr := rules.LoadOverlaysFromDir(*overlaysDir)
		if overlayErr != nil {
			fmt.Fprintf(os.Stderr, "lint-rules: overlays validation failed:\n%v\n", overlayErr)
			ok = false
		} else {
			fmt.Printf("lint-rules: %d overlay(s) OK\n", overlayStore.Count())
			if *strict && overlayStore.Count() == 0 {
				fmt.Fprintln(os.Stderr, "lint-rules: --strict: no overlay files found")
				ok = false
			}
		}
	}

	if !ok {
		fmt.Fprintln(os.Stderr, "lint-rules: FAILED")
		return 1
	}

	fmt.Println("lint-rules: all files valid")
	return 0
}
