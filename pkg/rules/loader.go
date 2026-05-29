package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// RuleStore is an immutable, indexed collection of loaded FindingRule objects.
type RuleStore struct {
	rules  []*FindingRule
	byID   map[string]*FindingRule
}

// All returns all rules in load order.
func (s *RuleStore) All() []*FindingRule {
	return s.rules
}

// ByID returns the rule with the given ID, or nil if not found.
func (s *RuleStore) ByID(id string) *FindingRule {
	return s.byID[id]
}

// Count returns the number of loaded rules.
func (s *RuleStore) Count() int {
	return len(s.rules)
}

// OverlayStore is an immutable, indexed collection of loaded IndustryOverlay objects.
type OverlayStore struct {
	overlays []*IndustryOverlay
	byID     map[string]*IndustryOverlay
}

// All returns all overlays in load order.
func (s *OverlayStore) All() []*IndustryOverlay {
	return s.overlays
}

// ByID returns the overlay for the given industry ID.
// Returns nil if not found — callers should fall back to a default overlay.
func (s *OverlayStore) ByID(id string) *IndustryOverlay {
	return s.byID[id]
}

// Count returns the number of loaded overlays.
func (s *OverlayStore) Count() int {
	return len(s.overlays)
}

// LoadRulesFromDir reads all *.yaml files in dir and returns a RuleStore.
// Files that fail to parse are collected and returned as a combined error.
// An empty directory returns an empty store with no error.
func LoadRulesFromDir(dir string) (*RuleStore, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("rules: reading directory %q: %w", dir, err)
	}

	store := &RuleStore{
		byID: make(map[string]*FindingRule),
	}
	var errs []string

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		rule, parseErr := loadRuleFile(path)
		if parseErr != nil {
			errs = append(errs, parseErr.Error())
			continue
		}
		if _, dup := store.byID[rule.ID]; dup {
			errs = append(errs, fmt.Sprintf("rules: duplicate rule ID %q in %s", rule.ID, path))
			continue
		}
		store.rules = append(store.rules, rule)
		store.byID[rule.ID] = rule
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("rules: %d error(s) loading from %q:\n  %s",
			len(errs), dir, strings.Join(errs, "\n  "))
	}
	return store, nil
}

// LoadOverlaysFromDir reads all *.yaml files in dir and returns an OverlayStore.
func LoadOverlaysFromDir(dir string) (*OverlayStore, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("overlays: reading directory %q: %w", dir, err)
	}

	store := &OverlayStore{
		byID: make(map[string]*IndustryOverlay),
	}
	var errs []string

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yaml") {
			continue
		}

		path := filepath.Join(dir, entry.Name())
		overlay, parseErr := loadOverlayFile(path)
		if parseErr != nil {
			errs = append(errs, parseErr.Error())
			continue
		}
		if _, dup := store.byID[overlay.ID]; dup {
			errs = append(errs, fmt.Sprintf("overlays: duplicate overlay ID %q in %s", overlay.ID, path))
			continue
		}
		store.overlays = append(store.overlays, overlay)
		store.byID[overlay.ID] = overlay
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("overlays: %d error(s) loading from %q:\n  %s",
			len(errs), dir, strings.Join(errs, "\n  "))
	}
	return store, nil
}

// loadRuleFile parses a single rule YAML file and validates required fields.
func loadRuleFile(path string) (*FindingRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var rule FindingRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	if err := validateRule(&rule, path); err != nil {
		return nil, err
	}
	return &rule, nil
}

// loadOverlayFile parses a single overlay YAML file and validates required fields.
func loadOverlayFile(path string) (*IndustryOverlay, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var overlay IndustryOverlay
	if err := yaml.Unmarshal(data, &overlay); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}

	if err := validateOverlay(&overlay, path); err != nil {
		return nil, err
	}
	return &overlay, nil
}

// validateRule checks that a parsed FindingRule has all required fields set.
func validateRule(r *FindingRule, path string) error {
	var missing []string
	if r.ID == "" {
		missing = append(missing, "id")
	}
	if r.Domain == "" {
		missing = append(missing, "domain")
	}
	if r.Severity == "" {
		missing = append(missing, "severity")
	}
	if r.DefaultWeight <= 0 || r.DefaultWeight > 1.0 {
		missing = append(missing, "default_weight (must be 0 < w ≤ 1.0)")
	}
	if r.Title == "" {
		missing = append(missing, "title")
	}
	if len(missing) > 0 {
		return fmt.Errorf("rule %s: missing or invalid fields: %s",
			path, strings.Join(missing, ", "))
	}
	return nil
}

// validateOverlay checks that a parsed IndustryOverlay has all required fields set.
func validateOverlay(o *IndustryOverlay, path string) error {
	if o.ID == "" {
		return fmt.Errorf("overlay %s: missing required field: id", path)
	}
	if o.DisplayName == "" {
		return fmt.Errorf("overlay %s: missing required field: display_name", path)
	}
	return nil
}
