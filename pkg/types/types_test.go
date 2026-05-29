package types_test

import (
	"testing"

	"github.com/Qwentrix/lumen-scoring/pkg/types"
)

func TestGrade(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{100, "A"},
		{90, "A"},
		{89, "B"},
		{75, "B"},
		{74, "C"},
		{60, "C"},
		{59, "D"},
		{45, "D"},
		{44, "F"},
		{0, "F"},
	}
	for _, c := range cases {
		got := types.Grade(c.score)
		if got != c.want {
			t.Errorf("Grade(%d) = %q; want %q", c.score, got, c.want)
		}
	}
}

func TestSeverityFactor(t *testing.T) {
	cases := []struct {
		sev  types.Severity
		want float64
	}{
		{types.SeverityCritical, 1.0},
		{types.SeverityHigh, 0.8},
		{types.SeverityMedium, 0.5},
		{types.SeverityLow, 0.25},
		{"unknown", 0.0},
	}
	for _, c := range cases {
		got := types.SeverityFactor(c.sev)
		if got != c.want {
			t.Errorf("SeverityFactor(%q) = %v; want %v", c.sev, got, c.want)
		}
	}
}
