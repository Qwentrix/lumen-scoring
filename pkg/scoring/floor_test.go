package scoring_test

// floor_test.go — tests for the per-domain unanswered-loss floor (Stage 1 / Task 1).
//
// The floor guards against sparse answer sets scoring falsely high.
// When DomainCoverage and Floors are nil, scoring must be byte-for-byte unchanged.

import (
	"testing"

	"github.com/Qwentrix/lumen-scoring/pkg/types"
)

// domainScore is a small helper that extracts the score for a single domain from
// a ReportPayload. Returns -1 if the domain is not present (causes the test to fail
// with a clear value rather than a panic).
func domainScore(p *types.ReportPayload, d types.DomainID) int {
	for _, dr := range p.Domains {
		if dr.DomainID == d {
			return dr.Score
		}
	}
	return -1
}

// TestFloor_RaisesLossWhenSparselyAnswered verifies that a domain floor is applied
// when no rules fire but the answer coverage is sparse.
//
// Setup:
//   - Empty Answers (Q-FIRE never fires → rawLoss = 0)
//   - DomainCoverage{compliance: {Answered:3, Total:13}}
//   - Floors{compliance: 0.25}
//
// Expected:
//
//	floorLoss = 0.25 × (1 − 3/13) = 0.25 × (10/13) ≈ 0.19231
//	score     = round(100 × (1 − 0.19231)) = round(80.769) = 81
func TestFloor_RaisesLossWhenSparselyAnswered(t *testing.T) {
	engine := newTestEngine(t)

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "smb",
		Answers:     map[string]string{}, // Q-FIRE never fires
		DomainCoverage: map[types.DomainID]types.DomainCoverage{
			types.DomainCompliance: {Answered: 3, Total: 13},
		},
		Floors: map[types.DomainID]float64{
			types.DomainCompliance: 0.25,
		},
	}

	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	got := domainScore(report, types.DomainCompliance)
	const want = 81
	if got != want {
		t.Errorf("TestFloor_RaisesLossWhenSparselyAnswered: compliance score = %d; want %d", got, want)
	}
}

// TestFloor_FiredLossWinsWhenLarger verifies that when an actual finding fires a
// contribution larger than the floor loss, the fired contribution is used (not the floor).
//
// Setup:
//   - Answers: {"Q-FIRE": "bad"} → Q-FIRE fires, contribution = 0.5×1.0×1.0 = 0.5
//   - DomainCoverage{compliance: {Answered:3, Total:13}}
//   - Floors{compliance: 0.25}
//
// Expected:
//
//	floorLoss = 0.25 × (10/13) ≈ 0.1923  (< fired 0.5 → floor does NOT override)
//	rawLoss   = 0.5
//	score     = round(100 × (1 − 0.5)) = 50
func TestFloor_FiredLossWinsWhenLarger(t *testing.T) {
	engine := newTestEngine(t)

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "smb",
		Answers:     map[string]string{"Q-FIRE": "bad"}, // fires the compliance rule
		DomainCoverage: map[types.DomainID]types.DomainCoverage{
			types.DomainCompliance: {Answered: 3, Total: 13},
		},
		Floors: map[types.DomainID]float64{
			types.DomainCompliance: 0.25,
		},
	}

	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	got := domainScore(report, types.DomainCompliance)
	const want = 50
	if got != want {
		t.Errorf("TestFloor_FiredLossWinsWhenLarger: compliance score = %d; want %d", got, want)
	}
}

// TestFloor_NilConfigIsUnchanged verifies the full-assessment backward-compatibility
// contract: when DomainCoverage and Floors are both nil, an empty Answers map
// produces a score of 100 (no floor applied, no rules fire).
func TestFloor_NilConfigIsUnchanged(t *testing.T) {
	engine := newTestEngine(t)

	input := types.ScoringInput{
		Industry:       "technology",
		CompanySize:    "smb",
		Answers:        map[string]string{},
		DomainCoverage: nil, // explicitly nil
		Floors:         nil, // explicitly nil
	}

	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	got := domainScore(report, types.DomainCompliance)
	const want = 100
	if got != want {
		t.Errorf("TestFloor_NilConfigIsUnchanged: compliance score = %d; want %d (nil config must not apply floor)", got, want)
	}
}

// TestFloor_FullyAnsweredRemovesFloor verifies that when all domain questions are
// answered (Answered == Total), frac == 1, so the floor term becomes 0 and the score
// stays at 100 (no rules fired, no floor applied).
//
// Arithmetic:
//
//	floorLoss = 0.25 × (1 − 13/13) = 0.25 × 0 = 0
//	rawLoss   = 0  (no rules fire)
//	score     = round(100 × (1 − 0)) = 100
func TestFloor_FullyAnsweredRemovesFloor(t *testing.T) {
	engine := newTestEngine(t)

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "smb",
		Answers:     map[string]string{}, // Q-FIRE never fires
		DomainCoverage: map[types.DomainID]types.DomainCoverage{
			types.DomainCompliance: {Answered: 13, Total: 13},
		},
		Floors: map[types.DomainID]float64{
			types.DomainCompliance: 0.25,
		},
	}

	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	got := domainScore(report, types.DomainCompliance)
	const want = 100
	if got != want {
		t.Errorf("TestFloor_FullyAnsweredRemovesFloor: compliance score = %d; want %d (frac=1 → floor=0)", got, want)
	}
}

// TestFloor_TotalZeroNoFloor verifies that when Total <= 0, the floorLoss guard
// returns 0 (division-by-zero guard) and the domain scores at 100.
//
// Arithmetic:
//
//	cov.Total <= 0 → floorLoss returns 0 immediately
//	rawLoss   = 0  (no rules fire)
//	score     = 100
func TestFloor_TotalZeroNoFloor(t *testing.T) {
	engine := newTestEngine(t)

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "smb",
		Answers:     map[string]string{}, // Q-FIRE never fires
		DomainCoverage: map[types.DomainID]types.DomainCoverage{
			types.DomainCompliance: {Answered: 0, Total: 0},
		},
		Floors: map[types.DomainID]float64{
			types.DomainCompliance: 0.25,
		},
	}

	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	got := domainScore(report, types.DomainCompliance)
	const want = 100
	if got != want {
		t.Errorf("TestFloor_TotalZeroNoFloor: compliance score = %d; want %d (Total=0 guard → floor=0)", got, want)
	}
}

// TestFloor_NegativeAnsweredClamped verifies that a negative Answered value is clamped
// to 0 before computing frac, so the floor is applied at its maximum (full floor).
//
// Arithmetic:
//
//	frac      = -5/13 → clamped to 0
//	floorLoss = 0.25 × (1 − 0) = 0.25
//	rawLoss   = 0  (no rules fire)
//	score     = round(100 × (1 − 0.25)) = 75
func TestFloor_NegativeAnsweredClamped(t *testing.T) {
	engine := newTestEngine(t)

	input := types.ScoringInput{
		Industry:    "technology",
		CompanySize: "smb",
		Answers:     map[string]string{}, // Q-FIRE never fires
		DomainCoverage: map[types.DomainID]types.DomainCoverage{
			types.DomainCompliance: {Answered: -5, Total: 13},
		},
		Floors: map[types.DomainID]float64{
			types.DomainCompliance: 0.25,
		},
	}

	report, err := engine.Score(input)
	if err != nil {
		t.Fatalf("Score: %v", err)
	}

	got := domainScore(report, types.DomainCompliance)
	const want = 75
	if got != want {
		t.Errorf("TestFloor_NegativeAnsweredClamped: compliance score = %d; want %d (negative frac clamped → full floor 0.25)", got, want)
	}
}
