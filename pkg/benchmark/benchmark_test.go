// Copyright 2026 Qwentrix Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package benchmark_test

import (
	"testing"

	"github.com/Qwentrix/lumen-scoring/pkg/benchmark"
)

// TestBucketBoundaries verifies the 5-point bucketing at critical boundary values.
// Acceptance criterion: score 0→0, 4→0, 5→1, 99→19, 100→19.
func TestBucketBoundaries(t *testing.T) {
	cases := []struct {
		score int
		want  int
	}{
		{score: 0, want: 0},   // lowest bucket
		{score: 4, want: 0},   // top of bucket 0
		{score: 5, want: 1},   // bottom of bucket 1
		{score: 9, want: 1},   // top of bucket 1
		{score: 10, want: 2},  // bottom of bucket 2
		{score: 49, want: 9},  // bucket 9
		{score: 50, want: 10}, // bucket 10
		{score: 94, want: 18}, // top of bucket 18
		{score: 95, want: 19}, // bottom of bucket 19
		{score: 99, want: 19}, // just below 100, still bucket 19
		{score: 100, want: 19}, // 100 must clamp to 19 (not overflow to 20)
	}
	for _, tc := range cases {
		got := benchmark.Bucket(tc.score)
		if got != tc.want {
			t.Errorf("Bucket(%d) = %d, want %d", tc.score, got, tc.want)
		}
	}
}

// TestBucketNegativeClamp verifies that negative scores clamp to bucket 0.
func TestBucketNegativeClamp(t *testing.T) {
	if got := benchmark.Bucket(-1); got != 0 {
		t.Errorf("Bucket(-1) = %d, want 0", got)
	}
	if got := benchmark.Bucket(-100); got != 0 {
		t.Errorf("Bucket(-100) = %d, want 0", got)
	}
}

// TestBenchmarkMinCohortN confirms the k-anonymity gate constant is 500.
func TestBenchmarkMinCohortN(t *testing.T) {
	if benchmark.BenchmarkMinCohortN != 500 {
		t.Errorf("BenchmarkMinCohortN = %d, want 500", benchmark.BenchmarkMinCohortN)
	}
}

// TestPercentileMidRankSymmetric verifies that a symmetric histogram centred on a
// bucket produces the 50th percentile for a score in that bucket.
//
// Example: uniform distribution, score=50 (bucket 10).
// With 1000 observations evenly spread (50 each), below=500, same=50, total=1000.
// mid-rank = round(100*(500+25)/1000) = round(52.5) = 53
// (Exact value varies with rounding; the test checks the formula is correct.)
func TestPercentileMidRankFormula(t *testing.T) {
	// Construct a histogram where ONLY bucket 10 is populated (score=50 → bucket 10).
	// below=0, same=100, total=100 → P = round(100*(0+50)/100) = 50.
	var counts [benchmark.BucketCount]int64
	counts[10] = 100
	p := benchmark.Percentile(counts, 50)
	if p != 50 {
		t.Errorf("Percentile with all mass in own bucket: got %d, want 50", p)
	}
}

// TestPercentileLowestBucket: score lands in bucket 0 with some mass above it.
// below=0, same=1, total=1000. P = round(100*(0+0.5)/1000) = 0 → clamped to 1.
func TestPercentileLowestBucket(t *testing.T) {
	var counts [benchmark.BucketCount]int64
	counts[0] = 1
	for i := 1; i < benchmark.BucketCount; i++ {
		counts[i] = 52 // 52 each in buckets 1–19 = 988; total = 989
	}
	// The point is: score is in bucket 0 with 1 obs, rest are above.
	// below=0, same=1, total=989; P = round(100*(0.5)/989) ≈ 0 → clamped to 1.
	p := benchmark.Percentile(counts, 0)
	if p < 1 {
		t.Errorf("Percentile at lowest bucket must be >= 1 (clamp), got %d", p)
	}
}

// TestPercentileHighestBucket: score lands in bucket 19 with all mass below.
// P = round(100*(N-1 + 0.5*1)/N) ≈ 99 → clamped to 99.
func TestPercentileHighestBucket(t *testing.T) {
	var counts [benchmark.BucketCount]int64
	for i := 0; i < benchmark.BucketCount-1; i++ {
		counts[i] = 52 // 52 × 19 = 988 below
	}
	counts[benchmark.BucketCount-1] = 1 // 1 at top
	// P = round(100*(988 + 0.5) / 989) = round(99.949...) = 100 → clamped to 99.
	p := benchmark.Percentile(counts, 100)
	if p > 99 {
		t.Errorf("Percentile at highest bucket must be <= 99 (clamp), got %d", p)
	}
	if p < 95 {
		t.Errorf("Percentile at highest bucket with almost all mass below must be near 99, got %d", p)
	}
}

// TestPercentileClampBounds verifies output is always in [1, 99].
func TestPercentileClampBounds(t *testing.T) {
	// All mass in bucket 0.
	var counts [benchmark.BucketCount]int64
	counts[0] = 1000
	p := benchmark.Percentile(counts, 0)
	if p < 1 || p > 99 {
		t.Errorf("Percentile clamp: got %d, want [1, 99]", p)
	}

	// All mass in bucket 19.
	var counts2 [benchmark.BucketCount]int64
	counts2[19] = 1000
	p2 := benchmark.Percentile(counts2, 99)
	if p2 < 1 || p2 > 99 {
		t.Errorf("Percentile clamp (all top): got %d, want [1, 99]", p2)
	}
}

// TestPercentileZeroTotal: passing a zero histogram returns 1 (guard for caller bug).
func TestPercentileZeroTotal(t *testing.T) {
	var counts [benchmark.BucketCount]int64
	p := benchmark.Percentile(counts, 50)
	if p != 1 {
		t.Errorf("Percentile(zero histogram) = %d, want 1", p)
	}
}

// TestPercentileKnownHistogram verifies an exact percentile for a deterministic
// histogram to serve as a regression anchor.
//
// Healthcare histogram (600 total): 30 observations per bucket for all 20 buckets.
// Score = 65 → bucket 13.
// below  = 30*13 = 390
// same   = 30
// total  = 600
// P = round(100*(390 + 15)/600) = round(100*405/600) = round(67.5) = 68
func TestPercentileKnownHistogram(t *testing.T) {
	var counts [benchmark.BucketCount]int64
	for i := range counts {
		counts[i] = 30
	}
	p := benchmark.Percentile(counts, 65) // score 65 → bucket 13
	if p != 68 {
		t.Errorf("Percentile for known histogram: got %d, want 68", p)
	}
}

// TestCohortN verifies CohortN sums all buckets correctly.
func TestCohortN(t *testing.T) {
	var counts [benchmark.BucketCount]int64
	for i := range counts {
		counts[i] = int64(i + 1) // 1+2+...+20 = 210
	}
	got := benchmark.CohortN(counts)
	if got != 210 {
		t.Errorf("CohortN = %d, want 210", got)
	}
}

// TestCohortNZero verifies CohortN returns 0 for an empty histogram.
func TestCohortNZero(t *testing.T) {
	var counts [benchmark.BucketCount]int64
	if n := benchmark.CohortN(counts); n != 0 {
		t.Errorf("CohortN(empty) = %d, want 0", n)
	}
}

// TestOverallDomainConstant verifies the domain key constant.
func TestOverallDomainConstant(t *testing.T) {
	if benchmark.OverallDomain != "overall" {
		t.Errorf("OverallDomain = %q, want %q", benchmark.OverallDomain, "overall")
	}
}
