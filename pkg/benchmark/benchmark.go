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

// Package benchmark provides the privacy-preserving histogram math for the
// Lumen industry benchmark feature (ENT-115 / LU-8).
//
// Pure functions, zero I/O. Both the lumen-api server (write and read paths)
// and any external auditor import this package to replay bucket assignments and
// percentile computations from public bucket counts (TP5, TP7).
//
// # Design invariant
//
// Scores are bucketed into 20 fixed-width 5-point ranges (bucket 0 = [0,4],
// bucket 19 = [95,100]). Only aggregate bucket counts are ever stored — never
// individual scores, session IDs, or any PII. Percentiles are served only when
// the cohort has ≥ BenchmarkMinCohortN = 500 observations (k-anonymity gate,
// §4.2 of LU8-BUILD-BLUEPRINT.md).
package benchmark

// BucketCount is the number of histogram buckets (20 × 5-point ranges).
const BucketCount = 20

// BucketWidth is the width of each bucket in score points.
const BucketWidth = 5

// BenchmarkMinCohortN is the minimum cohort size required before a percentile is
// served. When total_N(industry, 'overall') < BenchmarkMinCohortN the endpoint
// returns available:false and no percentile computation is performed.
// The name is intentionally qualified (rather than a bare MinCohortN) to avoid
// collision when this OSS package is imported alongside other benchmark packages
// and to match the specification constant name in LU8-BUILD-BLUEPRINT.md §4.2.
const BenchmarkMinCohortN = 500

// OverallDomain is the pseudo-domain key used for the overall score histogram
// alongside the five real domain IDs.
const OverallDomain = "overall"

// Bucket maps a 0–100 score to a 0–19 histogram bucket index.
//
//	bucket 0  → scores [0,  4]
//	bucket 1  → scores [5,  9]
//	…
//	bucket 19 → scores [95, 100]  (6 values; 100 is clamped into bucket 19)
//
// The formula is min(19, score/5) using integer division.
// A score of 100 would produce floor(100/5)=20, which is clamped to 19,
// so a perfect score lands in the top bucket rather than overflowing.
func Bucket(score int) int {
	if score < 0 {
		return 0
	}
	b := score / BucketWidth
	if b > BucketCount-1 {
		return BucketCount - 1
	}
	return b
}

// Percentile computes the mid-rank percentile of score within the given
// histogram of BucketCount bucket counts.
//
// Formula (mid-rank / midpoint convention):
//
//	b*    = Bucket(score)
//	below = Σ counts[b]  for b < b*      (observations in strictly lower buckets)
//	same  = counts[b*]                    (observations in the user's own bucket)
//	total = Σ counts[b]  for all b
//	P     = round(100 * (below + 0.5 * same) / total)   clamped to [1, 99]
//
// The mid-rank convention removes the systematic bias of counting the same-bucket
// mass as fully-below (overstates) or fully-above (understates). It guarantees
// 0 < P < 100 whenever total > 0.
//
// The caller MUST have already passed the cohort gate (total >= BenchmarkMinCohortN)
// before calling Percentile. Passing a zero-total histogram is a caller bug and
// returns 1.
//
// Higher score = better posture, so "Nth percentile" means N% of the cohort
// scored at or below the user's bucket (favourable direction).
func Percentile(counts [BucketCount]int64, score int) int {
	b := Bucket(score)

	var below, same, total int64
	for i := 0; i < BucketCount; i++ {
		total += counts[i]
		if i < b {
			below += counts[i]
		} else if i == b {
			same = counts[i]
		}
	}
	if total == 0 {
		return 1
	}

	// mid-rank: treat user as sitting at the median of their own bucket.
	// Use integer arithmetic with *2 scaling to avoid floating-point for the
	// 0.5 factor: round(100*(below + 0.5*same)/total)
	// = round((200*below + 100*same) / (2*total))
	// = (200*below + 100*same + total) / (2*total)  [integer round-half-up]
	// L-4: 200*below is int64; theoretical overflow at ~4.6e16 lower-bucket
	// observations (int64 max / 200) — unreachable in any realistic deployment.
	// Do NOT change these to int32 or smaller types to "optimise" — int64 is required.
	numerator := 200*below + 100*same + total // +total is the rounding offset (÷2 in denominator)
	p := int(numerator / (2 * total))

	// Clamp to [1, 99] so we never display "0th percentile" or "100th percentile".
	if p < 1 {
		return 1
	}
	if p > 99 {
		return 99
	}
	return p
}

// CohortN sums all bucket counts to produce the total cohort size for one
// (industry, domain) pair.
func CohortN(counts [BucketCount]int64) int64 {
	var total int64
	for _, c := range counts {
		total += c
	}
	return total
}
