# lumen-scoring

Shared Go scoring module for [Micelium Lumen](https://lumen.micelium.com) — the free security risk assessment tool by [Qwentrix](https://qwentrix.com).

This module is vendored by both the `lumen-api` server and the `lumen` scanner CLI to guarantee **identical scoring results** whether an assessment is completed via the web questionnaire or the local scanner binary.

[![CI](https://github.com/Qwentrix/lumen-scoring/actions/workflows/ci.yml/badge.svg)](https://github.com/Qwentrix/lumen-scoring/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Qwentrix/lumen-scoring.svg)](https://pkg.go.dev/github.com/Qwentrix/lumen-scoring)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

---

## Overview

`lumen-scoring` implements the deterministic, rule-based scoring engine at the heart of Lumen. Given a set of questionnaire answers (and optionally structured local-scanner probe results), it evaluates a library of YAML-defined finding rules across five security domains, applies industry-specific weight overlays, and returns a per-domain and overall score (0–100) with a letter grade (A–F) and an explainability trace for the "Why?" panel.

No machine learning. No randomness. Same input always produces the same output. This is an explicit design choice for a tool that must be independently auditable.

### Five scoring domains

| Domain | Description |
|---|---|
| `vulnerabilities` | Patch levels, known CVEs, software inventory |
| `compliance` | MFA, disk encryption, firewall, screen lock, patch policy |
| `ai_governance` | Shadow AI, LLM acceptable-use policy, browser extensions, model egress |
| `security_posture` | SSH keys, password manager, browser config, listening ports, startup items |
| `privacy` | PII presence, DLP posture, home-directory exposure |

### Industry overlays

Ten industry profiles ship with the rule content: `healthcare`, `financial`, `government`, `education`, `technology`, `it_services`, `legal`, `energy`, `retail`, `manufacturing`. Each overlay defines per-domain weight multipliers and per-rule weight overrides that adjust scores to reflect the regulatory and threat landscape of that industry.

---

## API Surface

```go
import (
    "github.com/Qwentrix/lumen-scoring/pkg/scoring"
    "github.com/Qwentrix/lumen-scoring/pkg/types"
    "github.com/Qwentrix/lumen-scoring/pkg/rules"
)

// Load rules from a content bundle directory (populated by lumen-api or lumen CLI).
store, err := rules.LoadFromDir("/path/to/content/rules")
if err != nil {
    log.Fatal(err)
}

overlays, err := rules.LoadOverlaysFromDir("/path/to/content/overlays")
if err != nil {
    log.Fatal(err)
}

// Prepare inputs.
input := types.ScoringInput{
    Industry:        "healthcare",
    CompanySize:     "enterprise",
    Answers:         map[string]string{"Q-AIGOV-001": "no_policy", "Q-COMP-003": "yes_full"},
    ScannerFindings: nil, // nil = questionnaire-only path
}

// Run the scoring engine.
engine := scoring.NewEngine(store, overlays)
report, err := engine.Score(input)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Overall: %d (%s)\n", report.OverallScore, report.OverallGrade)
for _, d := range report.Domains {
    fmt.Printf("  %s: %d (%s) — %d findings\n",
        d.DomainID, d.Score, d.Grade, len(d.Findings))
}
```

### Key types

| Type | Package | Description |
|---|---|---|
| `ScoringInput` | `pkg/types` | Questionnaire answers + optional scanner findings |
| `ReportPayload` | `pkg/types` | Full scoring output: domain scores, top risks, fix list, explain trace |
| `DomainResult` | `pkg/types` | Per-domain score, grade, findings, explain trace |
| `FindingResult` | `pkg/types` | A triggered rule: ID, severity, contribution, frameworks |
| `ExplainStep` | `pkg/types` | One term in the "Why?" breakdown (for the UI panel) |
| `RuleStore` | `pkg/rules` | In-memory collection of loaded `FindingRule` objects |
| `OverlayStore` | `pkg/rules` | In-memory collection of loaded `IndustryOverlay` objects |
| `Engine` | `pkg/scoring` | Stateless scorer; call `Score(ScoringInput)` |

### Grade thresholds

| Score | Grade |
|---|---|
| 90–100 | A |
| 75–89 | B |
| 60–74 | C |
| 45–59 | D |
| 0–44 | F |

These thresholds are the single source of truth — identical on the backend and in the `qwen-web` front-end via `lib/lumen/score-formatter.ts`.

---

## Rule YAML format

Rules live in `qwen-web/lumen/content/rules/` (the canonical content repository) and are bundled for both `lumen-api` and the scanner CLI. This module only parses them; it does not ship or version them.

Example rule file (`rules/AIGOV_NO_AUP.yaml`):

```yaml
id: AIGOV_NO_AUP
domain: ai_governance
severity: high          # critical | high | medium | low
default_weight: 0.75    # 0.0–1.0
detect:
  questionnaire:
    - Q-AIGOV-001 == no_policy
  scanner:
    - aigov.shadow_ai_apps_count > 2
title: "No AI acceptable-use policy"
description_short: "No written AI policy for employee LLM use."
frameworks:
  - { id: "EU AI Act Art. 26", text: "Deployer obligations: documented use-policy" }
  - { id: "NIST AI RMF GOVERN-1.1", text: "AI policies established" }
industry_overlays:
  healthcare:  { weight_multiplier: 1.7 }
  financial:   { weight_multiplier: 1.6 }
  default:     { weight_multiplier: 1.0 }
remediation_plain: |
  Write a one-page acceptable-use policy covering which LLMs are approved
  and what happens if the policy is violated.
```

Full schema reference: [`docs-2026/assessment-tool/02-design.md §5`](https://github.com/Qwentrix/micelium/blob/main/docs-2026/assessment-tool/02-design.md) in the main Micelium monorepo.

---

## Rule linter CLI

```bash
# Validate all YAML rule files in a content directory.
go run ./cmd/lint-rules -- --rules /path/to/rules --overlays /path/to/overlays

# Exit 0 = all valid. Exit 1 = at least one validation error (schema or semantic).
```

The linter is also used by `qwen-web`'s CI pipeline to validate content changes before publishing a new bundle to S3.

---

## Installation

```bash
go get github.com/Qwentrix/lumen-scoring@latest
```

Requires Go 1.22 or later.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributors must sign the Qwentrix CLA before their PR can be merged.

---

## Security

See [SECURITY.md](SECURITY.md) for our disclosure policy.

---

## Related repositories

| Repo | Description |
|---|---|
| [`Qwentrix/lumen`](https://github.com/Qwentrix/lumen) | Open-source Go scanner CLI (vendors this module) |
| `Qwentrix/lumen-api` *(private)* | Server-side scoring + PDF + lead funnel (vendors this module) |

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Copyright (c) 2026 Qwentrix Inc.
