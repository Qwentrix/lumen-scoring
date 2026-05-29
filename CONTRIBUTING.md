# Contributing to lumen-scoring

Thank you for your interest in contributing to `lumen-scoring`, the shared Go scoring module for [Micelium Lumen](https://lumen.micelium.com).

---

## Contributor License Agreement (CLA)

All contributors must sign the Qwentrix Individual CLA (or Corporate CLA for contributions made on behalf of an employer) **before** their pull request can be merged.

The CLA is managed via **cla-assistant**: when you open a PR, the CLA bot will comment with a link to the agreement. Sign it once; it covers all future contributions across Qwentrix repositories.

If your employer needs to sign the Corporate CLA, contact legal@qwentrix.com.

---

## Getting Started

1. Fork the repository.
2. Clone your fork: `git clone https://github.com/<your-username>/lumen-scoring.git`
3. Create a feature branch: `git checkout -b feat/your-feature`
4. Make your changes (see code-style and testing guidelines below).
5. Push to your fork and open a pull request against `main`.

---

## Code Style

**Formatter:** `gofmt`. All committed Go code must be formatted with `gofmt -s`. A pre-commit hook or your editor's Go plugin is the recommended way to enforce this automatically.

**Linter:** [`golangci-lint`](https://golangci-lint.run/) with the project's `.golangci.yml` configuration. Run locally before pushing:

```bash
golangci-lint run ./...
```

The CI pipeline enforces lint as a required status check (`ci/go-test`). PRs with lint failures will not be merged.

**Style notes:**

- Follow standard Go conventions: exported names, doc comments on all exported symbols, errors as values, no `panic` in library code.
- Keep `pkg/` packages free of side effects at `init()` time. The module must be safe to import in a single static binary.
- Prefer explicit error wrapping (`fmt.Errorf("context: %w", err)`) over opaque errors.
- Avoid adding new external dependencies without discussion in an issue first. The dependency surface of a security-tool library is under active scrutiny.

---

## Testing

Run the full test suite:

```bash
go test ./...
```

Run tests with the race detector (required before submitting):

```bash
go test -race ./...
```

**Test expectations:**

- Every exported function in `pkg/` must have at least one test.
- Scoring logic changes must include a table-driven test that covers the A/B/C/D/F grade boundaries and the edge cases (empty findings, all-critical findings, industry multiplier overflow).
- Rule-loader changes must include a test with a malformed YAML fixture to verify error surfacing.
- CI runs `go test ./...` on both Go 1.22 and 1.23 matrix.

---

## Submitting a Pull Request

- Link the relevant GitHub issue (or create one if none exists).
- Keep PRs focused: one logical change per PR.
- Write a clear description of what the change does and why.
- All status checks must pass before a reviewer will look at the PR.
- At least one approval from `@qwentrix/lumen-pod` is required to merge.

---

## Reporting Issues

For bugs, open a GitHub issue with a minimal reproduction case. For security vulnerabilities, see [SECURITY.md](SECURITY.md) — do NOT use a public issue.

---

## Code of Conduct

We expect all contributors to behave professionally and respectfully. Harassment, abuse, or discriminatory language will result in an immediate ban from the project. If you experience or witness unacceptable behavior, email conduct@qwentrix.com.
