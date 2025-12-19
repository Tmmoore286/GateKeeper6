# Implementation Plan — MCEN Python Safety Scanner (v1)

Default profile: `mcen_practical` (see `docs/MCEN_Python_Safety_Scanner_SPEC.md`).

## Phase 0 — Repo scaffolding

Deliverables:
- Python package skeleton (stdlib-only).
- CLI entrypoint that accepts a target path and output dir.

Acceptance:
- `python -m mcen_scan <path>` runs and exits cleanly.

## Phase 1 — Discovery + inventory

Deliverables:
- Deterministic file walker with include/exclude globs.
- File typing (py/ps1/bat/cmd/sh/vbs/other).
- Safe file reader (size limits, encoding fallback).
- Inventory section in `report.json` (counts, skipped files).

Acceptance:
- Scanning a repo with mixed file types produces `report.json` with accurate counts and stable ordering.

## Phase 2 — Findings model + decision engine

Deliverables:
- Dataclass model for `Finding`, `RunMetadata`, `Summary`.
- Decision logic (PASS/CONDITIONAL_PASS/FAIL) and exit codes.

Acceptance:
- Injecting a synthetic `blocker` finding forces `FAIL` and exit code `1`.

## Phase 3 — Python AST analyzer (core MCEN rules)

Deliverables:
- Parse Python files to AST (no imports/execution).
- Rule evaluations for:
  - Network: `NET001/NET002/NET003`
  - Dynamic execution: `DEX001/DEX002`
  - Unsafe deserialization: `DES001`
  - Process execution: `PEX001/PEX002/PEX003`
  - Persistence/system-mod patterns where statically detectable (imports + obvious paths)

Acceptance:
- Fixture tests that demonstrate:
  - Loopback allowed (no `NET001`)
  - Non-loopback literals trigger `NET001`
  - `eval/exec` trigger `DEX001`
  - `pickle.load(s)` trigger `DES001`
  - `subprocess(..., shell=True)` triggers `PEX001`

## Phase 4 — Script analyzers (.ps1/.bat/.cmd/.sh/.vbs)

Deliverables:
- Line/pattern rule library to detect:
  - network tooling
  - persistence tooling
  - dynamic execution patterns (e.g., PowerShell `iex`)
- Map matches to the same rule IDs/categories/severities.

Acceptance:
- Fixture tests for each script type with at least one known-bad sample per category.

## Phase 5 — Allowlist (subprocess productivity control)

Deliverables:
- JSON allowlist parser and matcher.
- Allowlist applies only to `PEX003` in practical mode.
- Allowlist entries require a justification string.

Acceptance:
- A benign subprocess fixture is `CONDITIONAL_PASS` without allowlist and becomes `PASS` with a matching allowlist entry.

## Phase 6 — Reporting

Deliverables:
- `report.json` conforms to spec keys and includes all findings + inventory.
- `report.md` includes:
  - executive summary (decision + totals)
  - findings grouped by severity/category
  - per-finding remediation guidance

Acceptance:
- Reports are readable and diff-friendly (stable ordering, no timestamps inside the body other than in metadata).

## Phase 7 — Validation and “audit readiness”

Deliverables:
- Fixture-based test suite runnable offline.
- Version stamping in reports (tool version + git commit hash when available).

Acceptance:
- Re-running the scan on the same commit yields byte-identical findings ordering and stable summaries (aside from timestamps in metadata).

## Phase 8 (Optional) — CI integration

Deliverables:
- GitHub Action that runs the scanner on PRs and uploads artifacts.
- Optional SARIF output for code scanning annotations.

