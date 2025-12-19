# GateKeeper6

GateKeeper6 is a **static (non-executing) safety scanner** for Python-focused repositories intended for use in **MCEN/NIPR-like environments**.

It helps produce a repeatable, readable audit by scanning source code for patterns that increase MCEN operational risk, especially:
- **Non-loopback network communications** (exfiltration/C2/unauthorized connections)
- **Persistence / system modification** behaviors (scheduled tasks, autoruns, system path writes)
- **Dynamic code execution / loading** (`eval/exec`, dynamic imports)
- **Unsafe deserialization** (`pickle`/`marshal`)
- **Risky process execution** (`subprocess`, `shell=True`, suspicious tooling)

The default profile is **practical mode**: it **fails only on confirmed disallowed behavior** and otherwise produces a **CONDITIONAL_PASS** with items requiring human review.

## Getting started

- Scan a repo/dir: `python3 -m mcen_scan /path/to/repo`
- Scan current directory: `python3 -m mcen_scan .`
- Reports written to: `./mcen_audit/report.md` and `./mcen_audit/report.json`
- Manifest (per-file SHA-256): `./mcen_audit/manifest.json`

### Profiles

- Practical (default): `--profile mcen_practical`
  - Loopback (`localhost`, `127.0.0.1`, `::1`) is treated as allowed.
  - Unknown/dynamic network destinations are flagged for review (not auto-fail).
- Strict: `--profile mcen_strict`
  - Unknown/dynamic network destinations and non-allowlisted subprocess are treated more conservatively.

### Subprocess allowlist (optional)

Use this to document and suppress benign `subprocess` review findings (does not suppress network/persistence/dynamic-exec findings):

- Example file: `docs/allowlist.example.json`
- Run with allowlist: `python3 -m mcen_scan . --allowlist docs/allowlist.example.json`

## Network assurance (priority workflow)

GateKeeper6 supports two complementary ways to build strong evidence that a repo does not attempt non-loopback network access:

1) **Static network evidence (default)**: detects common network APIs and call sites (`NET*` findings) without executing code.
2) **Runtime egress harness (optional)**: runs a Python command under an egress-blocking harness that logs and blocks non-loopback connection attempts.

### Runtime egress harness (optional)

This is supplemental, scenario-based evidence: it reflects the specific command/config/inputs you executed.

- Example (run repo entrypoint under harness):
  - `python3 -m mcen_scan egress --output-dir ./mcen_audit . -- python3 your_entrypoint.py --arg value`
- Output files:
  - `mcen_audit/egress_log.jsonl` (events)
  - `mcen_audit/runtime_egress.json` (summary)

See `docs/RUNTIME_EGRESS_HARNESS.md` for details and limitations.

## What it scans

Default file types:
- Python: `*.py` (AST-based static analysis)
- PowerShell: `*.ps1`
- Batch: `*.bat`, `*.cmd`
- Shell: `*.sh`
- VBScript: `*.vbs`

It does **not** import or execute scanned code.

## Docs

- Specification and rulepack: `docs/MCEN_Python_Safety_Scanner_SPEC.md`
- Milestones/implementation notes: `docs/IMPLEMENTATION_PLAN.md`
- Runtime harness usage: `docs/RUNTIME_EGRESS_HARNESS.md`

## Development

- Tests: `python3 -m unittest -q`
