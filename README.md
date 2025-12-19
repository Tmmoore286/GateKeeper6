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

## Development

- Tests: `python3 -m unittest -q`
