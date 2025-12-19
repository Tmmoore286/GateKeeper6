# MCEN Python Safety Scanner (Static) — Specification (v1)

This document defines a **static-only** scanning tool intended to help assess whether a Python-focused repository is safe to operate on **MCEN/NIPR-like environments**, with emphasis on preventing:
- **Non-loopback network communications**
- **Persistence / system modification behaviors**
- **Dynamic code execution and unsafe deserialization**

This is **not** an official STIG/ATO artifact. It is an engineering control to support local risk decisions and to produce a repeatable, human-readable audit record.

## 1) Goals

1. Scan a directory/repo and produce an **audit report** that is easy for a reviewer (SWE/ISSO/lead) to read.
2. Provide an **objective, repeatable** set of checks that can be run locally or in CI.
3. Avoid “blocking work” via excessive false positives by using a **Practical** profile by default:
   - **Fail only when the tool can prove a disallowed behavior**
   - Otherwise produce **Conditional Pass** findings that require human review

## 2) Non-goals

- Not a malware sandbox and does **not** attempt dynamic execution, emulation, or behavior detonation.
- Not a full SAST replacement; it focuses on **MCEN-relevant operational hazards**.
- Not a dependency/license compliance tool. Presence of vendored deps or `.whl` files is **not a finding** in v1.

## 3) Safety constraints (tool behavior)

The scanner must:
- **Never import or execute** scanned code.
- Require **no network access** to run (local-only operation).
- Use **Python standard library only** (no installation required on constrained endpoints).

## 4) Supported inputs / file types

Default scan targets:
- Python: `**/*.py`
- PowerShell: `**/*.ps1`
- Windows batch: `**/*.bat`, `**/*.cmd`
- Shell: `**/*.sh`
- VBScript: `**/*.vbs`

Default excludes:
- `.git/`, `__pycache__/`, `.venv/`, `venv/`, `env/`, `dist/`, `build/`, `out/`, `coverage/`, `node_modules/`

Files that are too large or clearly binary should be skipped safely with a recorded note in the report.

## 5) Output artifacts

The scan writes to an output directory (default: `./mcen_audit/`):
- `report.md` — human readable, suitable for attachment to a review packet
- `report.json` — machine-readable record for diffing/CI/storage

### 5.1 `report.json` schema (v1)

Top-level keys:
- `tool`: `{ name, version, profile }`
- `run`: `{ started_at, finished_at, duration_ms, hostname, os, python_version, cwd }`
- `target`: `{ root_path, git: { is_repo, head_commit, dirty } }`
- `summary`: `{ decision, totals_by_severity, totals_by_category }`
- `findings`: array of findings (see below)
- `inventory`: `{ file_counts_by_type, skipped_files, third_party_artifacts }`

Finding object:
- `rule_id`: stable string (e.g., `NET001`)
- `title`: short human label
- `category`: one of `network`, `persistence`, `dynamic_exec`, `deserialization`, `process_exec`, `obfuscation`, `secrets`, `other`
- `severity`: `blocker | high | medium | low | info`
- `confidence`: `high | medium | low`
- `file`: path relative to repo root
- `line`: 1-based line number when available
- `evidence`: short excerpt or structured evidence (never full-file dumps)
- `why_it_matters`: short MCEN-oriented rationale
- `remediation`: concrete next step

## 6) Decision model

The tool reports one overall decision:
- `PASS`: no `blocker` findings
- `CONDITIONAL_PASS`: no `blocker` findings, but one or more `high` findings
- `FAIL`: one or more `blocker` findings

Exit codes:
- `0`: PASS
- `2`: CONDITIONAL_PASS
- `1`: FAIL
- `3`: tool error (scan could not complete)

## 7) Profiles

### 7.1 Default: `mcen_practical`

Principle: **Fail only on proven disallowed behavior**; otherwise escalate to review.

Key policy choices:
- Loopback traffic is allowed (`localhost`, `127.0.0.1`, `::1`).
- Network-capable code with **unknown destinations** (variables/env/config) is **High + review**, not auto-fail.
- Subprocess usage is **context-based**:
  - `shell=True` or obvious network/persistence tooling is **Blocker**
  - other subprocess is **High + review** unless allowlisted
- Offline dependencies / `.whl` files are **not findings**.

### 7.2 Optional: `mcen_strict`

Principle: **Conservative**, reduce ambiguity.

Differences from practical:
- Unknown/variable network destinations are **Blocker**.
- Subprocess not allowlisted becomes **Blocker**.

## 8) Rulepack (v1)

Rule IDs are stable and must not be repurposed.

### 8.1 Network rules (category `network`)

**NET001 (Blocker, High confidence)**: Proven non-loopback network calls.

Triggers (examples; not exhaustive):
- Python call sites that clearly initiate outbound connections to a **non-loopback literal**:
  - `urllib.request.urlopen("https://example.com")`
  - `requests.get("https://example.com")`
  - `socket.connect(("10.0.0.5", 443))`
- Script tooling invoking non-loopback network utilities:
  - `curl https://…`, `wget http://…`, `ssh user@host`, `scp …`
  - PowerShell: `Invoke-WebRequest`, `Start-BitsTransfer`, `Net.WebClient`, etc.

Loopback exceptions (allowed):
- Destinations limited to `localhost`, `127.0.0.1`, `::1`

**NET002 (High, Medium confidence)**: Network-capable modules/APIs present with unknown destination.

Triggers:
- Imports or call patterns consistent with networking where host/port are derived from variables/env/config and are not provably loopback.

**NET003 (Blocker, High confidence)**: Binding/listening on all interfaces.

Triggers:
- Python servers binding to `0.0.0.0` or `::` (common in dev servers)
- PowerShell/batch/shell commands that start listeners on non-loopback interfaces

### 8.2 Persistence / system modification rules (category `persistence`)

**PER001 (Blocker, High confidence)**: Scheduled task / cron / service creation or modification.

Examples:
- Windows: `schtasks`, service creation, task XML drops
- Linux/macOS: `cron`, `systemd`, `launchd` patterns

**PER002 (Blocker, High confidence)**: Registry autoruns / startup persistence.

Examples:
- `HKLM\\...\\Run`, `HKCU\\...\\Run`, Startup folder modifications

**PER003 (High, Medium confidence)**: Writes to protected system locations.

Examples:
- `C:\\Windows\\...`, `C:\\Program Files\\...`, `/etc/...`, `/Library/LaunchDaemons/...`

### 8.3 Dynamic execution / loaders (category `dynamic_exec`)

**DEX001 (Blocker, High confidence)**: `eval`, `exec`, `compile`.

**DEX002 (Blocker, High confidence)**: Dynamic import/loader patterns likely to execute unreviewed code.

Examples:
- `__import__(variable)`
- `importlib.import_module(variable)`
- `runpy.run_path(...)`

**DEX003 (High, Medium confidence)**: `ctypes`/FFI or loading native libraries.

### 8.4 Unsafe deserialization (category `deserialization`)

**DES001 (Blocker, High confidence)**: `pickle.loads/loads`, `pickle.load`, `marshal.loads`, similar.

### 8.5 Process execution (category `process_exec`)

**PEX001 (Blocker, High confidence)**: Subprocess with shell invocation or shell metacharacters.

Triggers:
- `subprocess.*(..., shell=True)`
- obvious command strings containing shell chaining metacharacters where applicable

**PEX002 (Blocker, High confidence)**: Subprocess invokes known network/persistence tooling.

**PEX003 (High, Medium confidence)**: Other subprocess usage (review required unless allowlisted).

### 8.6 Obfuscation indicators (category `obfuscation`)

**OBF001 (High, Low/Medium confidence)**: Decode/decompress chains feeding into execution.

Examples:
- `base64.b64decode(...)` → `zlib.decompress(...)` → `exec(...)`
- very large base64 blobs embedded in source

## 9) Allowlist / waivers (for productivity + auditability)

Practical mode supports an **allowlist file** specifically for `PEX003` (benign subprocess usage).

Format: JSON (stdlib-only).

Requirements:
- Each allowlist entry must include:
  - match scope (`path_glob`, optional)
  - command match (`exact` or `regex`)
  - `justification` (free text, required)
  - `approved_by` and `approved_on` (optional but recommended)

Allowlist entries must never suppress:
- Proven non-loopback network (`NET001`)
- Bind-all-interfaces (`NET003`)
- Dynamic exec (`DEX001/DEX002`)
- Unsafe deserialization (`DES001`)
- Persistence (`PER001/PER002`)

## 10) Architecture (v1)

### 10.1 High-level flow

1. **CLI** parses args/profile/paths.
2. **Discovery** walks the target tree, applies include/exclude filters.
3. **Analyzers** run per file type:
   - Python analyzer: AST parse + targeted rule evaluation
   - Script analyzer: line-based pattern rules
4. **Findings aggregator** normalizes evidence, assigns severity/confidence.
5. **Decision engine** derives PASS/CONDITIONAL/FAIL.
6. **Reporters** emit `report.json` and `report.md`.

### 10.2 Module layout (proposed)

- `mcen_scan/cli.py` — argument parsing, orchestration
- `mcen_scan/discovery.py` — file walking, filters, file typing
- `mcen_scan/analyzers/python_ast.py` — AST parsing and helpers
- `mcen_scan/analyzers/scripts.py` — `.ps1/.bat/.cmd/.sh/.vbs` scanning
- `mcen_scan/rules/` — rule definitions and evaluators (pure functions)
- `mcen_scan/policy.py` — profile selection, allowlist parsing
- `mcen_scan/reporting/json_report.py` — JSON output
- `mcen_scan/reporting/md_report.py` — Markdown output
- `mcen_scan/models.py` — dataclasses for findings/run metadata

### 10.3 Design constraints

- Deterministic output ordering for diff-friendly audits.
- Robust handling of parse errors: record and continue scanning other files.
- Defensive file reading (encoding fallbacks, size limits).

## 11) Implementation milestones (v1)

1. CLI + discovery + output dir creation.
2. Findings model + JSON report skeleton + decision logic.
3. Python AST analyzer for: imports, network calls, `eval/exec/compile`, pickle/marshal, subprocess patterns, bind/listen patterns.
4. Script analyzers with pattern libraries for `.ps1/.bat/.cmd/.sh/.vbs`.
5. Allowlist support for subprocess review findings.
6. Markdown reporter and “executive summary” formatting.
7. Fixture-based validation (known-good / known-bad samples) and regression tests.

