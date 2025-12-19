# Runtime Egress Harness (Optional)

GateKeeper6’s default mode is **static-only** (it does not execute scanned code). For higher-confidence “doesn’t try to connect” evidence, GateKeeper6 also provides an **optional runtime egress harness** for Python commands.

This harness blocks and logs **non-loopback** network attempts during a specific execution.

## What it does

- Intercepts low-level socket operations (`connect`, `connect_ex`, `sendto`, `bind`) at Python startup using `sitecustomize`.
- Allows loopback destinations only: `localhost`, `127.0.0.1`, `::1`.
- Blocks and logs any attempt to connect/send to a non-loopback destination.
- Blocks and logs attempts to bind/listen on all interfaces (`0.0.0.0`, `::`).

## What it does not do

- It does not “prove” the application can never attempt network access in all scenarios.
- It only provides evidence for the specific command, configuration, and inputs that you ran.
- It does not intercept non-Python binaries (the harness is Python-only).

## How to use

Run a normal scan plus a runtime run under the harness:

- `python3 -m mcen_scan egress --output-dir ./mcen_audit /path/to/repo -- python3 your_entrypoint.py --arg value`

Outputs in `mcen_audit/`:
- `report.md` / `report.json` (static scan)
- `manifest.json` (per-file SHA-256 for scanned files)
- `egress_log.jsonl` (raw events)
- `runtime_egress.json` (summary for audit packets)

## Interpreting results

- If `runtime_egress.json` reports `blocked_attempts > 0`, the command attempted non-loopback network access (or bind-all-interfaces) and the harness blocked it.
- If `blocked_attempts == 0`, the tested execution path made no non-loopback network attempt.

Pair this with static scan results:
- `NET001/NET003` findings: confirmed non-loopback network behaviors in source (static evidence).
- `NET002` findings: potential network capability with unknown/dynamic destination (review required).
