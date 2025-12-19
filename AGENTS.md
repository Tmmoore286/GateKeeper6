# Agent Guidelines (GateKeeper6)

This repo will contain a static scanning tool to assess whether Python-focused repos are safe to operate in MCEN/NIPR-like environments.

## Ground rules

- Do not execute or import scanned code; scanning is **static-only**.
- Implement the scanner using **Python standard library only**.
- Treat **non-loopback network behavior** as disallowed by default; loopback (`localhost`, `127.0.0.1`, `::1`) is allowed.
- Do not flag `.whl` files or offline-packaged dependencies as findings (inventory is allowed if it’s non-blocking).
- Produce two outputs per scan: `report.md` (human) and `report.json` (machine).

## Engineering conventions

- Prefer small, testable modules (`discovery`, `analyzers`, `rules`, `reporting`).
- Keep rule IDs stable and documented in `docs/MCEN_Python_Safety_Scanner_SPEC.md`.
- Add a minimal fixture-based test set for rules to control false positives.

