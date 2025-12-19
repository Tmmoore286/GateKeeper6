from __future__ import annotations

import argparse
import json
from pathlib import Path

from .policy import load_allowlist, resolve_profile
from .scanner import scan_path


def _build_scan_parser(parser: argparse.ArgumentParser) -> None:
  parser.add_argument(
    "target",
    nargs="?",
    default=".",
    help="Target directory/repo root to scan (default: current directory).",
  )
  parser.add_argument(
    "--profile",
    default="mcen_practical",
    choices=["mcen_practical", "mcen_strict"],
    help="Scanning profile (default: mcen_practical).",
  )
  parser.add_argument(
    "--output-dir",
    default="mcen_audit",
    help="Directory to write reports into (default: ./mcen_audit).",
  )
  parser.add_argument(
    "--allowlist",
    default=None,
    help="Path to JSON allowlist file for approved subprocess commands (optional).",
  )
  parser.add_argument(
    "--json",
    default=None,
    help="Optional path to write JSON report (overrides output-dir/report.json).",
  )
  parser.add_argument(
    "--md",
    default=None,
    help="Optional path to write Markdown report (overrides output-dir/report.md).",
  )
  parser.add_argument(
    "--print-json",
    action="store_true",
    help="Print JSON report to stdout (in addition to writing files).",
  )
  parser.add_argument(
    "--no-manifest",
    action="store_true",
    help="Do not write a per-file SHA-256 manifest (default: writes manifest.json).",
  )


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="mcen_scan",
    description="Static MCEN/NIPR safety scanner for Python-focused repositories.",
  )

  subparsers = parser.add_subparsers(dest="command")

  scan_p = subparsers.add_parser("scan", help="Run static scan (default)")
  _build_scan_parser(scan_p)

  egress_p = subparsers.add_parser("egress", help="Run static scan + optional runtime egress harness")
  _build_scan_parser(egress_p)
  egress_p.add_argument(
    "egress_cmd",
    nargs="+",
    help="Python command to run under egress harness (use: -- python3 script.py ...).",
  )

  return parser


def main(argv: list[str] | None = None) -> int:
  parser = build_parser()

  raw_argv = argv if argv is not None else None
  # Backwards compatible: if no explicit subcommand, treat as scan.
  if raw_argv is None:
    import sys as _sys

    raw_argv = _sys.argv[1:]
  if raw_argv and raw_argv[0] not in {"scan", "egress"}:
    raw_argv = ["scan"] + raw_argv

  args = parser.parse_args(raw_argv)

  target = Path(args.target).resolve()
  output_dir = Path(args.output_dir).resolve()
  json_path = Path(args.json).resolve() if args.json else output_dir / "report.json"
  md_path = Path(args.md).resolve() if args.md else output_dir / "report.md"

  profile = resolve_profile(args.profile)
  allowlist = load_allowlist(Path(args.allowlist).resolve()) if args.allowlist else None

  result = scan_path(
    target=target,
    profile=profile,
    allowlist=allowlist,
  )

  output_dir.mkdir(parents=True, exist_ok=True)
  json_path.write_text(json.dumps(result.to_json(), indent=2, sort_keys=False) + "\n", encoding="utf-8")
  md_path.write_text(result.to_markdown(), encoding="utf-8")

  if not args.no_manifest:
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(result.to_manifest_json(), indent=2, sort_keys=False) + "\n", encoding="utf-8")

  runtime = None
  if args.command == "egress":
    if not args.egress_cmd:
      raise SystemExit("Missing egress command. Use: mcen_scan egress <target> -- python3 script.py ...")
    # If scan flags appear in the egress command, the user likely placed scan options after the target.
    scan_flags = {"--profile", "--output-dir", "--allowlist", "--json", "--md", "--print-json", "--no-manifest"}
    if any(tok in scan_flags for tok in args.egress_cmd):
      raise SystemExit(
        "Egress command contains mcen_scan flags. Put mcen_scan options before the target, e.g.:\n"
        "  python3 -m mcen_scan egress --output-dir ./mcen_audit . -- python3 your_entrypoint.py"
      )
    egress_cmd = args.egress_cmd
    from .egress_runner import run_python_egress_harness

    egress_out = output_dir / "egress_log.jsonl"
    runtime = run_python_egress_harness(target=target, cmd=egress_cmd, log_path=egress_out)
    runtime_path = output_dir / "runtime_egress.json"
    runtime_path.write_text(json.dumps(runtime, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    md_path.write_text(result.to_markdown(runtime_egress=runtime), encoding="utf-8")

  if args.print_json:
    print(json.dumps(result.to_json(), indent=2, sort_keys=False))

  print(f"Decision: {result.summary.decision} (exit {result.summary.exit_code})")
  print(f"Findings: blocker={result.summary.totals_by_severity.get('blocker', 0)}, "
        f"high={result.summary.totals_by_severity.get('high', 0)}, "
        f"medium={result.summary.totals_by_severity.get('medium', 0)}, "
        f"low={result.summary.totals_by_severity.get('low', 0)}, "
        f"info={result.summary.totals_by_severity.get('info', 0)}")
  print(f"Wrote: {json_path}")
  print(f"Wrote: {md_path}")
  if not args.no_manifest:
    print(f"Wrote: {output_dir / 'manifest.json'}")
  if args.command == "egress":
    print(f"Wrote: {output_dir / 'egress_log.jsonl'}")
    print(f"Wrote: {output_dir / 'runtime_egress.json'}")

  return result.summary.exit_code
