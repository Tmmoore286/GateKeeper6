from __future__ import annotations

import argparse
import json
from pathlib import Path

from .policy import load_allowlist, resolve_profile
from .scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(
    prog="mcen_scan",
    description="Static MCEN/NIPR safety scanner for Python-focused repositories.",
  )
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
  return parser


def main(argv: list[str] | None = None) -> int:
  parser = build_parser()
  args = parser.parse_args(argv)

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

  return result.summary.exit_code

