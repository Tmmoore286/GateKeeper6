from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

Severity = Literal["blocker", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]
Decision = Literal["PASS", "CONDITIONAL_PASS", "FAIL"]


@dataclass(frozen=True)
class Finding:
  rule_id: str
  title: str
  category: str
  severity: Severity
  confidence: Confidence
  file: str
  line: int | None
  evidence: str
  why_it_matters: str
  remediation: str

  def to_json(self) -> dict[str, Any]:
    return asdict(self)


@dataclass(frozen=True)
class RunMetadata:
  started_at: str
  finished_at: str
  duration_ms: int
  hostname: str
  os: str
  python_version: str
  cwd: str

  def to_json(self) -> dict[str, Any]:
    return asdict(self)


@dataclass(frozen=True)
class GitMetadata:
  is_repo: bool
  head_commit: str | None
  dirty: bool | None

  def to_json(self) -> dict[str, Any]:
    return asdict(self)


@dataclass(frozen=True)
class Summary:
  decision: Decision
  exit_code: int
  totals_by_severity: dict[str, int]
  totals_by_category: dict[str, int]

  def to_json(self) -> dict[str, Any]:
    return asdict(self)


@dataclass(frozen=True)
class Inventory:
  file_counts_by_type: dict[str, int]
  skipped_files: list[dict[str, Any]]
  third_party_artifacts: list[dict[str, Any]]

  def to_json(self) -> dict[str, Any]:
    return asdict(self)


@dataclass(frozen=True)
class ScanResult:
  tool: dict[str, Any]
  run: RunMetadata
  target: dict[str, Any]
  summary: Summary
  findings: list[Finding]
  inventory: Inventory

  def to_json(self) -> dict[str, Any]:
    return {
      "tool": self.tool,
      "run": self.run.to_json(),
      "target": self.target,
      "summary": self.summary.to_json(),
      "findings": [f.to_json() for f in self.findings],
      "inventory": self.inventory.to_json(),
    }

  def to_markdown(self) -> str:
    decision_meaning = {
      "PASS": "No disallowed behaviors were detected by this static scan.",
      "CONDITIONAL_PASS": "No confirmed disallowed behaviors were detected, but items require human review.",
      "FAIL": "Disallowed behavior(s) were detected by this static scan.",
    }.get(self.summary.decision, "")

    totals = self.summary.totals_by_severity
    findings_non_info = [f for f in self.findings if f.severity != "info"]
    top_issues = (findings_non_info or self.findings)[:3]
    scan_parse_errors = [f for f in self.findings if f.rule_id == "SCAN001"]
    skipped_count = len(self.inventory.skipped_files)

    lines: list[str] = []
    lines.append("# MCEN Python Safety Scanner Report")
    lines.append("")
    lines.append("## BLUF (Leadership)")
    lines.append("")
    lines.append(f"- Decision: `{self.summary.decision}` — {decision_meaning}")
    lines.append(
      "- Findings (count): "
      f"blocker={totals.get('blocker', 0)}, high={totals.get('high', 0)}, medium={totals.get('medium', 0)}"
    )

    if scan_parse_errors or skipped_count:
      lines.append(
        "- Audit completeness: "
        f"parse_errors={len(scan_parse_errors)}, skipped_files={skipped_count} (fix and re-run for a complete audit)"
      )
    else:
      lines.append("- Audit completeness: no parse errors; no skipped files")

    lines.append("")
    lines.append("### Top issues")
    lines.append("")
    if not top_issues:
      lines.append("None.")
    else:
      for f in top_issues:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        lines.append(f"- `{f.severity.upper()} {f.rule_id}` {f.title} (`{loc}`)")
    lines.append("")

    lines.append("## Technical Assessment (ISSO/ISSM/SWE)")
    lines.append("")
    lines.append("### Scope and context")
    lines.append("")
    lines.append(f"- Profile: `{self.tool.get('profile')}` (default is practical mode)")
    lines.append(f"- Target: `{self.target.get('root_path')}`")
    git = self.target.get("git") or {}
    if git.get("is_repo"):
      lines.append(f"- Git commit: `{git.get('head_commit') or 'unknown'}` (dirty={git.get('dirty')})")
    lines.append(f"- Scan window (UTC): `{self.run.started_at}` → `{self.run.finished_at}`")
    lines.append("")

    lines.append("### What this scanner checks (and why it reduces MCEN risk)")
    lines.append("")
    lines.append(
      "- Network (`NET*`): detects non-loopback communications and exposed listeners that can create exfiltration/C2 risk "
      "or violate enclave connection controls; loopback-only is treated as allowed."
    )
    lines.append(
      "- Persistence/system modification (`PER*`): detects common mechanisms that change endpoint state "
      "(scheduled tasks/cron/services/registry autoruns/system paths)."
    )
    lines.append(
      "- Dynamic execution/loaders (`DEX*`): flags `eval/exec/compile` and dynamic loaders/import patterns that execute "
      "unreviewed code paths and undermine auditability."
    )
    lines.append(
      "- Unsafe deserialization (`DES*`): flags `pickle`/`marshal` loading patterns that can execute code via data files."
    )
    lines.append(
      "- Process execution (`PEX*`): flags `shell=True` and suspicious tooling; otherwise requires review because it can "
      "hide network/persistence behaviors outside the Python code path."
    )
    lines.append(
      "- Scan completeness (`SCAN*` and skipped files): indicates files the tool could not fully analyze; unresolved items "
      "should be fixed and re-scanned before treating the audit as complete."
    )
    lines.append("")

    lines.append("### How to interpret the decision")
    lines.append("")
    lines.append("- `PASS`: no blocker findings and no high findings.")
    lines.append("- `CONDITIONAL_PASS`: no blocker findings, but one or more high findings require review.")
    lines.append("- `FAIL`: one or more blocker findings were detected.")
    lines.append("")

    lines.append("### Limitations (important for audits)")
    lines.append("")
    lines.append("- Static-only: does not execute code; runtime behavior can differ based on inputs/config/environment.")
    lines.append("- Best-effort inference: some commands/hosts are constructed dynamically and may require manual review.")
    lines.append("- Parse errors/skipped files reduce coverage; fix and re-run to complete the audit.")
    lines.append("")

    lines.append("### Totals")
    lines.append("")
    for sev in ["blocker", "high", "medium", "low", "info"]:
      lines.append(f"- `{sev}`: {self.summary.totals_by_severity.get(sev, 0)}")
    lines.append("")

    lines.append("### Findings (full details)")
    lines.append("")
    if not self.findings:
      lines.append("No findings.")
      lines.append("")
    else:
      for f in self.findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        lines.append(f"#### {f.severity.upper()} {f.rule_id} — {f.title}")
        lines.append("")
        lines.append(f"- Location: `{loc}`")
        lines.append(f"- Category: `{f.category}`")
        lines.append(f"- Confidence: `{f.confidence}`")
        lines.append(f"- Evidence: `{f.evidence}`")
        lines.append(f"- Why: {f.why_it_matters}")
        lines.append(f"- Remediation: {f.remediation}")
        lines.append("")

    lines.append("### Inventory")
    lines.append("")
    lines.append("#### File counts")
    for k in sorted(self.inventory.file_counts_by_type.keys()):
      lines.append(f"- `{k}`: {self.inventory.file_counts_by_type[k]}")
    lines.append("")

    if self.inventory.third_party_artifacts:
      lines.append("#### Artifacts (non-blocking)")
      for a in self.inventory.third_party_artifacts:
        lines.append(f"- `{a.get('path')}` ({a.get('kind')})")
      lines.append("")

    if self.inventory.skipped_files:
      lines.append("#### Skipped files")
      for s in self.inventory.skipped_files:
        lines.append(f"- `{s.get('path')}`: {s.get('reason')}")
      lines.append("")

    return "\n".join(lines)
