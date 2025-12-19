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
    lines: list[str] = []
    lines.append("# MCEN Python Safety Scanner Report")
    lines.append("")
    lines.append(f"- Decision: `{self.summary.decision}`")
    lines.append(f"- Profile: `{self.tool.get('profile')}`")
    lines.append(f"- Target: `{self.target.get('root_path')}`")
    git = self.target.get("git") or {}
    if git.get("is_repo"):
      lines.append(f"- Git commit: `{git.get('head_commit') or 'unknown'}`")
      lines.append(f"- Git dirty: `{git.get('dirty')}`")
    lines.append("")

    lines.append("## Totals")
    lines.append("")
    for sev in ["blocker", "high", "medium", "low", "info"]:
      lines.append(f"- `{sev}`: {self.summary.totals_by_severity.get(sev, 0)}")
    lines.append("")

    lines.append("## Findings")
    lines.append("")
    if not self.findings:
      lines.append("No findings.")
      lines.append("")
    else:
      for f in self.findings:
        loc = f"{f.file}:{f.line}" if f.line else f.file
        lines.append(f"### {f.severity.upper()} {f.rule_id} — {f.title}")
        lines.append("")
        lines.append(f"- Location: `{loc}`")
        lines.append(f"- Category: `{f.category}`")
        lines.append(f"- Confidence: `{f.confidence}`")
        lines.append(f"- Evidence: `{f.evidence}`")
        lines.append(f"- Why: {f.why_it_matters}")
        lines.append(f"- Remediation: {f.remediation}")
        lines.append("")

    lines.append("## Inventory")
    lines.append("")
    lines.append("### File counts")
    for k in sorted(self.inventory.file_counts_by_type.keys()):
      lines.append(f"- `{k}`: {self.inventory.file_counts_by_type[k]}")
    lines.append("")

    if self.inventory.third_party_artifacts:
      lines.append("### Artifacts (non-blocking)")
      for a in self.inventory.third_party_artifacts:
        lines.append(f"- `{a.get('path')}` ({a.get('kind')})")
      lines.append("")

    if self.inventory.skipped_files:
      lines.append("### Skipped files")
      for s in self.inventory.skipped_files:
        lines.append(f"- `{s.get('path')}`: {s.get('reason')}")
      lines.append("")

    return "\n".join(lines)

