from __future__ import annotations

from .models import Finding


_SEVERITY_ORDER = {"blocker": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def sort_findings(findings: list[Finding]) -> list[Finding]:
  return sorted(
    findings,
    key=lambda f: (
      _SEVERITY_ORDER.get(f.severity, 99),
      f.category,
      f.file,
      f.line or 0,
      f.rule_id,
      f.title,
    ),
  )

