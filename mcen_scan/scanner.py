from __future__ import annotations

import platform
import socket as py_socket
import subprocess
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .discovery import DiscoveredFile, discover_files, safe_read_text
from .models import (
  Inventory,
  RunMetadata,
  ScanResult,
  Summary,
)
from .policy import Allowlist, Profile
from .reporting import sort_findings
from .rules import rule_info
from .analyzers.python_ast import analyze_python
from .analyzers.scripts import analyze_script


def _utc_now_iso() -> str:
  return datetime.now(timezone.utc).isoformat()


def _git_metadata(root: Path) -> dict:
  git_dir = root / ".git"
  if not git_dir.exists():
    return {"is_repo": False, "head_commit": None, "dirty": None}

  head_commit: str | None = None
  dirty: bool | None = None
  try:
    head_commit = (
      subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=str(root))
      .decode("utf-8", "ignore")
      .strip()
    )
  except Exception:
    head_commit = None

  try:
    out = subprocess.check_output(["git", "status", "--porcelain"], cwd=str(root)).decode("utf-8", "ignore")
    dirty = bool(out.strip())
  except Exception:
    dirty = None

  return {"is_repo": True, "head_commit": head_commit, "dirty": dirty}


def scan_path(*, target: Path, profile: Profile, allowlist: Allowlist | None) -> ScanResult:
  start = time.time()
  started_at = _utc_now_iso()

  discovered = discover_files(target)

  skipped_files: list[dict] = []
  findings = []
  third_party_artifacts: list[dict] = []
  file_counts = Counter([d.kind for d in discovered])

  for d in discovered:
    if d.kind in {"wheel", "archive", "binary"}:
      third_party_artifacts.append({"path": d.relpath, "kind": d.kind})
      continue

    if d.kind not in {"python", "powershell", "batch", "shell", "vbscript"}:
      continue

    text, err = safe_read_text(d.path)
    if err is not None:
      skipped_files.append({"path": d.relpath, "reason": err})
      continue

    if d.kind == "python":
      findings.extend(analyze_python(relpath=d.relpath, source=text or "", profile=profile, allowlist=allowlist))
    else:
      findings.extend(analyze_script(relpath=d.relpath, kind=d.kind, source=text or "", profile=profile))

  findings = sort_findings(findings)

  totals_by_severity: dict[str, int] = defaultdict(int)
  totals_by_category: dict[str, int] = defaultdict(int)
  for f in findings:
    totals_by_severity[f.severity] += 1
    totals_by_category[f.category] += 1

  if totals_by_severity.get("blocker", 0) > 0:
    decision = "FAIL"
    exit_code = 1
  elif totals_by_severity.get("high", 0) > 0:
    decision = "CONDITIONAL_PASS"
    exit_code = 2
  else:
    decision = "PASS"
    exit_code = 0

  finished_at = _utc_now_iso()
  duration_ms = int((time.time() - start) * 1000)

  root_path = str(target.resolve())
  target_obj = {"root_path": root_path, "git": _git_metadata(target.resolve())}

  run = RunMetadata(
    started_at=started_at,
    finished_at=finished_at,
    duration_ms=duration_ms,
    hostname=py_socket.gethostname(),
    os=f"{platform.system()} {platform.release()}",
    python_version=platform.python_version(),
    cwd=str(Path.cwd()),
  )

  summary = Summary(
    decision=decision,  # type: ignore[arg-type]
    exit_code=exit_code,
    totals_by_severity=dict(totals_by_severity),
    totals_by_category=dict(totals_by_category),
  )

  inventory = Inventory(
    file_counts_by_type=dict(file_counts),
    skipped_files=sorted(skipped_files, key=lambda x: x.get("path", "")),
    third_party_artifacts=sorted(third_party_artifacts, key=lambda x: x.get("path", "")),
  )

  tool = {"name": "mcen_scan", "version": __version__, "profile": profile.name}

  return ScanResult(
    tool=tool,
    run=run,
    target=target_obj,
    summary=summary,
    findings=findings,
    inventory=inventory,
  )
