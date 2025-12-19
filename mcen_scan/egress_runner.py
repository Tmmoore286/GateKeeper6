from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def run_python_egress_harness(*, target: Path, cmd: list[str], log_path: Path) -> dict:
  """
  Runs a Python command with an import-time egress block (via sitecustomize).

  This is supplemental evidence only: it reflects the specific command/config/inputs used.
  """
  started_at = datetime.now(timezone.utc).isoformat()
  harness_dir = Path(__file__).resolve().parent / "harness"
  if not (harness_dir / "sitecustomize.py").exists():
    raise RuntimeError("Harness sitecustomize.py missing")

  env = os.environ.copy()
  env["MCEN_EGRESS_LOG"] = str(log_path)
  env["MCEN_EGRESS_ALLOW_LOOPBACK"] = "1"
  env["MCEN_EGRESS_BLOCK_NON_LOOPBACK"] = "1"
  env["PYTHONUNBUFFERED"] = "1"
  env["PYTHONPATH"] = str(harness_dir) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")

  # This harness only applies to Python processes.
  # If user passes a script directly, run it with current interpreter.
  resolved_cmd = cmd
  if cmd and cmd[0].endswith(".py"):
    resolved_cmd = [sys.executable] + cmd

  proc = subprocess.run(
    resolved_cmd,
    cwd=str(target),
    env=env,
    capture_output=True,
    text=True,
  )

  finished_at = datetime.now(timezone.utc).isoformat()

  events = []
  if log_path.exists():
    with log_path.open("r", encoding="utf-8") as f:
      for line in f:
        line = line.strip()
        if not line:
          continue
        try:
          events.append(json.loads(line))
        except json.JSONDecodeError:
          continue

  blocked = [e for e in events if e.get("action") == "blocked"]
  allowed = [e for e in events if e.get("action") == "allowed_loopback"]

  return {
    "ran": True,
    "started_at": started_at,
    "finished_at": finished_at,
    "cwd": str(target),
    "command": resolved_cmd,
    "exit_code": proc.returncode,
    "blocked_attempts": len(blocked),
    "allowed_loopback_attempts": len(allowed),
    "events": events[:200],
    "stderr_tail": proc.stderr[-4000:] if proc.stderr else "",
    "stdout_tail": proc.stdout[-4000:] if proc.stdout else "",
    "note": "Runtime egress evidence is scenario-based; it reflects this command/config/inputs only.",
  }

