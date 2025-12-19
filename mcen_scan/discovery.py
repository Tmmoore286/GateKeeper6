from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DiscoveredFile:
  path: Path
  relpath: str
  kind: str


DEFAULT_EXCLUDE_DIRS = {
  ".git",
  "__pycache__",
  ".venv",
  "venv",
  "env",
  "dist",
  "build",
  "out",
  "coverage",
  "node_modules",
}


def classify_path(path: Path) -> str:
  suffix = path.suffix.lower()
  if suffix == ".py":
    return "python"
  if suffix == ".ps1":
    return "powershell"
  if suffix in {".bat", ".cmd"}:
    return "batch"
  if suffix == ".sh":
    return "shell"
  if suffix == ".vbs":
    return "vbscript"
  if suffix == ".whl":
    return "wheel"
  if suffix in {".zip", ".tar", ".gz", ".tgz", ".7z"}:
    return "archive"
  if suffix in {".exe", ".dll", ".so", ".dylib", ".pyd"}:
    return "binary"
  return "other"


def discover_files(root: Path) -> list[DiscoveredFile]:
  root = root.resolve()
  results: list[DiscoveredFile] = []

  if root.is_file():
    kind = classify_path(root)
    return [DiscoveredFile(path=root, relpath=root.name, kind=kind)]

  for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = sorted([d for d in dirnames if d not in DEFAULT_EXCLUDE_DIRS])
    filenames = sorted(filenames)
    base = Path(dirpath)
    for name in filenames:
      p = base / name
      if not p.is_file():
        continue
      rel = str(p.relative_to(root))
      kind = classify_path(p)
      results.append(DiscoveredFile(path=p, relpath=rel, kind=kind))

  results.sort(key=lambda d: d.relpath)
  return results


def safe_read_text(path: Path, max_bytes: int = 2_000_000) -> tuple[str | None, str | None]:
  try:
    st = path.stat()
  except OSError as e:
    return None, f"stat_failed: {e}"

  if st.st_size > max_bytes:
    return None, f"too_large: {st.st_size} bytes"

  try:
    data = path.read_bytes()
  except OSError as e:
    return None, f"read_failed: {e}"

  if b"\x00" in data[:4096]:
    return None, "binary_detected"

  for enc in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
    try:
      return data.decode(enc), None
    except UnicodeDecodeError:
      continue
  return None, "decode_failed"

