from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Pattern
import re


@dataclass(frozen=True)
class Profile:
  name: str
  unknown_network_destination_is_blocker: bool
  subprocess_requires_allowlist: bool


MCEN_PRACTICAL = Profile(
  name="mcen_practical",
  unknown_network_destination_is_blocker=False,
  subprocess_requires_allowlist=False,
)

MCEN_STRICT = Profile(
  name="mcen_strict",
  unknown_network_destination_is_blocker=True,
  subprocess_requires_allowlist=True,
)


def resolve_profile(name: str) -> Profile:
  if name == "mcen_practical":
    return MCEN_PRACTICAL
  if name == "mcen_strict":
    return MCEN_STRICT
  raise ValueError(f"Unknown profile: {name}")


@dataclass(frozen=True)
class AllowlistEntry:
  path_glob: str | None
  command_exact: str | None
  command_regex: Pattern[str] | None
  justification: str
  approved_by: str | None
  approved_on: str | None

  def matches(self, relpath: str, command: str) -> bool:
    if self.path_glob is not None:
      if not Path(relpath).match(self.path_glob):
        return False
    if self.command_exact is not None:
      return command == self.command_exact
    if self.command_regex is not None:
      return bool(self.command_regex.search(command))
    return False


@dataclass(frozen=True)
class Allowlist:
  entries: list[AllowlistEntry]

  def is_allowed(self, relpath: str, command: str) -> bool:
    return any(e.matches(relpath, command) for e in self.entries)


def load_allowlist(path: Path) -> Allowlist:
  obj = json.loads(path.read_text(encoding="utf-8"))
  if not isinstance(obj, dict) or "entries" not in obj:
    raise ValueError("Allowlist JSON must be an object with an 'entries' array")
  entries_raw = obj["entries"]
  if not isinstance(entries_raw, list):
    raise ValueError("'entries' must be an array")

  entries: list[AllowlistEntry] = []
  for i, raw in enumerate(entries_raw):
    if not isinstance(raw, dict):
      raise ValueError(f"Allowlist entry {i} must be an object")
    justification = raw.get("justification")
    if not isinstance(justification, str) or not justification.strip():
      raise ValueError(f"Allowlist entry {i} must include non-empty 'justification'")

    path_glob = raw.get("path_glob")
    if path_glob is not None and not isinstance(path_glob, str):
      raise ValueError(f"Allowlist entry {i} 'path_glob' must be string")

    command_exact = raw.get("command_exact")
    if command_exact is not None and not isinstance(command_exact, str):
      raise ValueError(f"Allowlist entry {i} 'command_exact' must be string")

    command_regex_raw = raw.get("command_regex")
    command_regex: Pattern[str] | None = None
    if command_regex_raw is not None:
      if not isinstance(command_regex_raw, str):
        raise ValueError(f"Allowlist entry {i} 'command_regex' must be string")
      command_regex = re.compile(command_regex_raw)

    if not command_exact and not command_regex:
      raise ValueError(f"Allowlist entry {i} must include 'command_exact' or 'command_regex'")

    approved_by = raw.get("approved_by")
    if approved_by is not None and not isinstance(approved_by, str):
      raise ValueError(f"Allowlist entry {i} 'approved_by' must be string")

    approved_on = raw.get("approved_on")
    if approved_on is not None and not isinstance(approved_on, str):
      raise ValueError(f"Allowlist entry {i} 'approved_on' must be string")

    entries.append(
      AllowlistEntry(
        path_glob=path_glob,
        command_exact=command_exact,
        command_regex=command_regex,
        justification=justification.strip(),
        approved_by=approved_by,
        approved_on=approved_on,
      )
    )

  return Allowlist(entries=entries)

