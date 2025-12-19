from __future__ import annotations

import re

from ..models import Finding, Severity
from ..policy import Profile
from ..rules import rule_info


def _make(rule_id: str, *, severity: str, confidence: str, relpath: str, line: int, evidence: str) -> Finding:
  info = rule_info(rule_id)
  return Finding(
    rule_id=info.rule_id,
    title=info.title,
    category=info.category,
    severity=severity,  # type: ignore[arg-type]
    confidence=confidence,  # type: ignore[arg-type]
    file=relpath,
    line=line,
    evidence=evidence,
    why_it_matters=info.why_it_matters,
    remediation=info.remediation,
  )


_PS_NET = re.compile(r"\\b(Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|Net\\.WebClient|WebClient)\\b", re.I)
_PS_EXEC = re.compile(r"\\b(Invoke-Expression|IEX)\\b", re.I)
_PS_PERSIST = re.compile(r"\\b(schtasks|New-ScheduledTask|Register-ScheduledTask|Set-ItemProperty)\\b", re.I)

_BAT_NET = re.compile(r"\\b(curl|wget|bitsadmin|certutil)\\b", re.I)
_BAT_PERSIST = re.compile(r"\\b(schtasks|reg\\s+add|sc\\s+create)\\b", re.I)

_SH_NET = re.compile(r"\\b(curl|wget|nc|netcat|socat|ssh|scp)\\b", re.I)
_SH_PERSIST = re.compile(r"\\b(crontab|systemctl\\s+enable|launchctl\\s+load)\\b", re.I)

_VBS_EXEC = re.compile(r"CreateObject\\(\"WScript\\.Shell\"\\)", re.I)
_VBS_NET = re.compile(r"(MSXML2\\.XMLHTTP|WinHttp\\.WinHttpRequest|ADODB\\.Stream)", re.I)


_URL_RE = re.compile(r"(https?://[^\\s'\"\\)]+)", re.I)
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _url_host(url: str) -> str | None:
  m = re.match(r"^https?://([^/]+)", url, flags=re.I)
  if not m:
    return None
  hostport = m.group(1)
  host = hostport.split("@")[-1].split(":")[0].strip("[]")
  return host


def _is_loopback(host: str) -> bool:
  return host.lower() in _LOOPBACK_HOSTS


def _net_finding_severity(profile: Profile, *, proven_non_loopback: bool) -> Severity:
  if proven_non_loopback:
    return "blocker"
  return "blocker" if profile.unknown_network_destination_is_blocker else "high"


def analyze_script(*, relpath: str, kind: str, source: str, profile: Profile) -> list[Finding]:
  findings: list[Finding] = []
  for idx, line in enumerate(source.splitlines(), start=1):
    l = line.strip()
    if not l or l.startswith("#"):
      continue

    urls = _URL_RE.findall(l)
    non_loopback_url = False
    loopback_url = False
    for u in urls:
      host = _url_host(u)
      if host is None:
        continue
      if _is_loopback(host):
        loopback_url = True
      else:
        non_loopback_url = True

    if kind == "powershell":
      if _PS_NET.search(l):
        if non_loopback_url:
          findings.append(_make("NET001", severity="blocker", confidence="high", relpath=relpath, line=idx, evidence=l[:200]))
        elif loopback_url:
          pass
        else:
          findings.append(
            _make(
              "NET002",
              severity=_net_finding_severity(profile, proven_non_loopback=False),
              confidence="medium",
              relpath=relpath,
              line=idx,
              evidence=l[:200],
            )
          )
      if _PS_EXEC.search(l):
        findings.append(_make("DEX001", severity="blocker", confidence="high", relpath=relpath, line=idx, evidence=l[:200]))
      if _PS_PERSIST.search(l):
        findings.append(_make("PER001", severity="blocker", confidence="high", relpath=relpath, line=idx, evidence=l[:200]))

    elif kind == "batch":
      if _BAT_NET.search(l):
        if non_loopback_url:
          findings.append(_make("NET001", severity="blocker", confidence="high", relpath=relpath, line=idx, evidence=l[:200]))
        elif loopback_url:
          pass
        else:
          findings.append(
            _make(
              "NET002",
              severity=_net_finding_severity(profile, proven_non_loopback=False),
              confidence="medium",
              relpath=relpath,
              line=idx,
              evidence=l[:200],
            )
          )
      if _BAT_PERSIST.search(l):
        findings.append(_make("PER001", severity="blocker", confidence="high", relpath=relpath, line=idx, evidence=l[:200]))

    elif kind == "shell":
      if _SH_NET.search(l):
        if non_loopback_url:
          findings.append(_make("NET001", severity="blocker", confidence="high", relpath=relpath, line=idx, evidence=l[:200]))
        elif loopback_url:
          pass
        else:
          findings.append(
            _make(
              "NET002",
              severity=_net_finding_severity(profile, proven_non_loopback=False),
              confidence="medium",
              relpath=relpath,
              line=idx,
              evidence=l[:200],
            )
          )
      if _SH_PERSIST.search(l):
        findings.append(_make("PER001", severity="blocker", confidence="high", relpath=relpath, line=idx, evidence=l[:200]))

    elif kind == "vbscript":
      if _VBS_NET.search(l):
        if non_loopback_url:
          findings.append(_make("NET001", severity="blocker", confidence="high", relpath=relpath, line=idx, evidence=l[:200]))
        elif loopback_url:
          pass
        else:
          findings.append(
            _make(
              "NET002",
              severity=_net_finding_severity(profile, proven_non_loopback=False),
              confidence="medium",
              relpath=relpath,
              line=idx,
              evidence=l[:200],
            )
          )
      if _VBS_EXEC.search(l):
        findings.append(_make("PEX003", severity="high", confidence="medium", relpath=relpath, line=idx, evidence=l[:200]))

  return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
  seen: set[tuple] = set()
  out: list[Finding] = []
  for f in findings:
    key = (f.rule_id, f.file, f.line, f.evidence)
    if key in seen:
      continue
    seen.add(key)
    out.append(f)
  return out
