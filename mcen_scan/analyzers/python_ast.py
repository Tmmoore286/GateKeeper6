from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from ..models import Finding, Confidence, Severity
from ..policy import Allowlist, Profile
from ..rules import rule_info


_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
_BIND_ALL = {"0.0.0.0", "::"}


def _is_loopback_host(host: str) -> bool:
  return host.lower() in _LOOPBACK_HOSTS


def _extract_url_host(url: str) -> str | None:
  try:
    p = urlparse(url)
  except Exception:
    return None
  if p.scheme and p.netloc:
    host = p.hostname
    return host
  return None


def _const_str(node: ast.AST) -> str | None:
  if isinstance(node, ast.Constant) and isinstance(node.value, str):
    return node.value
  return None


def _const_bool(node: ast.AST) -> bool | None:
  if isinstance(node, ast.Constant) and isinstance(node.value, bool):
    return node.value
  return None


def _const_tuple_str_int(node: ast.AST) -> tuple[str, int] | None:
  if not isinstance(node, (ast.Tuple, ast.List)) or len(node.elts) < 2:
    return None
  host = _const_str(node.elts[0])
  port_node = node.elts[1]
  if not host:
    return None
  if isinstance(port_node, ast.Constant) and isinstance(port_node.value, int):
    return host, port_node.value
  return None


def _extract_call_name(func: ast.AST) -> str:
  if isinstance(func, ast.Name):
    return func.id
  if isinstance(func, ast.Attribute):
    return f"{_extract_call_name(func.value)}.{func.attr}"
  return "<unknown>"


@dataclass
class ImportIndex:
  name_to_module: dict[str, str]

  def resolve(self, name: str) -> str:
    if name in self.name_to_module:
      return self.name_to_module[name]
    return name


def _build_import_index(tree: ast.AST) -> ImportIndex:
  mapping: dict[str, str] = {}
  for node in ast.walk(tree):
    if isinstance(node, ast.Import):
      for alias in node.names:
        asname = alias.asname or alias.name.split(".")[0]
        mapping[asname] = alias.name
    elif isinstance(node, ast.ImportFrom):
      if not node.module:
        continue
      for alias in node.names:
        if alias.name == "*":
          continue
        asname = alias.asname or alias.name
        mapping[asname] = f"{node.module}.{alias.name}"
  return ImportIndex(name_to_module=mapping)


def _make_finding(
  *,
  rule_id: str,
  severity: Severity,
  confidence: Confidence,
  relpath: str,
  line: int | None,
  evidence: str,
) -> Finding:
  info = rule_info(rule_id)
  return Finding(
    rule_id=info.rule_id,
    title=info.title,
    category=info.category,
    severity=severity,
    confidence=confidence,
    file=relpath,
    line=line,
    evidence=evidence,
    why_it_matters=info.why_it_matters,
    remediation=info.remediation,
  )


_NETWORK_CALL_PREFIXES = {
  "urllib.request.urlopen",
  "urllib3.PoolManager.request",
  "requests.get",
  "requests.post",
  "requests.put",
  "requests.delete",
  "requests.request",
  "http.client.HTTPConnection",
  "http.client.HTTPSConnection",
  "ftplib.FTP",
  "smtplib.SMTP",
  "smtplib.SMTP_SSL",
  "imaplib.IMAP4",
  "poplib.POP3",
  "xmlrpc.client.ServerProxy",
}

_SOCKET_METHODS = {"socket.connect", "connect", "socket.bind", "bind", "socket.listen", "listen"}

_PROTECTED_PATH_PREFIXES = (
  "/etc/",
  "/System/",
  "/Library/LaunchDaemons/",
  "/Library/LaunchAgents/",
  "/usr/local/bin/",
  "/usr/bin/",
  "C:\\\\Windows\\\\",
  "C:\\\\Program Files\\\\",
  "C:\\\\Program Files (x86)\\\\",
)

_WINDOWS_STARTUP_HINTS = (
  "\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup",
  "\\\\CurrentVersion\\\\Run",
  "\\\\CurrentVersion\\\\RunOnce",
)


def analyze_python(*, relpath: str, source: str, profile: Profile, allowlist: Allowlist | None) -> list[Finding]:
  findings: list[Finding] = []
  findings.extend(_obfuscation_heuristics(relpath=relpath, source=source))
  try:
    tree = ast.parse(source, filename=relpath)
  except SyntaxError as e:
    findings.append(
      _make_finding(
        rule_id="OBF001",
        severity="info",
        confidence="low",
        relpath=relpath,
        line=getattr(e, "lineno", None),
        evidence=f"parse_error: {e.msg}",
      )
    )
    return findings

  imports = _build_import_index(tree)
  imported_roots = {m.split(".")[0] for m in imports.name_to_module.values()}

  for node in ast.walk(tree):
    if isinstance(node, ast.Call):
      raw_name = _extract_call_name(node.func)
      resolved = _resolve_dotted(raw_name, imports)

      # DEX001
      if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec", "compile"}:
        findings.append(
          _make_finding(
            rule_id="DEX001",
            severity="blocker",
            confidence="high",
            relpath=relpath,
            line=getattr(node, "lineno", None),
            evidence=f"call: {node.func.id}(...)",
          )
        )
        continue

      # DES001 (pickle/marshal)
      if resolved in {"pickle.load", "pickle.loads", "marshal.loads", "dill.load", "dill.loads"}:
        findings.append(
          _make_finding(
            rule_id="DES001",
            severity="blocker",
            confidence="high",
            relpath=relpath,
            line=getattr(node, "lineno", None),
            evidence=f"call: {resolved}(...)",
          )
        )
        continue

      # DEX002 (dynamic import/loader)
      if resolved in {
        "__import__",
        "importlib.import_module",
        "runpy.run_path",
        "runpy.run_module",
      }:
        findings.append(
          _make_finding(
            rule_id="DEX002",
            severity="blocker",
            confidence="high",
            relpath=relpath,
            line=getattr(node, "lineno", None),
            evidence=f"call: {resolved}(...)",
          )
        )
        continue

      # DEX003 (FFI)
      if resolved.startswith("ctypes.") or resolved.startswith("cffi.") or resolved in {"ctypes.CDLL", "ctypes.WinDLL"}:
        findings.append(
          _make_finding(
            rule_id="DEX003",
            severity="high",
            confidence="medium",
            relpath=relpath,
            line=getattr(node, "lineno", None),
            evidence=f"use: {resolved}",
          )
        )

      # PER003 (writes to protected paths)
      if _is_write_call(node, resolved):
        path_arg = node.args[0] if node.args else None
        p = _const_str(path_arg) if path_arg else None
        if p and _is_protected_path(p):
          findings.append(
            _make_finding(
              rule_id="PER003",
              severity="high",
              confidence="medium",
              relpath=relpath,
              line=getattr(node, "lineno", None),
              evidence=f"write path: {p!r}",
            )
          )

      # PER002 (registry autoruns) - conservative signature
      if resolved in {"winreg.SetValueEx", "winreg.SetValue", "winreg.CreateKey", "winreg.CreateKeyEx"}:
        # look for any constant string containing Run/RunOnce patterns
        for a in node.args:
          s = _const_str(a)
          if not s:
            continue
          if any(h.lower() in s.lower() for h in _WINDOWS_STARTUP_HINTS):
            findings.append(
              _make_finding(
                rule_id="PER002",
                severity="blocker",
                confidence="high",
                relpath=relpath,
                line=getattr(node, "lineno", None),
                evidence=f"winreg persistence key: {s!r}",
              )
            )
            break

      # PEX (subprocess / os.system)
      if resolved in {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_output",
        "subprocess.check_call",
        "os.system",
        "os.popen",
        "pty.spawn",
      }:
        cmd_str = _extract_command_string(node)
        if _has_shell_true(node):
          findings.append(
            _make_finding(
              rule_id="PEX001",
              severity="blocker",
              confidence="high",
              relpath=relpath,
              line=getattr(node, "lineno", None),
              evidence=f"{resolved}(shell=True)",
            )
          )
          continue

        if cmd_str and _looks_like_network_or_persist_tooling(cmd_str):
          findings.append(
            _make_finding(
              rule_id="PEX002",
              severity="blocker",
              confidence="high",
              relpath=relpath,
              line=getattr(node, "lineno", None),
              evidence=f"{resolved}({cmd_str})",
            )
          )
          continue

        if cmd_str and allowlist and allowlist.is_allowed(relpath, cmd_str):
          continue

        sev: Severity = "high"
        if profile.subprocess_requires_allowlist:
          sev = "blocker"

        evidence = f"{resolved}({cmd_str})" if cmd_str else f"{resolved}(...)"
        findings.append(
          _make_finding(
            rule_id="PEX003",
            severity=sev,
            confidence="medium",
            relpath=relpath,
            line=getattr(node, "lineno", None),
            evidence=evidence,
          )
        )
        continue

      # Network calls: literal URLs / hosts
      if any(resolved == p or resolved.startswith(p + ".") for p in _NETWORK_CALL_PREFIXES):
        url_arg = node.args[0] if node.args else None
        url = _const_str(url_arg) if url_arg else None
        host = _extract_url_host(url) if url else None
        if host is not None:
          if _is_loopback_host(host):
            continue
          findings.append(
            _make_finding(
              rule_id="NET001",
              severity="blocker",
              confidence="high",
              relpath=relpath,
              line=getattr(node, "lineno", None),
              evidence=f"call: {resolved}({url!r})",
            )
          )
        else:
          sev: Severity = "high"
          if profile.unknown_network_destination_is_blocker:
            sev = "blocker"
          findings.append(
            _make_finding(
              rule_id="NET002",
              severity=sev,
              confidence="medium",
              relpath=relpath,
              line=getattr(node, "lineno", None),
              evidence=f"call: {resolved}(<dynamic>)",
            )
          )
        continue

      # Heuristic: HTTP verb method call with URL literal when requests/urllib3 imported
      if isinstance(node.func, ast.Attribute) and node.func.attr.lower() in {"get", "post", "put", "delete", "request"}:
        if "requests" in imported_roots or "urllib3" in imported_roots:
          url_arg = node.args[0] if node.args else None
          url = _const_str(url_arg) if url_arg else None
          host = _extract_url_host(url) if url else None
          if host is not None and not _is_loopback_host(host):
            findings.append(
              _make_finding(
                rule_id="NET001",
                severity="blocker",
                confidence="medium",
                relpath=relpath,
                line=getattr(node, "lineno", None),
                evidence=f"call: <http>.{node.func.attr}({url!r})",
              )
            )

      # Socket connect/bind with literal tuple
      if resolved.endswith(".connect") or resolved.endswith(".bind") or resolved.endswith(".listen"):
        tup = _const_tuple_str_int(node.args[0]) if node.args else None
        if tup:
          host, _port = tup
          if resolved.endswith(".connect"):
            if _is_loopback_host(host):
              continue
            findings.append(
              _make_finding(
                rule_id="NET001",
                severity="blocker",
                confidence="high",
                relpath=relpath,
                line=getattr(node, "lineno", None),
                evidence=f"socket.connect(({host!r}, ...))",
              )
            )
            continue
          if resolved.endswith(".bind"):
            if host in _BIND_ALL:
              findings.append(
                _make_finding(
                  rule_id="NET003",
                  severity="blocker",
                  confidence="high",
                  relpath=relpath,
                  line=getattr(node, "lineno", None),
                  evidence=f"socket.bind(({host!r}, ...))",
                )
              )
            continue

      # Framework bind patterns (host keyword)
      host_kw = _keyword_value(node, "host")
      host_val = _const_str(host_kw) if host_kw is not None else None
      if host_val in _BIND_ALL:
        findings.append(
          _make_finding(
            rule_id="NET003",
            severity="blocker",
            confidence="high",
            relpath=relpath,
            line=getattr(node, "lineno", None),
            evidence=f"host={host_val!r}",
          )
        )

  # Import-level signal for network modules without callsite proof -> NET002 review
  network_modules = {
    "socket",
    "urllib",
    "urllib.request",
    "http.client",
    "ftplib",
    "smtplib",
    "imaplib",
    "poplib",
    "telnetlib",
    "xmlrpc.client",
    "requests",
    "urllib3",
    "paramiko",
    "boto3",
  }
  for _alias, module in imports.name_to_module.items():
    mod_root = module.split(".")[0]
    if module in network_modules or mod_root in network_modules:
      sev: Severity = "info" if not profile.unknown_network_destination_is_blocker else "high"
      findings.append(
        _make_finding(
          rule_id="NET002",
          severity=sev,
          confidence="low",
          relpath=relpath,
          line=None,
          evidence=f"import: {module}",
        )
      )

  return _dedupe(findings)


def _resolve_dotted(raw_name: str, imports: ImportIndex) -> str:
  if raw_name == "<unknown>":
    return raw_name
  parts = raw_name.split(".")
  if not parts:
    return raw_name
  first = parts[0]
  first_resolved = imports.resolve(first)
  if len(parts) == 1:
    return first_resolved

  if first_resolved != first:
    last_seg = first_resolved.split(".")[-1]
    if parts[1] == last_seg:
      parts = [first_resolved] + parts[2:]
    else:
      parts = [first_resolved] + parts[1:]

  return ".".join(parts)


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


def _keyword_value(call: ast.Call, name: str) -> ast.AST | None:
  for kw in call.keywords:
    if kw.arg == name:
      return kw.value
  return None


def _has_shell_true(call: ast.Call) -> bool:
  v = _keyword_value(call, "shell")
  if v is None:
    return False
  b = _const_bool(v)
  return b is True


def _extract_command_string(call: ast.Call) -> str | None:
  if not call.args:
    return None
  arg0 = call.args[0]
  s = _const_str(arg0)
  if s is not None:
    return s.strip()

  if isinstance(arg0, (ast.List, ast.Tuple)):
    parts: list[str] = []
    for elt in arg0.elts:
      sv = _const_str(elt)
      if sv is None:
        return None
      parts.append(sv)
    return " ".join(parts).strip()

  return None


_TOOL_TOKENS_BLOCKER = {
  # network
  "curl",
  "wget",
  "nc",
  "netcat",
  "socat",
  "ssh",
  "scp",
  "ftp",
  "tftp",
  "powershell",
  "invoke-webrequest",
  "iwr",
  "webclient",
  "bitsadmin",
  "start-bitstransfer",
  # persistence / system mods
  "schtasks",
  "reg",
  "sc",
  "systemctl",
  "launchctl",
  "crontab",
}


def _looks_like_network_or_persist_tooling(cmd: str) -> bool:
  tokens = re.split(r"\\s+", cmd.strip().lower())
  if not tokens:
    return False
  first = tokens[0].strip('"').strip("'")
  if first in _TOOL_TOKENS_BLOCKER:
    return True
  return any(t in _TOOL_TOKENS_BLOCKER for t in tokens[:4])


_BASE64_BLOB_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{600,}={0,2}(?![A-Za-z0-9+/=])")


def _obfuscation_heuristics(*, relpath: str, source: str) -> list[Finding]:
  findings: list[Finding] = []
  if "base64" in source and _BASE64_BLOB_RE.search(source):
    findings.append(
      _make_finding(
        rule_id="OBF001",
        severity="high",
        confidence="low",
        relpath=relpath,
        line=None,
        evidence="large base64-like blob present",
      )
    )
  if "zlib.decompress" in source and "base64.b64decode" in source:
    findings.append(
      _make_finding(
        rule_id="OBF001",
        severity="high",
        confidence="low",
        relpath=relpath,
        line=None,
        evidence="base64 decode + zlib decompress pattern present",
      )
    )
  return findings


def _is_write_call(call: ast.Call, resolved: str) -> bool:
  if resolved == "open":
    mode_node = call.args[1] if len(call.args) >= 2 else _keyword_value(call, "mode")
    mode = _const_str(mode_node) if mode_node is not None else None
    if mode is None:
      return False
    return any(ch in mode for ch in ("w", "a", "x", "+"))
  return resolved.endswith(".write_text") or resolved.endswith(".write_bytes")


def _is_protected_path(p: str) -> bool:
  if any(p.startswith(pref) for pref in _PROTECTED_PATH_PREFIXES):
    return True
  if any(h.lower() in p.lower() for h in _WINDOWS_STARTUP_HINTS):
    return True
  return False
