from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RuleInfo:
  rule_id: str
  title: str
  category: str
  why_it_matters: str
  remediation: str


RULES: dict[str, RuleInfo] = {
  "SCAN001": RuleInfo(
    rule_id="SCAN001",
    title="Python parse error (scan incomplete)",
    category="other",
    why_it_matters="If a file cannot be parsed, the scan cannot assess it for network/persistence/dynamic-exec risks.",
    remediation="Fix the syntax error and re-run the scan to produce a complete audit.",
  ),
  "NET001": RuleInfo(
    rule_id="NET001",
    title="Proven non-loopback network communication",
    category="network",
    why_it_matters="Non-loopback communications can violate enclave controls and create exfiltration/C2 risk.",
    remediation="Remove the network call or constrain it to loopback; document any required communications through the appropriate approval process.",
  ),
  "NET002": RuleInfo(
    rule_id="NET002",
    title="Potential network capability with unknown destination",
    category="network",
    why_it_matters="Network-capable code with derived destinations is hard to audit and can be redirected unexpectedly.",
    remediation="Constrain destinations to loopback or make destinations explicit and reviewable; avoid reading hosts from env/config unless required and approved.",
  ),
  "NET003": RuleInfo(
    rule_id="NET003",
    title="Service binds/listens on all interfaces",
    category="network",
    why_it_matters="Binding to 0.0.0.0/:: exposes services beyond localhost and can create unintended network exposure.",
    remediation="Bind to localhost only (127.0.0.1/::1) unless a documented and approved need exists.",
  ),
  "PER001": RuleInfo(
    rule_id="PER001",
    title="Persistence or service scheduling behavior detected",
    category="persistence",
    why_it_matters="Persistence mechanisms can violate endpoint configuration baselines and are common malware behaviors.",
    remediation="Remove scheduling/persistence behavior; if operationally required, implement via approved enterprise mechanisms and document.",
  ),
  "PER002": RuleInfo(
    rule_id="PER002",
    title="Registry/startup persistence behavior detected",
    category="persistence",
    why_it_matters="Autorun persistence modifies endpoint state and is high-risk on managed networks.",
    remediation="Remove autorun/registry modifications; use approved deployment and configuration channels.",
  ),
  "PER003": RuleInfo(
    rule_id="PER003",
    title="Writes to protected system locations",
    category="persistence",
    why_it_matters="Writing to system directories can indicate install/persistence behavior and violates least privilege.",
    remediation="Write only to user-approved working directories; avoid system paths and require explicit operator choice.",
  ),
  "DEX001": RuleInfo(
    rule_id="DEX001",
    title="Dynamic code execution (eval/exec/compile)",
    category="dynamic_exec",
    why_it_matters="Dynamic execution allows code injection and makes auditing intent and behavior unreliable.",
    remediation="Replace with explicit logic; if a DSL is needed, use a restricted parser that cannot execute arbitrary code.",
  ),
  "DEX002": RuleInfo(
    rule_id="DEX002",
    title="Dynamic import/loader behavior",
    category="dynamic_exec",
    why_it_matters="Loading modules from variable paths/names can execute unreviewed code and bypass controls.",
    remediation="Use explicit imports and static module lists; avoid importing by user-controlled input.",
  ),
  "DEX003": RuleInfo(
    rule_id="DEX003",
    title="Native library loading / FFI detected",
    category="dynamic_exec",
    why_it_matters="FFI can bypass Python-level safety assumptions and load unreviewed native code.",
    remediation="Avoid FFI on MCEN endpoints unless specifically approved; prefer pure-Python implementations.",
  ),
  "DES001": RuleInfo(
    rule_id="DES001",
    title="Unsafe deserialization (pickle/marshal)",
    category="deserialization",
    why_it_matters="Pickle/marshal data can execute code during load, enabling code execution via data files.",
    remediation="Use safe formats (JSON) and validate schema; never load pickle from untrusted sources.",
  ),
  "PEX001": RuleInfo(
    rule_id="PEX001",
    title="Subprocess with shell invocation or shell injection risk",
    category="process_exec",
    why_it_matters="Shell execution expands injection risk and can execute unintended commands.",
    remediation="Avoid shell=True; pass argument arrays; strictly validate/quote inputs.",
  ),
  "PEX002": RuleInfo(
    rule_id="PEX002",
    title="Subprocess invokes network/persistence tooling",
    category="process_exec",
    why_it_matters="Chaining to external tooling can bypass code review and enable disallowed behaviors.",
    remediation="Remove the tooling invocation; implement required behavior via approved mechanisms or explicit safe APIs.",
  ),
  "PEX003": RuleInfo(
    rule_id="PEX003",
    title="Subprocess execution requires review",
    category="process_exec",
    why_it_matters="Process execution can materially change system state and is frequently used to hide network/persistence behavior.",
    remediation="Review and justify the command; add an allowlist entry if it is benign and required.",
  ),
  "OBF001": RuleInfo(
    rule_id="OBF001",
    title="Obfuscation-like decode/decompress patterns",
    category="obfuscation",
    why_it_matters="Obfuscation patterns are common in droppers and make intent hard to audit.",
    remediation="Remove encoded payloads; keep code explicit and reviewable.",
  ),
}


def rule_info(rule_id: str) -> RuleInfo:
  return RULES[rule_id]
