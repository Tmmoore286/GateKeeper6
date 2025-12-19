from __future__ import annotations

import json
import os
import socket
import traceback
from datetime import datetime, timezone


LOG_PATH = os.environ.get("MCEN_EGRESS_LOG")
ALLOW_LOOPBACK = os.environ.get("MCEN_EGRESS_ALLOW_LOOPBACK", "1") == "1"
BLOCK_NON_LOOPBACK = os.environ.get("MCEN_EGRESS_BLOCK_NON_LOOPBACK", "1") == "1"

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}
BIND_ALL = {"0.0.0.0", "::"}


def _utc_now() -> str:
  return datetime.now(timezone.utc).isoformat()


def _write_event(event: dict) -> None:
  if not LOG_PATH:
    return
  try:
    with open(LOG_PATH, "a", encoding="utf-8") as f:
      f.write(json.dumps(event, sort_keys=True) + "\n")
  except Exception:
    return


def _stack_summary() -> list[dict]:
  frames = traceback.extract_stack()
  out = []
  for fr in frames[:-2]:
    fn = fr.filename
    if "sitecustomize.py" in fn:
      continue
    out.append({"file": fn, "line": fr.lineno, "name": fr.name})
  return out[-25:]


def _host_is_loopback(host: str) -> bool:
  return host.lower() in LOOPBACK_HOSTS


def _is_non_loopback_inet_addr(addr) -> tuple[bool, str | None]:
  if not isinstance(addr, tuple) or not addr:
    return False, None
  host = addr[0]
  if not isinstance(host, str):
    return False, None
  if host in BIND_ALL:
    return True, host
  if _host_is_loopback(host):
    return False, host
  return True, host


_orig_connect = socket.socket.connect
_orig_connect_ex = socket.socket.connect_ex
_orig_sendto = socket.socket.sendto
_orig_bind = socket.socket.bind


def _blocked_error(host: str) -> RuntimeError:
  return RuntimeError(f"MCEN_EGRESS_BLOCK: non-loopback network attempt to {host}")


def connect(self, address):  # noqa: A001
  is_non_loopback, host = _is_non_loopback_inet_addr(address)
  if host is None:
    return _orig_connect(self, address)
  if not is_non_loopback and ALLOW_LOOPBACK:
    _write_event(
      {"ts": _utc_now(), "action": "allowed_loopback", "op": "connect", "host": host, "address": repr(address), "stack": _stack_summary()}
    )
    return _orig_connect(self, address)

  _write_event({"ts": _utc_now(), "action": "blocked", "op": "connect", "host": host, "address": repr(address), "stack": _stack_summary()})
  if BLOCK_NON_LOOPBACK:
    raise _blocked_error(host)
  return _orig_connect(self, address)


def connect_ex(self, address):  # noqa: A001
  is_non_loopback, host = _is_non_loopback_inet_addr(address)
  if host is None:
    return _orig_connect_ex(self, address)
  if not is_non_loopback and ALLOW_LOOPBACK:
    _write_event(
      {"ts": _utc_now(), "action": "allowed_loopback", "op": "connect_ex", "host": host, "address": repr(address), "stack": _stack_summary()}
    )
    return _orig_connect_ex(self, address)

  _write_event(
    {"ts": _utc_now(), "action": "blocked", "op": "connect_ex", "host": host, "address": repr(address), "stack": _stack_summary()}
  )
  if BLOCK_NON_LOOPBACK:
    raise _blocked_error(host)
  return _orig_connect_ex(self, address)


def sendto(self, data, address, *args, **kwargs):  # noqa: A001
  is_non_loopback, host = _is_non_loopback_inet_addr(address)
  if host is None:
    return _orig_sendto(self, data, address, *args, **kwargs)
  if not is_non_loopback and ALLOW_LOOPBACK:
    _write_event(
      {"ts": _utc_now(), "action": "allowed_loopback", "op": "sendto", "host": host, "address": repr(address), "stack": _stack_summary()}
    )
    return _orig_sendto(self, data, address, *args, **kwargs)

  _write_event({"ts": _utc_now(), "action": "blocked", "op": "sendto", "host": host, "address": repr(address), "stack": _stack_summary()})
  if BLOCK_NON_LOOPBACK:
    raise _blocked_error(host)
  return _orig_sendto(self, data, address, *args, **kwargs)


def bind(self, address):  # noqa: A001
  is_non_loopback, host = _is_non_loopback_inet_addr(address)
  if host in BIND_ALL:
    _write_event({"ts": _utc_now(), "action": "blocked", "op": "bind", "host": host, "address": repr(address), "stack": _stack_summary()})
    if BLOCK_NON_LOOPBACK:
      raise RuntimeError(f"MCEN_EGRESS_BLOCK: bind to all interfaces {host}")
  return _orig_bind(self, address)


socket.socket.connect = connect  # type: ignore[assignment]
socket.socket.connect_ex = connect_ex  # type: ignore[assignment]
socket.socket.sendto = sendto  # type: ignore[assignment]
socket.socket.bind = bind  # type: ignore[assignment]

