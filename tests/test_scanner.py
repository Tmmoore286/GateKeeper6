import json
import tempfile
import unittest
from pathlib import Path

from mcen_scan.policy import load_allowlist, resolve_profile
from mcen_scan.scanner import scan_path


class ScannerTests(unittest.TestCase):
  def _write(self, root: Path, rel: str, content: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")

  def test_loopback_network_allowed(self) -> None:
    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      self._write(
        root,
        "a.py",
        'import urllib.request\nurllib.request.urlopen("http://127.0.0.1:8080/health")\n',
      )
      res = scan_path(target=root, profile=resolve_profile("mcen_practical"), allowlist=None)
      self.assertEqual(res.summary.exit_code, 0)
      self.assertEqual(res.summary.decision, "PASS")
      self.assertEqual(res.summary.totals_by_severity.get("blocker", 0), 0)

  def test_external_network_is_blocker(self) -> None:
    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      self._write(root, "a.py", 'import urllib.request\nurllib.request.urlopen("https://example.com")\n')
      res = scan_path(target=root, profile=resolve_profile("mcen_practical"), allowlist=None)
      self.assertEqual(res.summary.exit_code, 1)
      self.assertEqual(res.summary.decision, "FAIL")
      self.assertGreaterEqual(res.summary.totals_by_severity.get("blocker", 0), 1)

  def test_bind_all_interfaces_is_blocker(self) -> None:
    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      self._write(
        root,
        "a.py",
        "import socket\ns=socket.socket()\ns.bind(('0.0.0.0', 8000))\n",
      )
      res = scan_path(target=root, profile=resolve_profile("mcen_practical"), allowlist=None)
      self.assertEqual(res.summary.exit_code, 1)

  def test_dynamic_exec_is_blocker(self) -> None:
    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      self._write(root, "a.py", "eval('1+1')\n")
      res = scan_path(target=root, profile=resolve_profile("mcen_practical"), allowlist=None)
      self.assertEqual(res.summary.exit_code, 1)

  def test_unsafe_deserialization_is_blocker(self) -> None:
    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      self._write(root, "a.py", "import pickle\npickle.loads(b'xyz')\n")
      res = scan_path(target=root, profile=resolve_profile("mcen_practical"), allowlist=None)
      self.assertEqual(res.summary.exit_code, 1)

  def test_subprocess_requires_review_in_practical(self) -> None:
    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      self._write(root, "a.py", "import subprocess\nsubprocess.run(['echo','hi'])\n")
      res = scan_path(target=root, profile=resolve_profile("mcen_practical"), allowlist=None)
      self.assertEqual(res.summary.exit_code, 2)
      self.assertEqual(res.summary.decision, "CONDITIONAL_PASS")

  def test_subprocess_allowlist_can_clear_review(self) -> None:
    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      self._write(root, "a.py", "import subprocess\nsubprocess.run(['echo','hi'])\n")
      allowlist_path = root / "allowlist.json"
      allowlist_path.write_text(
        json.dumps(
          {
            "entries": [
              {
                "path_glob": "*.py",
                "command_exact": "echo hi",
                "justification": "Local-only harmless command for operator feedback.",
              }
            ]
          }
        ),
        encoding="utf-8",
      )
      allowlist = load_allowlist(allowlist_path)
      res = scan_path(target=root, profile=resolve_profile("mcen_practical"), allowlist=allowlist)
      self.assertEqual(res.summary.exit_code, 0)
      self.assertEqual(res.summary.decision, "PASS")

  def test_local_python_orchestration_is_medium_in_practical(self) -> None:
    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      self._write(root, "child.py", "print('ok')\n")
      self._write(
        root,
        "runner.py",
        "\n".join(
          [
            "import subprocess",
            "import sys",
            "from pathlib import Path",
            "script_dir = Path(__file__).resolve().parent",
            "cmd = [sys.executable, str(script_dir / 'child.py')]",
            "subprocess.run(cmd, cwd=script_dir)",
            "",
          ]
        ),
      )
      res = scan_path(target=root, profile=resolve_profile("mcen_practical"), allowlist=None)
      # Should not block or require review when clearly orchestrating local Python.
      self.assertEqual(res.summary.exit_code, 0)
      self.assertEqual(res.summary.decision, "PASS")

  def test_report_includes_bluf_and_completeness(self) -> None:
    with tempfile.TemporaryDirectory() as td:
      root = Path(td)
      self._write(root, "bad.py", "def x(:\n  pass\n")
      res = scan_path(target=root, profile=resolve_profile("mcen_practical"), allowlist=None)
      md = res.to_markdown()
      self.assertIn("## BLUF (Leadership)", md)
      self.assertIn("## Technical Assessment (ISSO/ISSM/SWE)", md)
      self.assertIn("Audit completeness:", md)
      self.assertIn("SCAN001", md)


if __name__ == "__main__":
  unittest.main()
