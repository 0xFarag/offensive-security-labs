"""Run regression tests, then record nine exploit/fix/legitimate-control demonstrations."""
from datetime import datetime, timezone
import hashlib
import importlib
import json
from pathlib import Path
import platform
import sys
import unittest

ROOT = Path(__file__).resolve().parent
LABS = ["jwt_audience", "oauth_pkce", "mcp_consent", "ssrf_redirect", "ci_injection",
        "tar_traversal", "api_mass_assignment", "agent_tool_boundary", "webhook_replay"]


def main():
    tests = unittest.defaultTestLoader.discover(str(ROOT), pattern="test_security_boundaries.py")
    result = unittest.TextTestRunner(verbosity=1).run(tests)
    if not result.wasSuccessful():
        return 1
    rows = []
    for name in LABS:
        evidence = importlib.import_module("lab_" + name).demo()
        if not (evidence["vulnerable_accepts"] is True and evidence["fixed_accepts"] is False
                and evidence["legitimate_accepts"] is True):
            raise RuntimeError(f"demonstration contract failed: {name}")
        rows.append({"lab": name, **evidence})
        print(f"PASS {name}: exploit reproduced; fix blocks; legitimate control passes")
    report = {"schema_version": 1, "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
              "runtime": {"python": platform.python_version(), "os": platform.system()},
              "scope": "Synthetic local fixtures; no external target was assessed",
              "provenance": "Prepared with AI assistance; tests and demonstrations executed locally",
              "regression_tests": {"run": result.testsRun, "failures": len(result.failures),
                                   "errors": len(result.errors), "skipped": len(result.skipped)},
              "source_sha256": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in sorted(ROOT.glob("*.py"))}, "demonstrations": rows}
    output = ROOT / "evidence.json"
    output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {len(rows)} demonstrations and {result.testsRun} tests in {output.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
