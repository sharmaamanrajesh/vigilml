#!/usr/bin/env python3
"""Agent 3 — The CI/CD Pipeline Runner. See AGENTS.md for the full spec."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from _agent_utils import CheckList, run_scan, run_scan_json

ROOT = Path(__file__).parent.parent.parent
VULNERABLE = ROOT / "tests" / "fixtures" / "careless_engineer"
CLEAN = ROOT / "tests" / "fixtures" / "clean_project"

_REQUIRED_FINDING_FIELDS = {
    "type",
    "severity",
    "file",
    "line",
    "message",
    "remediation",
}


def main() -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "tests" / "fixtures" / "setup_all_fixtures.py")],
        check=True,
        capture_output=True,
    )

    checks = CheckList("Agent 3 — The CI/CD Pipeline Runner")

    # Test 1: JSON output on vulnerable project
    json_exit_code, payload = run_scan_json(str(VULNERABLE))
    checks.check("JSON output is valid JSON (parseable)", isinstance(payload, dict))
    checks.check(
        "JSON contains version, scanned_at, total_findings, findings[]",
        {"version", "scanned_at", "total_findings", "findings"} <= payload.keys(),
    )
    checks.check(
        "Each finding has type/severity/file/line/message/remediation",
        all(f.keys() >= _REQUIRED_FINDING_FIELDS for f in payload["findings"]),
    )
    checks.check("Exit code is 1 with findings present", json_exit_code == 1)

    # Test 2: --no-colour output on vulnerable project
    _, no_colour_output = run_scan(str(VULNERABLE), "--no-colour")
    checks.check("No ANSI colour codes in --no-colour output", "\x1b[" not in no_colour_output)

    # Test 3: --quiet mode — only summary line
    _, quiet_output = run_scan(str(VULNERABLE), "--quiet")
    quiet_lines = [line for line in quiet_output.splitlines() if line.strip()]
    checks.check("--quiet outputs exactly one line", len(quiet_lines) == 1)

    # Test 4: clean project, JSON output — must be exit code 0
    clean_exit_code, clean_payload = run_scan_json(str(CLEAN))
    checks.check("Clean project JSON output exit code is 0", clean_exit_code == 0)
    checks.check("Clean project JSON shows zero findings", clean_payload["total_findings"] == 0)

    # JSON output to stdout only — nothing but the JSON document
    _, raw_json_output = run_scan(str(CLEAN), "--json")
    checks.check(
        "--json stdout contains nothing but the JSON document",
        raw_json_output.strip().startswith("{") and raw_json_output.strip().endswith("}"),
    )

    checks.finish()


if __name__ == "__main__":
    main()
