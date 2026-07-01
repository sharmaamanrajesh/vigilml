#!/usr/bin/env python3
"""Agent 2 — The Clean Project Validator. See AGENTS.md for the full spec."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from _agent_utils import CheckList, run_scan, run_scan_json

ROOT = Path(__file__).parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "clean_project"


def main() -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "tests" / "fixtures" / "setup_all_fixtures.py")],
        check=True,
        capture_output=True,
    )

    checks = CheckList("Agent 2 — The Clean Project Validator")
    exit_code, payload = run_scan_json(str(FIXTURE))

    checks.check("Zero findings reported", payload["total_findings"] == 0)
    checks.check("Exit code is 0", exit_code == 0)

    text_exit_code, text_output = run_scan(str(FIXTURE))
    checks.check("Summary shows 'No issues found'", "No issues found" in text_output)
    checks.check("Text-mode exit code is also 0", text_exit_code == 0)

    checks.check(
        ".env.example with placeholder values not flagged",
        not any(f["file"].endswith(".env.example") for f in payload["findings"]),
    )
    checks.check(
        "os.getenv('OPENAI_API_KEY') not flagged as a credential",
        not any(f["rule"] == "openai-api-key" for f in payload["findings"]),
    )

    checks.finish()


if __name__ == "__main__":
    main()
