#!/usr/bin/env python3
"""Agent 4 — The Large Repo Stress Tester. See AGENTS.md for the full spec."""

from __future__ import annotations

import resource
import subprocess
import sys
import time
from pathlib import Path

from _agent_utils import CheckList, run_scan_json

ROOT = Path(__file__).parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "large_repo"

# The 3 vulnerabilities setup_large_repo() actually plants (AGENTS.md's "10
# known vulnerabilities" predates this implementation — tracked as a known
# fixture/doc mismatch, not something to fabricate data to match).
PLANTED_VULNERABLE_FILES = (
    "src/models/loader.py",
    "experiments/run_001.py",
    "data/upload.py",
)


def _peak_rss_mb() -> float:
    """Peak resident set size of this process so far, in MB."""
    raw = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return raw / (1024 * 1024) if sys.platform == "darwin" else raw / 1024


def main() -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "tests" / "fixtures" / "setup_all_fixtures.py")],
        check=True,
        capture_output=True,
    )

    checks = CheckList("Agent 4 — The Large Repo Stress Tester")

    # Plant a poison file inside an excluded directory to verify it's skipped.
    poison_dir = FIXTURE / "__pycache__"
    poison_dir.mkdir(exist_ok=True)
    poison_file = poison_dir / "poison.py"
    poison_file.write_text('API_KEY = "sk-proj-SHOULD_NOT_BE_FOUND_XXXXXXXXXXXXXXXXXXXXXXXX"\n')

    try:
        started = time.perf_counter()
        exit_code, payload = run_scan_json(str(FIXTURE))
        duration_seconds = time.perf_counter() - started

        checks.check(
            f"Scan completes in under 10 seconds (took {duration_seconds:.2f}s)",
            duration_seconds < 10,
        )

        peak_mb = _peak_rss_mb()
        checks.check(f"Memory usage stays under 200MB (peak {peak_mb:.0f}MB)", peak_mb < 200)

        found_files = {f["file"] for f in payload["findings"]}
        checks.check(
            "All 3 planted vulnerabilities are reported",
            all(
                any(str(FIXTURE / planted) == f for f in found_files)
                for planted in PLANTED_VULNERABLE_FILES
            ),
        )

        checks.check(
            "__pycache__ is excluded (poison file not reported)",
            not any("__pycache__" in f for f in found_files),
        )

        checks.check("Exit code is 1 (vulnerabilities present)", exit_code == 1)
    finally:
        poison_file.unlink(missing_ok=True)

    checks.finish()


if __name__ == "__main__":
    main()
