#!/usr/bin/env python3
"""
VigilML Hook Dispatcher — on_bash_run.py

Triggered by Claude Code's PostToolUse hook after every Bash command.
Detects test runs, fixture setups, and install commands, then
triggers the appropriate agents automatically.

Claude Code passes the bash command string as the first argument.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent


def run_agent(script: str, reason: str) -> bool:
    """Run a single agent script. Returns True if passed."""
    script_path = ROOT / script
    if not script_path.exists():
        print(f"  [SKIP] {script} — not yet implemented", flush=True)
        return True

    print(f"\n  [AUTO-AGENT] {reason}", flush=True)
    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=False,
        timeout=120,
    )
    passed = result.returncode == 0
    status = "PASS" if passed else "FAIL"
    print(f"  [{status}] {Path(script).stem}", flush=True)
    return passed


# ── Command → agent trigger map ──────────────────────────────────────────────
# Each entry: (substring_to_match, [(agent_script, reason)])
# A command is matched if it CONTAINS the substring.

COMMAND_TRIGGER_MAP: list[tuple[str, list[tuple[str, str]]]] = [
    # After installing the package — full smoke test
    (
        "pip install -e",
        [
            ("tests/agents/agent_careless_engineer.py",
             "package installed — running end-to-end smoke test"),
            ("tests/agents/agent_clean_project.py",
             "package installed — false positive check after install"),
        ],
    ),

    # After setting up fixtures — validate fixtures are correct
    (
        "setup_all_fixtures.py",
        [
            ("tests/agents/agent_careless_engineer.py",
             "fixtures regenerated — verifying vulnerable fixture is detectable"),
            ("tests/agents/agent_clean_project.py",
             "fixtures regenerated — verifying clean fixture has zero findings"),
        ],
    ),

    # After running pytest on the full suite — also run agents as a second pass
    (
        "pytest tests/ ",
        [
            ("tests/agents/agent_cicd_runner.py",
             "full test suite completed — running CI/CD compatibility agent"),
        ],
    ),

    # After running the benchmark — check performance agent too
    (
        "benchmark.py",
        [
            ("tests/agents/agent_stress_tester.py",
             "benchmark run — cross-checking with stress test agent"),
        ],
    ),
]


def find_triggered_agents(command: str) -> list[tuple[str, str]]:
    """Return deduplicated (agent_script, reason) list for a command."""
    triggered: dict[str, str] = {}
    for pattern, agents in COMMAND_TRIGGER_MAP:
        if pattern in command:
            for script, reason in agents:
                if script not in triggered:
                    triggered[script] = reason
    return list(triggered.items())


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(0)

    command = sys.argv[1]
    triggered = find_triggered_agents(command)

    if not triggered:
        sys.exit(0)

    print(f"\n{'─' * 60}", flush=True)
    print(f"  VigilML auto-agents triggered by bash command", flush=True)
    print(f"  Command: {command[:80]}{'...' if len(command) > 80 else ''}", flush=True)
    print(f"{'─' * 60}", flush=True)

    all_passed = True
    for script, reason in triggered:
        if not run_agent(script, reason):
            all_passed = False

    print(f"\n{'─' * 60}", flush=True)
    status = "PASSED" if all_passed else "FAILED — fix issues above before continuing"
    print(f"  Auto-agents {status}", flush=True)
    print(f"{'─' * 60}\n", flush=True)

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
