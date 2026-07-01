"""Shared helpers for VigilML agent scripts.

Each agent_*.py script runs standalone via `sys.executable script.py`
(see tests/agents/run_all_agents.py) — not via pytest. The contract:
print "X/Y checks passed" to stdout and exit 0 only if X == Y.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from click.testing import CliRunner

from vigilml.cli import main as vigilml_main


class CheckList:
    """Tracks pass/fail checks and prints the summary line agents are scored on."""

    def __init__(self, name: str) -> None:
        self.name = name
        self._checks: list[tuple[str, bool]] = []

    def check(self, description: str, condition: bool) -> None:
        self._checks.append((description, condition))

    def finish(self) -> None:
        passed = sum(1 for _, ok in self._checks if ok)
        total = len(self._checks)
        print(f"\n{self.name}")
        for description, ok in self._checks:
            print(f"  [{'PASS' if ok else 'FAIL'}] {description}")
        print(f"{passed}/{total} checks passed")
        sys.exit(0 if passed == total else 1)


def run_scan(*args: str) -> tuple[int, str]:
    """Invoke `vigilml scan <args>` in-process and return (exit_code, output)."""
    runner = CliRunner()
    result = runner.invoke(vigilml_main, ["scan", *args])
    return result.exit_code, result.output


def run_scan_json(*args: str) -> tuple[int, dict[str, Any]]:
    """Invoke `vigilml scan <args> --json` and return (exit_code, parsed payload)."""
    exit_code, output = run_scan(*args, "--json")
    return exit_code, json.loads(output)
