#!/usr/bin/env python3
"""
VigilML Agent Test Runner
Runs all defined agents and reports results.
Claude Code runs this after completing each feature.
"""

from __future__ import annotations

import argparse
import datetime
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class AgentResult:
    name: str
    passed: bool
    checks_passed: int
    checks_total: int
    duration_seconds: float
    output: str
    error: str = ""


@dataclass
class AgentSuite:
    results: list[AgentResult] = field(default_factory=list)

    @property
    def all_passed(self) -> bool:
        return all(r.passed for r in self.results)

    @property
    def total_checks(self) -> int:
        return sum(r.checks_total for r in self.results)

    @property
    def passed_checks(self) -> int:
        return sum(r.checks_passed for r in self.results)


AGENTS = [
    {
        "name": "Careless ML Engineer",
        "script": "tests/agents/agent_careless_engineer.py",
        "description": "Validates credential scanner and pickle detector",
    },
    {
        "name": "Clean Project Validator",
        "script": "tests/agents/agent_clean_project.py",
        "description": "Validates zero false positives on clean code",
    },
    {
        "name": "CI/CD Pipeline Runner",
        "script": "tests/agents/agent_cicd_runner.py",
        "description": "Validates JSON output, exit codes, --no-colour flag",
    },
    {
        "name": "Large Repo Stress Tester",
        "script": "tests/agents/agent_stress_tester.py",
        "description": "Validates performance on 5,000-file repos",
    },
    {
        "name": "Config Enforcer",
        "script": "tests/agents/agent_config_enforcer.py",
        "description": "Validates .vigilml.yml config loading and rule overrides",
    },
    {
        "name": "Notebook Specialist",
        "script": "tests/agents/agent_notebook_specialist.py",
        "description": "Validates .ipynb scanning with cell-level reporting",
    },
]


def run_agent(agent: dict[str, str]) -> AgentResult:
    """Run a single agent script and capture results."""
    import time

    script = Path(agent["script"])
    start = time.time()

    if not script.exists():
        return AgentResult(
            name=agent["name"],
            passed=False,
            checks_passed=0,
            checks_total=0,
            duration_seconds=0,
            output="",
            error=f"Agent script not found: {script}\nCreate it following the template in AGENTS.md",
        )

    try:
        result = subprocess.run(
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        duration = time.time() - start

        passed = result.returncode == 0
        # Parse check counts from output (agents print "X/Y checks passed")
        checks_passed, checks_total = _parse_check_counts(result.stdout)

        return AgentResult(
            name=agent["name"],
            passed=passed,
            checks_passed=checks_passed,
            checks_total=checks_total,
            duration_seconds=duration,
            output=result.stdout,
            error=result.stderr if not passed else "",
        )
    except subprocess.TimeoutExpired:
        return AgentResult(
            name=agent["name"],
            passed=False,
            checks_passed=0,
            checks_total=0,
            duration_seconds=120,
            output="",
            error="Agent timed out after 120 seconds",
        )
    except Exception as e:
        return AgentResult(
            name=agent["name"],
            passed=False,
            checks_passed=0,
            checks_total=0,
            duration_seconds=0,
            output="",
            error=str(e),
        )


def _parse_check_counts(output: str) -> tuple[int, int]:
    """Parse 'X/Y checks passed' from agent output."""
    import re
    match = re.search(r"(\d+)/(\d+) checks", output)
    if match:
        return int(match.group(1)), int(match.group(2))
    return 0, 0


def print_results(suite: AgentSuite) -> None:
    """Print a formatted results table."""
    width = 70
    print("\n" + "=" * width)
    print("  VigilML Agent Test Suite")
    print("=" * width)

    for result in suite.results:
        status = "PASS" if result.passed else "FAIL"
        checks = f"({result.checks_passed}/{result.checks_total} checks)"
        timing = f"{result.duration_seconds:.1f}s"
        name_col = f"  {result.name}"
        print(f"{name_col:<42} {status:<6} {checks:<18} {timing}")

        if not result.passed and result.error:
            for line in result.error.strip().split("\n")[:3]:
                print(f"    ERROR: {line}")

    print("=" * width)
    total_status = "All agents PASSED" if suite.all_passed else "AGENTS FAILED"
    print(f"  {total_status} — {suite.passed_checks}/{suite.total_checks} total checks")
    print("=" * width + "\n")


def update_progress(suite: AgentSuite) -> None:
    """Append agent results to PROGRESS.md."""
    progress_path = Path("PROGRESS.md")
    if not progress_path.exists():
        return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    status = "ALL PASS" if suite.all_passed else "FAILURES DETECTED"

    entry = f"\n### Agent run — {timestamp} — {status}\n"
    for result in suite.results:
        icon = "✓" if result.passed else "✗"
        entry += f"- {icon} {result.name} ({result.checks_passed}/{result.checks_total} checks)\n"

    content = progress_path.read_text()
    # Insert after the session log header
    insert_at = content.find("## Session Log")
    if insert_at != -1:
        insert_at = content.find("\n", insert_at) + 1
        content = content[:insert_at] + entry + content[insert_at:]
        progress_path.write_text(content)
        print(f"PROGRESS.md updated with agent results.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run VigilML agent tests")
    parser.add_argument(
        "--agent",
        help="Run a specific agent by name (partial match)",
        default=None,
    )
    parser.add_argument(
        "--update-progress",
        action="store_true",
        help="Update PROGRESS.md with results",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available agents",
    )
    args = parser.parse_args()

    if args.list:
        print("\nAvailable agents:")
        for agent in AGENTS:
            print(f"  - {agent['name']}: {agent['description']}")
        return

    agents_to_run = AGENTS
    if args.agent:
        agents_to_run = [
            a for a in AGENTS
            if args.agent.lower() in a["name"].lower()
        ]
        if not agents_to_run:
            print(f"No agent matching '{args.agent}' found.")
            print("Use --list to see available agents.")
            sys.exit(1)

    suite = AgentSuite()
    for agent in agents_to_run:
        print(f"  Running: {agent['name']}...", end=" ", flush=True)
        result = run_agent(agent)
        suite.results.append(result)
        print("PASS" if result.passed else "FAIL")

    print_results(suite)

    if args.update_progress:
        update_progress(suite)

    sys.exit(0 if suite.all_passed else 1)


if __name__ == "__main__":
    main()
