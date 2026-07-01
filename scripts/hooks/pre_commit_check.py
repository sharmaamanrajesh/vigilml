#!/usr/bin/env python3
"""
VigilML Pre-Commit Hook — pre_commit_check.py

Runs before Claude Code executes any git commit.
Enforces: ruff passes, mypy passes, unit tests pass,
and the agents relevant to changed files all pass.

Exit code 0 = commit allowed.
Exit code 1 = commit blocked — Claude Code sees this and stops.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent


def run(cmd: list[str], label: str) -> bool:
    """Run a command and return True if it succeeded."""
    print(f"\n  [{label}]", flush=True)
    result = subprocess.run(cmd, cwd=ROOT, capture_output=False)
    return result.returncode == 0


def get_changed_files() -> list[str]:
    """Get list of staged files from git."""
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return [f.strip() for f in result.stdout.strip().splitlines() if f.strip()]


def main() -> None:
    print(f"\n{'═' * 60}", flush=True)
    print("  VigilML pre-commit gate", flush=True)
    print(f"{'═' * 60}", flush=True)

    changed = get_changed_files()
    if changed:
        print(f"  Changed files: {', '.join(Path(f).name for f in changed)}", flush=True)

    checks: list[tuple[str, bool]] = []

    # 1. Ruff lint
    ruff_ok = run(["ruff", "check", "vigilml/", "tests/"], "RUFF LINT")
    checks.append(("Ruff lint", ruff_ok))

    # 2. Mypy type check
    mypy_ok = run(["mypy", "vigilml/"], "MYPY")
    checks.append(("Mypy type check", mypy_ok))

    # 3. Unit tests (always)
    pytest_ok = run(
        ["pytest", "tests/unit/", "-v", "--tb=short", "-q"],
        "UNIT TESTS",
    )
    checks.append(("Unit tests", pytest_ok))

    # 4. Targeted agents based on changed files
    agent_map = {
        "credentials.py":   ["tests/agents/agent_careless_engineer.py",
                              "tests/agents/agent_clean_project.py",
                              "tests/agents/agent_notebook_specialist.py"],
        "model_files.py":   ["tests/agents/agent_careless_engineer.py",
                              "tests/agents/agent_notebook_specialist.py"],
        "cloud.py":         ["tests/agents/agent_careless_engineer.py"],
        "dependencies.py":  ["tests/agents/agent_careless_engineer.py"],
        "file_walker.py":   ["tests/agents/agent_stress_tester.py",
                              "tests/agents/agent_clean_project.py"],
        "config.py":        ["tests/agents/agent_config_enforcer.py"],
        "cli.py":           ["tests/agents/agent_cicd_runner.py",
                              "tests/agents/agent_careless_engineer.py"],
        "terminal.py":      ["tests/agents/agent_cicd_runner.py"],
        "json_output.py":   ["tests/agents/agent_cicd_runner.py"],
    }

    agents_to_run: dict[str, str] = {}
    for changed_file in changed:
        fname = Path(changed_file).name
        if fname in agent_map:
            for agent in agent_map[fname]:
                agents_to_run[agent] = fname

    if agents_to_run:
        print(f"\n  Running {len(agents_to_run)} targeted agent(s) for changed files...",
              flush=True)
        for agent_script, triggered_by in agents_to_run.items():
            agent_path = ROOT / agent_script
            if not agent_path.exists():
                print(f"  [SKIP] {agent_script} — not yet implemented", flush=True)
                checks.append((f"Agent: {Path(agent_script).stem}", True))
                continue

            print(f"\n  [AGENT] {Path(agent_script).stem} (triggered by {triggered_by})",
                  flush=True)
            result = subprocess.run(
                [sys.executable, str(agent_path)],
                cwd=ROOT,
                capture_output=False,
            )
            passed = result.returncode == 0
            checks.append((f"Agent: {Path(agent_script).stem}", passed))
    else:
        print("  No targeted agents for these files — skipping agent step", flush=True)

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f"\n{'═' * 60}", flush=True)
    print("  Pre-commit gate results:", flush=True)
    all_passed = True
    for name, passed in checks:
        icon = "✓" if passed else "✗"
        print(f"  {icon}  {name}", flush=True)
        if not passed:
            all_passed = False

    print(f"{'═' * 60}", flush=True)
    if all_passed:
        print("  GATE PASSED — commit allowed\n", flush=True)
    else:
        print("  GATE FAILED — commit blocked", flush=True)
        print("  Fix all failures above, then try again.\n", flush=True)

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
