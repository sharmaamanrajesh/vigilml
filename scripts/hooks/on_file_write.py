#!/usr/bin/env python3
"""
VigilML Hook Dispatcher — on_file_write.py

Triggered by Claude Code's PostToolUse hook every time a file is written.
Maps the written file path to the relevant agents and runs them automatically.

Claude Code passes the written file path as the first argument.
Exit code 0 = all triggered agents passed.
Exit code 1 = one or more agents failed (Claude Code sees this and stops).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent

# ── Agent trigger map ────────────────────────────────────────────────────────
# Maps glob patterns to a list of (agent_script, reason) tuples.
# When a written file matches a pattern, those agents run automatically.

TRIGGER_MAP: list[tuple[str, list[tuple[str, str]]]] = [
    # Credential scanner touched → run careless engineer + clean project agents
    (
        "vigilml/scanner/credentials.py",
        [
            ("tests/agents/agent_careless_engineer.py",
             "credential scanner changed — validating all credential detections"),
            ("tests/agents/agent_clean_project.py",
             "credential scanner changed — checking for false positive regressions"),
            ("tests/agents/agent_notebook_specialist.py",
             "credential scanner changed — re-validating notebook cell detection"),
        ],
    ),

    # Model file scanner touched → run careless engineer + notebook agents
    (
        "vigilml/scanner/model_files.py",
        [
            ("tests/agents/agent_careless_engineer.py",
             "model file scanner changed — validating pickle and torch.load detection"),
            ("tests/agents/agent_notebook_specialist.py",
             "model file scanner changed — re-validating notebook scanning"),
        ],
    ),

    # Cloud scanner touched → careless engineer agent only
    (
        "vigilml/scanner/cloud.py",
        [
            ("tests/agents/agent_careless_engineer.py",
             "cloud scanner changed — validating S3 and permission detection"),
        ],
    ),

    # Dependency scanner touched → careless engineer agent only
    (
        "vigilml/scanner/dependencies.py",
        [
            ("tests/agents/agent_careless_engineer.py",
             "dependency scanner changed — validating CVE detection"),
        ],
    ),

    # File walker touched → stress tester (performance matters here)
    (
        "vigilml/utils/file_walker.py",
        [
            ("tests/agents/agent_stress_tester.py",
             "file walker changed — running performance validation"),
            ("tests/agents/agent_clean_project.py",
             "file walker changed — checking exclusion patterns still work"),
        ],
    ),

    # Config loader touched → config enforcer agent
    (
        "vigilml/utils/config.py",
        [
            ("tests/agents/agent_config_enforcer.py",
             "config loader changed — validating .vigilml.yml rule overrides"),
        ],
    ),

    # CLI entrypoint touched → CI/CD runner (exit codes, flags)
    (
        "vigilml/cli.py",
        [
            ("tests/agents/agent_cicd_runner.py",
             "CLI entrypoint changed — validating flags, exit codes, JSON output"),
            ("tests/agents/agent_careless_engineer.py",
             "CLI entrypoint changed — end-to-end smoke test"),
        ],
    ),

    # Output renderers touched → CI/CD runner (JSON schema, colour flags)
    (
        "vigilml/output/terminal.py",
        [
            ("tests/agents/agent_cicd_runner.py",
             "terminal output changed — validating --no-colour and --quiet flags"),
        ],
    ),
    (
        "vigilml/output/json_output.py",
        [
            ("tests/agents/agent_cicd_runner.py",
             "JSON output changed — validating schema and stdout cleanliness"),
        ],
    ),

    # Any scanner file touched → always run clean project (false positive guard)
    (
        "vigilml/scanner/",
        [
            ("tests/agents/agent_clean_project.py",
             "scanner directory changed — false positive guard always runs"),
        ],
    ),

    # pyproject.toml touched → stress tester (dependency changes can affect perf)
    (
        "pyproject.toml",
        [
            ("tests/agents/agent_stress_tester.py",
             "dependencies changed — re-running performance validation"),
        ],
    ),
]


def find_triggered_agents(written_path: str) -> list[tuple[str, str]]:
    """Return deduplicated list of (agent_script, reason) for a written file."""
    p = Path(written_path)
    # Normalise to relative path from project root
    try:
        rel = p.relative_to(ROOT)
    except ValueError:
        rel = p

    rel_str = str(rel).replace("\\", "/")
    triggered: dict[str, str] = {}  # script → reason (dedup by script)

    for pattern, agents in TRIGGER_MAP:
        if rel_str == pattern or rel_str.startswith(pattern):
            for script, reason in agents:
                if script not in triggered:
                    triggered[script] = reason

    return list(triggered.items())


def run_agent(script: str, reason: str) -> bool:
    """Run a single agent script. Returns True if it passed."""
    script_path = ROOT / script
    if not script_path.exists():
        print(f"  [SKIP] {script} — not yet implemented", flush=True)
        return True  # don't block on unimplemented agents

    print(f"\n  [AUTO-AGENT] {reason}", flush=True)
    print(f"  Running: {script}", flush=True)

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=False,  # let output stream to terminal
        timeout=120,
    )

    if result.returncode == 0:
        print(f"  [PASS] {Path(script).stem}", flush=True)
        return True
    else:
        print(f"  [FAIL] {Path(script).stem} — agent failed, review output above", flush=True)
        return False


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit(0)  # no path provided — do nothing

    written_path = sys.argv[1]
    triggered = find_triggered_agents(written_path)

    if not triggered:
        sys.exit(0)  # no agents triggered for this file

    print(f"\n{'─' * 60}", flush=True)
    print(f"  VigilML auto-agents triggered by: {Path(written_path).name}", flush=True)
    print(f"  {len(triggered)} agent(s) queued", flush=True)
    print(f"{'─' * 60}", flush=True)

    all_passed = True
    for script, reason in triggered:
        passed = run_agent(script, reason)
        if not passed:
            all_passed = False

    print(f"\n{'─' * 60}", flush=True)
    if all_passed:
        print("  All auto-agents PASSED — safe to continue", flush=True)
    else:
        print("  AGENT FAILURE — fix the issues above before proceeding", flush=True)
        print("  Claude Code has been stopped. Review agent output.", flush=True)
    print(f"{'─' * 60}\n", flush=True)

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
