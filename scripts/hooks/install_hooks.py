#!/usr/bin/env python3
"""
VigilML Hook Installer

Wires up all hooks in one command:
  1. Git pre-commit hook (runs on every git commit)
  2. Validates Claude Code hooks config is in place
  3. Confirms all hook scripts are executable

Usage:
    python scripts/hooks/install_hooks.py

Run this once after cloning the repo, after pip install -e ".[dev]".
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent.parent


def install_git_hook() -> bool:
    """Install the pre-commit git hook."""
    hooks_dir = ROOT / ".git" / "hooks"
    if not hooks_dir.exists():
        print("  [SKIP] .git/hooks not found — is this a git repo?")
        print("         Run: git init && python scripts/hooks/install_hooks.py")
        return False

    pre_commit = hooks_dir / "pre-commit"
    source = ROOT / "scripts" / "hooks" / "pre-commit.sh"

    # Write the hook
    pre_commit.write_text(
        f"#!/usr/bin/env bash\n"
        f'exec "{sys.executable}" '
        f'"{ROOT / "scripts" / "hooks" / "pre_commit_check.py"}"\n'
    )

    # Make executable
    pre_commit.chmod(
        pre_commit.stat().st_mode
        | stat.S_IXUSR
        | stat.S_IXGRP
        | stat.S_IXOTH
    )

    print(f"  [OK] Git pre-commit hook installed → .git/hooks/pre-commit")
    return True


def validate_claude_hooks() -> bool:
    """Check Claude Code hooks config exists and is valid JSON."""
    import json

    hooks_file = ROOT / ".claude" / "hooks" / "hooks.json"
    if not hooks_file.exists():
        print(f"  [FAIL] Claude Code hooks config missing: {hooks_file}")
        return False

    try:
        data = json.loads(hooks_file.read_text())
        hook_count = len(data.get("hooks", {}).get("PostToolUse", []))
        print(f"  [OK] Claude Code hooks config valid ({hook_count} PostToolUse hooks)")
        return True
    except json.JSONDecodeError as e:
        print(f"  [FAIL] Claude Code hooks config invalid JSON: {e}")
        return False


def make_scripts_executable() -> bool:
    """Ensure all hook scripts are executable."""
    scripts = [
        ROOT / "scripts" / "hooks" / "on_file_write.py",
        ROOT / "scripts" / "hooks" / "on_bash_run.py",
        ROOT / "scripts" / "hooks" / "pre_commit_check.py",
        ROOT / "tests" / "agents" / "run_all_agents.py",
        ROOT / "tests" / "fixtures" / "setup_all_fixtures.py",
    ]
    for script in scripts:
        if script.exists():
            script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)
            print(f"  [OK] Executable: {script.relative_to(ROOT)}")
        else:
            print(f"  [--] Not yet created: {script.relative_to(ROOT)}")
    return True


def check_venv() -> bool:
    """Warn if not running inside a virtual environment."""
    in_venv = (
        hasattr(sys, "real_prefix")
        or (hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix)
    )
    if in_venv:
        print(f"  [OK] Virtual environment active: {sys.prefix}")
        return True
    else:
        print("  [WARN] No virtual environment active.")
        print("         Run: python -m venv .venv && source .venv/bin/activate")
        return False


def check_dependencies() -> bool:
    """Check that required tools are installed."""
    tools = ["ruff", "mypy", "pytest"]
    all_ok = True
    for tool in tools:
        result = subprocess.run(
            [tool, "--version"],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            version = result.stdout.strip().split("\n")[0]
            print(f"  [OK] {tool}: {version}")
        else:
            print(f"  [FAIL] {tool} not found — run: pip install -e '.[dev]'")
            all_ok = False
    return all_ok


def main() -> None:
    print(f"\n{'═' * 60}")
    print("  VigilML Hook Installer")
    print(f"{'═' * 60}\n")

    results = {
        "Virtual environment": check_venv(),
        "Dependencies installed": check_dependencies(),
        "Hook scripts executable": make_scripts_executable(),
        "Git pre-commit hook": install_git_hook(),
        "Claude Code hooks config": validate_claude_hooks(),
    }

    print(f"\n{'═' * 60}")
    print("  Installation summary:")
    all_ok = True
    for name, ok in results.items():
        icon = "✓" if ok else "✗"
        print(f"  {icon}  {name}")
        if not ok:
            all_ok = False

    print(f"{'═' * 60}")
    if all_ok:
        print("\n  All hooks installed. You're ready to build.\n")
        print("  What happens now automatically:")
        print("  · Every file Claude Code writes → relevant agents run")
        print("  · Every git commit → ruff + mypy + unit tests + targeted agents")
        print("  · pip install -e . → smoke test agents run")
        print("  · setup_all_fixtures.py → fixture validation agents run\n")
    else:
        print("\n  Fix the issues above, then re-run this script.\n")

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
