#!/usr/bin/env bash
# VigilML git pre-commit hook
# Installed by: python scripts/hooks/install_hooks.py
# Runs: ruff, mypy, unit tests, and targeted agents before every commit.

set -e

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

# Activate venv if it exists
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
elif [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

echo ""
echo "Running VigilML pre-commit gate..."
python scripts/hooks/pre_commit_check.py
