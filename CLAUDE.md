# VigilML — Claude Code Master Context

> This file is read by Claude Code at the start of every session.
> Keep it updated. It is the single source of truth for the project.

---

## Product Identity

| Field        | Value                                      |
|--------------|--------------------------------------------|
| Product name | VigilML                                    |
| Domain       | vigilml.ai                                 |
| PyPI handle  | vigilml                                    |
| CLI command  | `vigilml scan .`                           |
| Tagline      | Security for the AI development lifecycle  |
| Stage        | Pre-seed MVP — building Layer 1 (CLI only) |
| Stack        | Python 3.10+, Click, Rich, OSV.dev API     |
| IDE          | VS Code + Claude Code extension            |

---

## What This Product Does

VigilML is a developer-first security CLI for ML engineers.
It scans ML projects and catches AI-specific vulnerabilities before they ship:

1. Hardcoded API keys in `.py` and `.ipynb` files
2. Unsafe model deserialisation (`.pkl`, `.joblib`, unsafe `torch.load()`)
3. Cloud misconfigurations (public S3 writes, world-readable permissions)
4. ML dependency CVEs via OSV.dev (numpy, torch, transformers, etc.)

**It is NOT a web app, a dashboard, or an enterprise platform yet.**
Build only the CLI in this phase. See docs/PRD.md for full scope.

---

## Current Phase

**Phase 1 — CLI MVP (Days 1–90)**

Gate to Phase 2: 1,000 installs AND 3 companies with 5+ engineers using it.
Do not build Phase 2 features until this gate is confirmed.

---

## Project Structure

```
vigilml/
├── CLAUDE.md                  ← You are here — read this first every session
├── PROGRESS.md                ← Updated after every work session
├── AGENTS.md                  ← Agent definitions and test instructions
├── docs/
│   ├── PRD.md                 ← Full product requirements document
│   ├── ARCHITECTURE.md        ← Technical design decisions
│   └── DECISIONS.md           ← ADR log — why we chose X over Y
├── vigilml/                   ← Main Python package
│   ├── __init__.py
│   ├── cli.py                 ← Click CLI entrypoint
│   ├── scanner/
│   │   ├── __init__.py
│   │   ├── credentials.py     ← API key / token detection
│   │   ├── model_files.py     ← Pickle / unsafe deserialisation
│   │   ├── cloud.py           ← S3 / GCS misconfiguration
│   │   └── dependencies.py    ← OSV.dev CVE checker
│   ├── output/
│   │   ├── __init__.py
│   │   ├── terminal.py        ← Rich terminal output renderer
│   │   └── json_output.py     ← JSON output formatter
│   └── utils/
│       ├── __init__.py
│       ├── file_walker.py     ← File system traversal
│       └── config.py          ← .vigilml.yml config loader
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── fixtures/
│   └── agents/
├── scripts/
├── .github/workflows/
├── .vscode/                   ← VS Code workspace config (pre-configured)
│   ├── settings.json
│   ├── extensions.json
│   ├── launch.json
│   └── tasks.json
├── .claude/
│   ├── settings.json
│   └── commands/
├── pyproject.toml
├── .vigilml.yml
└── README.md
```

---

## Automatic Hooks — What Runs Without Being Asked

Hooks fire automatically. Claude Code does NOT need to trigger agents manually.

### PostToolUse — file write hook
Every time Claude Code writes a file, `scripts/hooks/on_file_write.py` fires:

| File written | Agents that auto-run |
|---|---|
| `vigilml/scanner/credentials.py` | Careless Engineer + Clean Project + Notebook Specialist |
| `vigilml/scanner/model_files.py` | Careless Engineer + Notebook Specialist |
| `vigilml/scanner/cloud.py` | Careless Engineer |
| `vigilml/scanner/dependencies.py` | Careless Engineer |
| `vigilml/utils/file_walker.py` | Stress Tester + Clean Project |
| `vigilml/utils/config.py` | Config Enforcer |
| `vigilml/cli.py` | CI/CD Runner + Careless Engineer |
| `vigilml/output/terminal.py` | CI/CD Runner |
| `vigilml/output/json_output.py` | CI/CD Runner |
| Any file in `vigilml/scanner/` | Clean Project (false positive guard — always) |
| `pyproject.toml` | Stress Tester |

### PostToolUse — bash command hook
Certain bash commands trigger agents via `scripts/hooks/on_bash_run.py`:

| Command | Agents that auto-run |
|---|---|
| `pip install -e .` | Careless Engineer + Clean Project |
| `setup_all_fixtures.py` | Careless Engineer + Clean Project |
| `pytest tests/` | CI/CD Runner |
| `benchmark.py` | Stress Tester |

### Pre-commit git hook
Before any git commit, `scripts/hooks/pre_commit_check.py` runs:
ruff + mypy + unit tests + targeted agents for changed files.
Commit is blocked if any check fails.

### Rules for Claude Code
- Do NOT manually run agents after writing a file — the hook does it
- If an agent fails after a file write, fix the issue before writing more files
- If a hook blocks you and an override is genuinely needed, say so explicitly

---

## VS Code — Key Shortcuts for This Project

| Action | Shortcut |
|--------|----------|
| Run a task (lint, test, agents) | Ctrl+Shift+P → Tasks: Run Task |
| Open debug panel | Ctrl+Shift+D |
| Run unit tests | Ctrl+Shift+P → Tasks: Run Task → Unit tests |
| Run all agents | Ctrl+Shift+P → Tasks: Run Task → Run all agents |
| Full check (lint+types+tests) | Ctrl+Shift+P → Tasks: Run Task → Full check |
| Debug CLI on fixtures | Ctrl+Shift+D → select config → F5 |
| Select Python interpreter | Ctrl+Shift+P → Python: Select Interpreter → .venv |

---

## Coding Rules — Read Before Writing Any Code

### Non-negotiable standards
- Python 3.10+ only — use match/case, union types (X | Y), tomllib
- Type hints on every function signature — no exceptions
- Docstrings on every public function and class
- Maximum line length: 100 characters
- All new code must have tests before the PR is merged
- Never hardcode paths — use pathlib.Path everywhere
- Never use print() — use the Rich console or Python logging

### File scanning rules
- Always use generators for file walking — never load all files into memory
- Respect .gitignore patterns when scanning
- Exclude: .git/, __pycache__/, *.pyc, node_modules/, .venv/, venv/, env/
- Notebook scanning: parse .ipynb as JSON, scan source fields of code cells only

### Security scanner rules
- False positives are worse than false negatives at this stage
- Every finding must have: file path, line number, severity, finding type, remediation
- Severity levels: CRITICAL / HIGH / MEDIUM / LOW
- Credential findings: show first 4 chars, redact the rest as ****
- Never log or store the full value of a detected credential anywhere

### Output rules
- Exit code 0 = no findings, exit code 1 = findings present
- --json outputs valid JSON to stdout, nothing else
- --no-colour for CI/CD environments
- --quiet suppresses everything except the summary line

### Dependency rules
- Core deps must stay minimal — target < 5
- Allowed: click, rich, requests, tomllib (stdlib 3.11+)
- No pandas, numpy, or ML libraries in the scanner itself
- Add new deps only with justification in docs/DECISIONS.md

---

## Commands Claude Code Should Know

```bash
# Setup (run once)
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
python tests/fixtures/setup_all_fixtures.py

# Daily workflow
pytest tests/unit/ -v
ruff check vigilml/ tests/
mypy vigilml/
vigilml scan .

# After completing a feature
python tests/agents/run_all_agents.py --update-progress

# CI simulation
ruff check vigilml/ tests/ && mypy vigilml/ && pytest tests/ -v
```

---

## What Claude Code Should Never Do

- Build any web UI, dashboard, or API server
- Add authentication or user accounts
- Connect to any database
- Add Slack, email, or webhook integrations
- Expand scope beyond Phase 1 CLI features
- Install packages not in pyproject.toml without asking
- Commit directly to main
- Modify .vscode/ files

---

## Definition of Done — Per Feature

- [ ] Implementation matches spec in docs/PRD.md
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Relevant agent test run and logged in PROGRESS.md
- [ ] PROGRESS.md updated
- [ ] DECISIONS.md updated if non-obvious choices made
- [ ] Ruff and mypy pass with zero errors
- [ ] Scan of 1,000 files completes in under 3 seconds

---

## Key Resources

- OSV.dev API: https://osv.dev/docs/
- Rich: https://rich.readthedocs.io/
- Click: https://click.palletsprojects.com/
- PRD: docs/PRD.md
- Architecture: docs/ARCHITECTURE.md
