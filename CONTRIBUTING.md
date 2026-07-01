# Contributing to VigilML

## Setup

```bash
git clone https://github.com/vigilml-ai/vigilml.git
cd vigilml
python3.11 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running tests

```bash
# Unit tests
pytest tests/unit/ -v

# Lint
ruff check vigilml/ tests/

# Type checking
mypy vigilml/
```

All three must pass before opening a pull request.

## Code standards

- Python 3.10+ — use `match/case`, union types (`X | Y`), `tomllib`
- Type hints are required on every function signature
- `ruff` is the formatter and linter — run it before committing
- Every new scanner rule or detection path needs unit tests

## Reporting a false positive

Open a GitHub issue and include:

- The file type (e.g. `.py`, `.ipynb`, `requirements.txt`)
- The finding type (e.g. `openai-api-key`, `unsafe-pickle-file`)
- A minimal redacted example that triggers the false positive

We treat false positives as bugs. Precision matters more than recall at this stage.

## Adding a new detection rule

Each scanner is self-contained in [vigilml/scanner/](vigilml/scanner/). To add a rule:

1. Add your pattern or logic to the relevant file in `vigilml/scanner/`
2. Write unit tests in `tests/unit/` covering the true-positive and false-positive cases
3. Add a `Finding` with `rule`, `severity`, `file`, `line`, `message`, and `remediation` fields
4. Update `docs/DECISIONS.md` if you made a non-obvious choice (regex trade-offs, severity rationale, etc.)

Do not add new core dependencies without first opening an issue to discuss — see `docs/DECISIONS.md` for the reasoning behind the current minimal dependency set.
