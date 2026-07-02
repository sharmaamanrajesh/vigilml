# Contributing to VigilML

## Setup

```bash
git clone https://github.com/sharmaamanrajesh/vigilml.git
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

## Pull requests

- Keep PRs focused — one fix or one feature per PR. Unrelated cleanup
  makes review harder and slows everything down.
- Use a clear, descriptive title (e.g. `fix: tighten .run() LLM-sink
  pattern`, not `update stuff`).
- Reference the issue you're addressing, if one exists.
- Make sure lint, type checks, and the full test suite pass locally
  before requesting review (see *Running tests* above).
- A maintainer will review and may ask for changes before merging.
  Force-pushing to update a PR in response to review is fine; please
  don't open a second PR for the same change.

## Code of conduct

Be respectful and constructive. Disagree on ideas, not people. Assume
good faith, and give feedback the way you'd want to receive it.
Harassment or personal attacks of any kind will not be tolerated —
maintainers may close issues/PRs or block participation from anyone
who violates this.

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

## Licensing

VigilML is licensed under the [MIT License](LICENSE). By submitting a
pull request, you agree that your contribution is provided under the
same license.
