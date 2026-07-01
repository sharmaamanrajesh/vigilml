# VigilML — Architecture & Technical Decisions

> Every non-obvious technical choice is logged here with the date and reasoning.
> Claude Code reads this before making architectural decisions.

---

## JSON output schema

Every finding in `--json` mode must conform to this schema.
Claude Code must not deviate from this without updating this document.

```json
{
  "version": "0.1.0",
  "scanned_at": "2025-06-24T10:30:00Z",
  "scan_path": "/path/to/project",
  "duration_seconds": 2.3,
  "total_findings": 5,
  "summary": {
    "CRITICAL": 1,
    "HIGH": 2,
    "MEDIUM": 2,
    "LOW": 0,
    "ignored": 1
  },
  "findings": [
    {
      "id": "CRED-001",
      "type": "credential",
      "severity": "CRITICAL",
      "file": "train.py",
      "line": 7,
      "column": 14,
      "rule": "openai-api-key",
      "message": "OpenAI API key detected",
      "detail": "Found pattern matching OpenAI API key: sk-****...****",
      "remediation": "Remove the key from source code. Store it in an environment variable and load with os.getenv('OPENAI_API_KEY'). Add this file to .gitignore if it must contain secrets.",
      "docs_url": "https://docs.vigilml.ai/rules/cred-001"
    }
  ],
  "ignored_findings": [
    {
      "rule": "credentials",
      "file": "scripts/generate_keys.py",
      "reason": "This file generates test keys — not real credentials"
    }
  ]
}
```

---

## Severity definitions

| Level | Definition | Example |
|-------|-----------|---------|
| CRITICAL | Exposed secret that is active and exploitable right now | Real API key in a public repo |
| HIGH | Unsafe pattern that is very likely to cause a breach | Pickle file in the project root |
| MEDIUM | Misconfiguration that creates meaningful risk | Public S3 write without ACL check |
| LOW | Best practice violation with limited immediate impact | Missing `weights_only` on a local-only load |

---

## ADR-001 — Use Click over Typer or Argparse

**Date:** Project start
**Decision:** Click
**Rationale:** Click is battle-tested, has excellent help text generation,
and the VigilML team has more experience with it. Typer adds a FastAPI/Pydantic
dependency chain that is unnecessary. Argparse produces inferior UX.
**Consequence:** All CLI entrypoints use Click decorators.

---

## ADR-002 — Use Rich for terminal output

**Date:** Project start
**Decision:** Rich
**Rationale:** The terminal output is a core product differentiator —
it needs to be screenshot-worthy. Rich provides tables, colour,
panels, and progress bars out of the box with minimal code.
**Consequence:** Never use `print()` in the codebase. Import `console` from
`vigilml.output.terminal` and use `console.print()` everywhere.

---

## ADR-003 — OSV.dev over Snyk API or Safety DB for CVE data

**Date:** Project start
**Decision:** OSV.dev
**Rationale:** OSV.dev is free with no API key required, has excellent
Python package coverage, and is maintained by Google. The Safety DB
requires a paid API key. Snyk's API is not intended for this use case.
**Consequence:** Network calls to `api.osv.dev` for dependency checks.
Wrap in a timeout (5 seconds) and degrade gracefully if the API is down.

---

## ADR-004 — No persistent state in the CLI

**Date:** Project start
**Decision:** The CLI is stateless — no database, no config written to disk,
no telemetry without explicit opt-in.
**Rationale:** Stateless tools are easier to trust, easier to install in CI/CD,
and have no privacy concerns. State (team dashboard, drift detection) belongs
in the Phase 2 SaaS layer, not the CLI.
**Consequence:** The CLI reads `.vigilml.yml` if it exists, but writes nothing.

---

## ADR-005 — Generator-based file walker

**Date:** Project start
**Decision:** All file scanning uses Python generators, not lists.
**Rationale:** Large ML repos can have tens of thousands of files.
Loading all paths into memory before scanning would cause memory spikes.
Generators allow streaming processing with constant memory overhead.
**Consequence:** `file_walker.py` yields `Path` objects. Never call `list()`
on the walker output in the hot path.

---

## ADR-006 — Notebook scanning: source fields only

**Date:** Project start
**Decision:** When scanning `.ipynb` files, only scan the `source` field
of each cell. Do not scan `outputs`, `metadata`, or `execution_count`.
**Rationale:** Output cells may contain rendered HTML, base64 images,
or data that looks like credentials but isn't. Scanning outputs would
create massive false positive rates. Metadata is not user-written code.
**Consequence:** The notebook scanner JSON-parses the `.ipynb` file and
iterates over `cells[*].source` only. Cell type must be `code`.

---

## ADR-007 — Credential redaction in output

**Date:** Project start
**Decision:** Show the first 4 characters of a detected credential and
replace the rest with `****`. Never log the full value anywhere.
**Rationale:** The tool needs to show enough context for the engineer to
identify which credential was found, but must not create a second
exposure vector by printing the full key to the terminal or logs.
**Consequence:** All credential pattern matchers must apply this redaction
before passing the finding to the output layer. The raw value must
never be stored in the `Finding` dataclass.
