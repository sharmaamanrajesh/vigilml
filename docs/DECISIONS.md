# VigilML — Decision Log

> Every non-obvious technical or product decision is logged here.
> Claude Code reads this before making decisions.
> Format: ADR-NNN, date, decision, rationale, consequences.
> Full technical architecture is in docs/ARCHITECTURE.md.

---

## How to add a decision

When Claude Code makes a non-obvious choice, it adds an entry here:

```
## ADR-NNN — [Short title]
**Date:** YYYY-MM-DD
**Decision:** [What was decided]
**Rationale:** [Why — what alternatives were considered]
**Consequences:** [What this means for future code]
```

---

## ADR-001 — vigilml as the PyPI and CLI name

**Date:** 2025-06-24
**Decision:** The PyPI package name, CLI command, and GitHub org are all `vigilml`.
**Rationale:** Matches the product domain (vigilml.ai). Short enough to type in a terminal.
Distinctive enough that `pip install vigilml` is unambiguous.
**Consequences:** All internal imports use `vigilml.*`. The CLI entrypoint in
pyproject.toml points to `vigilml.cli:main`.

---

## ADR-002 — MIT licence for the CLI

**Date:** 2025-06-24
**Decision:** Release the CLI under MIT licence.
**Rationale:** Maximum adoption for a developer tool. The moat is not in the
CLI code — it is in the team dashboard (Phase 2) and the malicious-model
database (Phase 3), which are proprietary. Open-sourcing the CLI drives
installs, trust, and community contributions to the rule set.
**Consequences:** The `LICENSE` file must be MIT. The team SaaS and enterprise
layers are separate, proprietary products not in this repo.

---

## ADR-003 — Only exact `==` pins are checked against OSV.dev

**Date:** 2026-06-30
**Decision:** `vigilml/scanner/dependencies.py` only queries OSV.dev for
packages pinned with `==` (or conda's bare `=`). Range specifiers
(`>=`, `<=`, `~=`, `!=`, bare `>`/`<`) and fully unpinned packages are
skipped entirely — never treated as if the bound were the installed version.
**Rationale:** Found while testing the CLI end-to-end against
`tests/fixtures/clean_project/requirements.txt`, which pins `torch>=2.2.0`.
The scanner was extracting "2.2.0" from the `>=` bound and querying OSV.dev
as if that were the exact installed version, producing dozens of false
positives on a fixture AGENTS.md explicitly requires to have zero findings.
Per CLAUDE.md, false positives are worse than false negatives at this stage.
**Consequences:** A `requirements.txt`/`pyproject.toml` using range
specifiers gets no CVE coverage from this scanner until pinned exactly.
This is a known gap, not a bug — there's no way to know the resolved
version without actually installing the environment.

---

## ADR-004 — PyYAML for `.vigilml.yml` config loading

**Date:** 2026-06-30
**Decision:** Added `pyyaml>=6.0` to core dependencies for `vigilml/utils/config.py`.
**Rationale:** `.vigilml.yml` has a nested schema (dicts of dicts, booleans,
lists of dicts for the `ignore` entries) — unlike `environment.yml`'s narrow
list-only structure (hand-parsed in `dependencies.py`), this isn't reasonably
hand-rollable without real risk of subtle bugs on edge cases. PyYAML is the
de facto standard YAML library and the smallest reasonable addition. Switching
`.vigilml.yml` to TOML (reusing `tomllib`) was considered but rejected — it
would mean renaming and rewriting the config file format, a bigger and
less obviously justified change than adding one well-known dependency.
**Consequences:** Core deps are now click/rich/requests/pyyaml/tomllib —
update this list and CLAUDE.md's "Allowed" dependency table if it drifts
further.

---

_New decisions are added above this line._
