"""Inline suppression-comment support — `# vigilml: ignore[-start|-end|-file]`.

Shared by every scanner so all seven interpret suppression comments
identically:

- `# vigilml: ignore` on a line suppresses findings on that line only.
- `# vigilml: ignore-start` / `# vigilml: ignore-end` suppress findings on
  every line between the two markers (inclusive).
- `# vigilml: ignore-file` anywhere in a file (or, for a notebook, in any
  code cell's source) suppresses the entire file/notebook.

This is a separate, code-comment-based mechanism from `.vigilml.yml`'s
`ignore:` list (see `vigilml/utils/config.py`), which suppresses by
path+rule instead.
"""

from __future__ import annotations

import re
from typing import Any

from vigilml.scanner import Finding

_IGNORE_FILE_RE = re.compile(r"#\s*vigilml:\s*ignore-file\b")
_IGNORE_START_RE = re.compile(r"#\s*vigilml:\s*ignore-start\b")
_IGNORE_END_RE = re.compile(r"#\s*vigilml:\s*ignore-end\b")
# Negative lookahead excludes ignore-start/-end/-file from also matching
# the plain single-line form.
_IGNORE_LINE_RE = re.compile(r"#\s*vigilml:\s*ignore\b(?!-)")


def _cell_text(cell: dict[str, Any]) -> str:
    source = cell.get("source", "")
    return "".join(source) if isinstance(source, list) else source


def has_ignore_file_marker(text: str) -> bool:
    """True if `text` contains a `# vigilml: ignore-file` marker anywhere."""
    return bool(_IGNORE_FILE_RE.search(text))


def notebook_has_ignore_file_marker(notebook: dict[str, Any]) -> bool:
    """True if any code cell's source contains an `ignore-file` marker."""
    for cell in notebook.get("cells", []):
        if cell.get("cell_type") != "code":
            continue
        if has_ignore_file_marker(_cell_text(cell)):
            return True
    return False


def suppressed_lines(text: str) -> frozenset[int]:
    """Return every 1-based line number of `text` suppressed by an inline
    `# vigilml: ignore` comment or an `ignore-start`/`ignore-end` block."""
    suppressed: set[int] = set()
    in_block = False
    for line_number, line in enumerate(text.splitlines(), start=1):
        if _IGNORE_START_RE.search(line):
            in_block = True
            suppressed.add(line_number)
            continue
        if _IGNORE_END_RE.search(line):
            in_block = False
            suppressed.add(line_number)
            continue
        if in_block or _IGNORE_LINE_RE.search(line):
            suppressed.add(line_number)
    return frozenset(suppressed)


def filter_suppressed(findings: list[Finding], text: str) -> list[Finding]:
    """Drop findings whose `line` falls on a suppressed line of `text`."""
    suppressed = suppressed_lines(text)
    if not suppressed:
        return findings
    return [f for f in findings if f.line not in suppressed]


def filter_notebook_suppressed(
    findings: list[Finding],
    notebook: dict[str, Any],
    *,
    exempt_rules: frozenset[str] = frozenset(),
) -> list[Finding]:
    """Drop findings whose `(cell, line)` falls on a suppressed line of that
    cell's source.

    Findings with `cell is None` (notebook-level, not tied to any cell) or
    whose `rule` is in `exempt_rules` are always kept — `exempt_rules` is for
    scanners that also produce findings whose `line` addresses something
    other than cell *source* (e.g. `notebook_risks.py`'s cell *output*
    findings, which a source-only suppression comment cannot reach).
    """
    cell_sources: dict[int, str] = {
        cell_number: _cell_text(cell)
        for cell_number, cell in enumerate(notebook.get("cells", []), start=1)
        if cell.get("cell_type") == "code"
    }

    cache: dict[int, frozenset[int]] = {}
    kept = []
    for finding in findings:
        if finding.cell is None or finding.rule in exempt_rules:
            kept.append(finding)
            continue
        if finding.cell not in cache:
            cache[finding.cell] = suppressed_lines(cell_sources.get(finding.cell, ""))
        if finding.line not in cache[finding.cell]:
            kept.append(finding)
    return kept
