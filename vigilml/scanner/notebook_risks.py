"""Notebook-specific risk detection for `.ipynb` files only.

Unlike every other scanner in this package, this one deliberately scans
cell **outputs** as well as cell source — outputs are committed to git and
visible to anyone who views the notebook, so a credential or PII preview
that only ever appears in an output cell is a real, common leak that
`credentials.py`/`data_pipeline.py` (source-only, by design — see their own
docstrings) will never catch. Non-`.ipynb` files are always skipped.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from vigilml.scanner import Finding, Severity
from vigilml.scanner.credentials import _redact
from vigilml.scanner.credentials import _scan_line as _credential_scan_line
from vigilml.utils.file_walker import walk_files
from vigilml.utils.suppression import filter_notebook_suppressed, notebook_has_ignore_file_marker

_INCLUDE_EXTENSIONS: frozenset[str] = frozenset({".ipynb"})

# Rules produced from cell *output* text, not cell *source* — an inline
# `# vigilml: ignore` comment can only ever live in source (outputs are
# program-generated), so these are exempt from per-line/block suppression
# and can only be silenced by a whole-notebook `# vigilml: ignore-file`.
_OUTPUT_RULE_NAMES: frozenset[str] = frozenset(
    {
        "credential-in-output",
        "stack-trace-in-output",
        "pii-dataframe-in-output",
        "base64-secret-in-output",
    }
)

# (rule, severity, message, detail, remediation, line, cell)
_RawFinding = tuple[str, Severity, str, str, str, int, "int | None"]


def _as_text(value: Any) -> str:
    return "".join(value) if isinstance(value, list) else str(value)


def _cell_source_text(cell: dict[str, Any]) -> str:
    return _as_text(cell.get("source", ""))


def _cell_output_text(cell: dict[str, Any]) -> str:
    parts: list[str] = []
    for output in cell.get("outputs", []) or []:
        output_type = output.get("output_type")
        if output_type == "stream":
            parts.append(_as_text(output.get("text", "")))
        elif output_type in ("display_data", "execute_result"):
            text_plain = output.get("data", {}).get("text/plain")
            if text_plain is not None:
                parts.append(_as_text(text_plain))
        elif output_type == "error":
            traceback = output.get("traceback")
            if traceback is not None:
                parts.append(_as_text(traceback))
    return "\n".join(part for part in parts if part)


# ---------------------------------------------------------------------------
# Step 7A — cell OUTPUT scanning
# ---------------------------------------------------------------------------

_OUTPUT_CREDENTIAL_REMEDIATION = (
    "Clear all cell outputs before committing: "
    "jupyter nbconvert --clear-output --inplace notebook.ipynb. "
    "Add .ipynb output clearing to your pre-commit hooks."
)


def _check_output_credentials(output_text: str, cell_number: int) -> Iterator[_RawFinding]:
    """Pattern 1 — apply credentials.py's own detection rules to output text."""
    for line_number, line in enumerate(output_text.splitlines(), start=1):
        for rule, value, _column in _credential_scan_line(line):
            yield (
                "credential-in-output",
                "CRITICAL",
                f"Credential pattern found in notebook cell OUTPUT (cell {cell_number}) "
                "— outputs are committed to git and visible to anyone who views the notebook",
                f"Found pattern matching {rule.message.lower()}: {_redact(value)}",
                _OUTPUT_CREDENTIAL_REMEDIATION,
                line_number,
                cell_number,
            )


_TRACEBACK_TEXT = "Traceback (most recent call last):"

_TRACEBACK_REMEDIATION = (
    "Clear cell outputs before committing. Never commit notebooks with error "
    "outputs that reveal internal paths."
)


def _check_output_stack_trace(output_text: str, cell_number: int) -> Iterator[_RawFinding]:
    """Pattern 2 — a stack trace in a cell output reveals internal paths."""
    for line_number, line in enumerate(output_text.splitlines(), start=1):
        if _TRACEBACK_TEXT in line:
            yield (
                "stack-trace-in-output",
                "MEDIUM",
                f"Stack trace found in notebook cell output (cell {cell_number}) — "
                "reveals internal file paths and code structure",
                "Cell output contains a Python traceback.",
                _TRACEBACK_REMEDIATION,
                line_number,
                cell_number,
            )
            return


_PII_COLUMN_KEYWORDS: tuple[str, ...] = (
    "ssn",
    "social_security",
    "credit_card",
    "passport",
    "date_of_birth",
    "dob",
    "phone_number",
    "phone",
    "email_address",
    "home_address",
    "ip_address",
    "gps",
    "location",
    "salary",
    "medical",
    "diagnosis",
    "prescription",
    "national_id",
    "tax_id",
)

_COLUMN_SPLIT_RE = re.compile(r"\t+|\|+|\s{2,}")

_PII_DATAFRAME_REMEDIATION = (
    "Clear all outputs before committing. Never commit notebooks that display "
    "rows of personal data."
)


def _dataframe_columns(line: str) -> list[str]:
    columns = [c.strip() for c in _COLUMN_SPLIT_RE.split(line.strip()) if c.strip()]
    return columns if len(columns) >= 2 else []


def _check_output_pii_dataframe(output_text: str, cell_number: int) -> Iterator[_RawFinding]:
    """Pattern 3 — a dataframe-preview output whose column headers suggest PII."""
    for line_number, line in enumerate(output_text.splitlines(), start=1):
        columns = _dataframe_columns(line)
        if not columns:
            continue
        lowered_columns = [c.lower() for c in columns]
        if not any(
            keyword in column for column in lowered_columns for keyword in _PII_COLUMN_KEYWORDS
        ):
            continue
        yield (
            "pii-dataframe-in-output",
            "HIGH",
            "Notebook output appears to contain a dataframe preview with PII "
            f"column names (cell {cell_number}) — sensitive data may be "
            "committed in notebook outputs",
            f"Possible PII column headers detected: {', '.join(columns)}",
            _PII_DATAFRAME_REMEDIATION,
            line_number,
            cell_number,
        )
        return


_BASE64_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{60,}={0,2}(?![A-Za-z0-9+/=])")

_BASE64_SECRET_REMEDIATION = (
    "Clear cell outputs. Check whether this encoded value contains sensitive data."  # noqa: S105
)


def _decode_base64_candidate(candidate: str) -> str | None:
    padded = candidate + "=" * (-len(candidate) % 4)
    try:
        decoded_bytes = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    try:
        return decoded_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _decoded_text_contains_credential(decoded: str) -> bool:
    return any(True for _ in _credential_scan_line(decoded))


def _check_output_base64_secret(output_text: str, cell_number: int) -> Iterator[_RawFinding]:
    """Pattern 8 — a base64-looking output string that decodes to a credential."""
    for line_number, line in enumerate(output_text.splitlines(), start=1):
        for match in _BASE64_CANDIDATE_RE.finditer(line):
            decoded = _decode_base64_candidate(match.group(0))
            if decoded is None or not _decoded_text_contains_credential(decoded):
                continue
            yield (
                "base64-secret-in-output",
                "MEDIUM",
                "Possible base64-encoded secret in notebook output "
                f"(cell {cell_number}) — secrets are sometimes base64-encoded "
                "before committing",
                "A base64-looking output string decodes to a known credential pattern.",
                _BASE64_SECRET_REMEDIATION,
                line_number,
                cell_number,
            )


def _scan_cell_output(output_text: str, cell_number: int) -> Iterator[_RawFinding]:
    if not output_text:
        return
    yield from _check_output_credentials(output_text, cell_number)
    yield from _check_output_stack_trace(output_text, cell_number)
    yield from _check_output_pii_dataframe(output_text, cell_number)
    yield from _check_output_base64_secret(output_text, cell_number)


# ---------------------------------------------------------------------------
# Step 7B — dangerous cell SOURCE patterns
# ---------------------------------------------------------------------------

_PIP_INSTALL_RE = re.compile(r"^\s*(?:!\s*pip\s+install|!\s*conda\s+install|%\s*pip\s+install)\b")

_PIP_INSTALL_REMEDIATION = (
    "Move dependencies to requirements.txt or pyproject.toml. Use a "
    "reproducible environment rather than installing packages in notebook cells."
)


def _check_pip_install(source: str, cell_number: int) -> Iterator[_RawFinding]:
    """Pattern 4 — package installation directly inside a notebook cell."""
    for line_number, line in enumerate(source.splitlines(), start=1):
        if _PIP_INSTALL_RE.search(line):
            yield (
                "pip-install-in-notebook",
                "LOW",
                "Package installation in notebook cell — installs are "
                "non-reproducible and environment-dependent",
                line.strip(),
                _PIP_INSTALL_REMEDIATION,
                line_number,
                cell_number,
            )


_WGET_CURL_HTTP_RE = re.compile(r"^\s*!\s*(?:wget|curl)\b[^\n]*\bhttp://")

_HTTP_DOWNLOAD_REMEDIATION = "Use https:// for all downloads. Verify checksums after downloading."


def _check_http_download(source: str, cell_number: int) -> Iterator[_RawFinding]:
    """Pattern 5 — !wget/!curl over unencrypted HTTP."""
    for line_number, line in enumerate(source.splitlines(), start=1):
        if _WGET_CURL_HTTP_RE.search(line):
            yield (
                "http-download-in-notebook",
                "HIGH",
                "Notebook cell downloads over unencrypted HTTP — training "
                "data poisoning risk",
                line.strip(),
                _HTTP_DOWNLOAD_REMEDIATION,
                line_number,
                cell_number,
            )


_ENV_MAGIC_SET_RE = re.compile(
    r"^\s*%env\s+(\w*(?:TOKEN|KEY|SECRET|PASSWORD)\w*)\s*=\s*\S+", re.IGNORECASE
)

_ENV_MAGIC_REMEDIATION = (
    "Never set secret values with %env in notebooks. Load secrets from a "
    ".env file using python-dotenv or from your system environment before "
    "launching Jupyter."
)


def _check_env_magic_secret(source: str, cell_number: int) -> Iterator[_RawFinding]:
    """Pattern 6 — %env magic that *sets* a secret-looking variable."""
    for line_number, line in enumerate(source.splitlines(), start=1):
        if _ENV_MAGIC_SET_RE.search(line):
            yield (
                "env-secret-in-notebook",
                "HIGH",
                "%env magic command sets environment variable in notebook — "
                "if the value is a real secret it appears in cell source "
                "which is committed to git",
                line.strip(),
                _ENV_MAGIC_REMEDIATION,
                line_number,
                cell_number,
            )


_WHOAMI_RE = re.compile(r"^\s*!\s*whoami\b")
_ROOT_WORD_RE = re.compile(r"\broot\b")

_ROOT_EXECUTION_REMEDIATION = (
    "Never run Jupyter as root. Create a dedicated non-root user for ML development."
)
_ROOT_EXECUTION_MESSAGE = (
    "Notebook appears to have been executed as root user — running Jupyter "
    "as root is a security risk"
)


def _check_whoami_root_output(
    source: str, output_text: str, cell_number: int
) -> Iterator[_RawFinding]:
    """Pattern 7 (source half) — !whoami cell whose output shows root."""
    if not _WHOAMI_RE.search(source) or not _ROOT_WORD_RE.search(output_text):
        return
    yield (
        "root-execution-detected",
        "HIGH",
        _ROOT_EXECUTION_MESSAGE,
        "!whoami output in this cell shows 'root'.",
        _ROOT_EXECUTION_REMEDIATION,
        1,
        cell_number,
    )


def _check_kernelspec_root(notebook: dict[str, Any]) -> Iterator[_RawFinding]:
    """Pattern 7 (metadata half) — kernelspec display_name/language mentions root."""
    kernelspec = notebook.get("metadata", {}).get("kernelspec", {}) or {}
    display_name = str(kernelspec.get("display_name", "")).lower()
    language = str(kernelspec.get("language", "")).lower()
    if "root" not in display_name and "root" not in language:
        return
    yield (
        "root-execution-detected",
        "HIGH",
        _ROOT_EXECUTION_MESSAGE,
        "Notebook kernelspec metadata references 'root'.",
        _ROOT_EXECUTION_REMEDIATION,
        1,
        None,
    )


def _scan_cell_source(source: str, output_text: str, cell_number: int) -> Iterator[_RawFinding]:
    yield from _check_pip_install(source, cell_number)
    yield from _check_http_download(source, cell_number)
    yield from _check_env_magic_secret(source, cell_number)
    yield from _check_whoami_root_output(source, output_text, cell_number)


# ---------------------------------------------------------------------------
# File / notebook scanning
# ---------------------------------------------------------------------------


def _build_finding(raw: _RawFinding, path: Path) -> Finding:
    rule, severity, message, detail, remediation, line, cell = raw
    return Finding(
        rule=rule,
        type="notebook_risk",
        severity=severity,
        file=str(path),
        line=line,
        message=message,
        detail=detail,
        remediation=remediation,
        cell=cell,
    )


def scan_file(path: Path) -> list[Finding]:
    """Scan a single `.ipynb` file for notebook-specific risks.

    Every other file type is skipped silently (returns an empty list) — this
    scanner never scans `.py` or any other source file.
    """
    if path.suffix != ".ipynb":
        return []

    try:
        notebook = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []

    if notebook_has_ignore_file_marker(notebook):
        return []

    findings = [_build_finding(raw, path) for raw in _check_kernelspec_root(notebook)]

    for cell_number, cell in enumerate(notebook.get("cells", []), start=1):
        if cell.get("cell_type") != "code":
            continue

        source = _cell_source_text(cell)
        output_text = _cell_output_text(cell)

        findings.extend(
            _build_finding(raw, path) for raw in _scan_cell_output(output_text, cell_number)
        )
        findings.extend(
            _build_finding(raw, path)
            for raw in _scan_cell_source(source, output_text, cell_number)
        )

    return filter_notebook_suppressed(findings, notebook, exempt_rules=_OUTPUT_RULE_NAMES)


def scan_path(root: Path) -> Iterator[Finding]:
    """Walk `root` and yield notebook-risk findings from every `.ipynb` file."""
    for path in walk_files(root, include_extensions=_INCLUDE_EXTENSIONS):
        yield from scan_file(path)


def count_files(root: Path) -> int:
    """Count how many files `scan_path(root)` would examine."""
    return sum(1 for _ in walk_files(root, include_extensions=_INCLUDE_EXTENSIONS))
