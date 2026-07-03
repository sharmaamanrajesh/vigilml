"""Data pipeline security and privacy detection for `.py`/`.ipynb` files.

Flags risky training-data download/loading patterns, possible PII exposure
in pandas pipelines, preprocessing fitted before a train/test split (data
leakage), and data/model artifacts saved to risky paths. Like the other
scanners, this works at file level rather than via full taint analysis: "is
X present anywhere in this file" checks, not "does this specific value flow
into that specific call".
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

from vigilml.scanner import Finding, Severity
from vigilml.utils.file_walker import walk_files
from vigilml.utils.suppression import (
    filter_notebook_suppressed,
    filter_suppressed,
    has_ignore_file_marker,
    notebook_has_ignore_file_marker,
)

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _extract_paren_args(text: str, start: int) -> str | None:
    """Return a call's arguments, given the index just after its opening
    `(`, handling nested brackets/quotes and multi-line calls."""
    depth = 1
    i = start
    in_string: str | None = None
    while i < len(text):
        ch = text[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == in_string:
                in_string = None
        elif ch in "'\"":
            in_string = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return text[start:i]
        i += 1
    return None


def _first_string_arg_value(args: str) -> str | None:
    """Return the literal value of a call's first argument, if it is a
    plain quoted string (possibly preceded by whitespace/newlines)."""
    stripped = args.lstrip()
    if not stripped or stripped[0] not in "'\"":
        return None
    quote = stripped[0]
    end = stripped.find(quote, 1)
    if end == -1:
        return None
    return stripped[1:end]


def _line_and_column(text: str, offset: int) -> tuple[int, int]:
    line_start = text.rfind("\n", 0, offset) + 1
    line = text.count("\n", 0, offset) + 1
    return line, offset - line_start + 1


# ---------------------------------------------------------------------------
# Step 6A — training data download risks
# ---------------------------------------------------------------------------

_DOWNLOAD_CALL_NAME_RE = re.compile(
    r"\b(?:requests\.get|urllib\.request\.urlretrieve|urllib\.request\.urlopen"
    r"|urlretrieve|urlopen)\s*\("
)
_WGET_CURL_HTTP_RE = re.compile(
    r"(?:subprocess\.\w+|os\.system)\([^)]*\b(?:wget|curl)\b[^)]*http://"
)
_WGET_CURL_ANY_RE = re.compile(r"(?:subprocess\.\w+|os\.system)\([^)]*\b(?:wget|curl)\b")

_HTTP_DOWNLOAD_REMEDIATION = (
    "Use https:// for all downloads. Verify file integrity with SHA256 checksum "
    "after downloading."
)
_CHECKSUM_REMEDIATION = (
    "After downloading verify the SHA256 hash: import hashlib; "
    "hashlib.sha256(data).hexdigest() and compare against a known-good value."
)


def _check_http_downloads(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    for match in _DOWNLOAD_CALL_NAME_RE.finditer(text):
        args = _extract_paren_args(text, match.end())
        if args is None:
            continue
        value = _first_string_arg_value(args)
        if value is None or not value.startswith("http://"):
            continue
        line, _ = _line_and_column(text, match.start())
        yield (
            "http-download",
            "HIGH",
            "Training data or model downloaded over unencrypted HTTP — "
            "vulnerable to man-in-the-middle attacks and training data poisoning",
            _HTTP_DOWNLOAD_REMEDIATION,
            line,
        )
    for match in _WGET_CURL_HTTP_RE.finditer(text):
        line, _ = _line_and_column(text, match.start())
        yield (
            "http-download",
            "HIGH",
            "Training data or model downloaded over unencrypted HTTP — "
            "vulnerable to man-in-the-middle attacks and training data poisoning",
            _HTTP_DOWNLOAD_REMEDIATION,
            line,
        )


def _check_missing_checksum(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    if "hashlib" in text:
        return
    for match in _DOWNLOAD_CALL_NAME_RE.finditer(text):
        line, _ = _line_and_column(text, match.start())
        yield (
            "download-without-checksum",
            "MEDIUM",
            "File downloaded without checksum verification — integrity of "
            "training data or model weights cannot be confirmed",
            _CHECKSUM_REMEDIATION,
            line,
        )
    for match in _WGET_CURL_ANY_RE.finditer(text):
        line, _ = _line_and_column(text, match.start())
        yield (
            "download-without-checksum",
            "MEDIUM",
            "File downloaded without checksum verification — integrity of "
            "training data or model weights cannot be confirmed",
            _CHECKSUM_REMEDIATION,
            line,
        )


_LOAD_DATASET_RE = re.compile(r"\bload_dataset\s*\(")
_SAFE_DATASET_ORGS: tuple[str, ...] = ("huggingface", "datasets")

_UNVERIFIED_DATASET_REMEDIATION = (
    "Verify the dataset source before use. Prefer official datasets from "
    "verified organisations. Pin a specific revision: load_dataset('org/name', "  # vigilml: ignore
    "revision='commit_hash')"
)


def _check_unverified_dataset(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    for match in _LOAD_DATASET_RE.finditer(text):
        args = _extract_paren_args(text, match.end())
        if args is None:
            continue
        value = _first_string_arg_value(args)
        if value is None or "/" not in value:
            continue
        org = value.split("/", 1)[0].strip().lower()
        if org in _SAFE_DATASET_ORGS:
            continue
        line, _ = _line_and_column(text, match.start())
        yield (
            "unverified-dataset-source",
            "MEDIUM",
            "Dataset loaded from unverified HuggingFace source — community "
            "datasets may contain poisoned or mislabelled data",
            _UNVERIFIED_DATASET_REMEDIATION,
            line,
        )


# ---------------------------------------------------------------------------
# Step 6B — PII in data pipelines
# ---------------------------------------------------------------------------

_PANDAS_LOAD_RE = re.compile(r"pd\.(?:read_csv|read_json|read_parquet|DataFrame)\s*\(")

# Keywords must appear as whole snake_case segments: `user_phone` and
# `df["phone_number"]` match, but identifiers that merely contain a keyword
# as a substring (`allocation`, `endobj`) do not. "location" is deliberately
# absent — in ML code it almost always means `map_location`, a file path, or
# a memory location, not a person's whereabouts.
_PII_KEYWORD_RE = re.compile(
    r"(?i)(?<![a-z0-9])(?:social_security|credit_card|date_of_birth|phone_number|"
    r"email_address|home_address|ip_address|national_id|tax_id|ssn|dob|phone|"
    r"gps|salary|medical|diagnosis|prescription)(?![a-z0-9])"
)

_PII_COLUMN_REMEDIATION = (
    "Ensure PII columns are anonymised or pseudonymised before use in "
    "training. Document your legal basis for processing this data under "
    "GDPR/CCPA. Consider using differential privacy techniques."
)
_PII_LOGGING_REMEDIATION = (
    "Never log raw PII. Implement log scrubbing, mask sensitive fields "
    "before logging, and ensure log storage complies with your data "
    "retention policy."
)

_LOGGING_CALL_RE = re.compile(r"\b(?:logging\.info|logging\.debug|logger\.info|print)\s*\(")


def _has_pandas_load(text: str) -> bool:
    return bool(_PANDAS_LOAD_RE.search(text))


def _check_pii_columns(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    if not _has_pandas_load(text):
        return
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not _PII_KEYWORD_RE.search(line):
            continue
        yield (
            "pii-column-reference",
            "MEDIUM",
            "Possible PII column reference in data pipeline — verify that "
            "personal data is handled according to your privacy policy and "
            "applicable regulations",
            _PII_COLUMN_REMEDIATION,
            line_number,
        )


def _check_pii_logging(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    """Flag logging calls whose own arguments reference a PII keyword.

    The keyword must appear inside the call's argument list — a PII
    reference elsewhere in the file (e.g. a dataframe column defined
    earlier) must not implicate every print() in the module.
    """
    for match in _LOGGING_CALL_RE.finditer(text):
        args = _extract_paren_args(text, match.end())
        if args is None or not _PII_KEYWORD_RE.search(args):
            continue
        line, _ = _line_and_column(text, match.start())
        yield (
            "pii-logging",
            "HIGH",
            "Possible PII logging detected — personal data may be written "
            "to log files in plaintext",
            _PII_LOGGING_REMEDIATION,
            line,
        )


# ---------------------------------------------------------------------------
# Step 6C — data leakage risks
# ---------------------------------------------------------------------------

_SCALER_CLASSES: tuple[str, ...] = (
    "StandardScaler",
    "MinMaxScaler",
    "LabelEncoder",
    "OneHotEncoder",
    "TfidfVectorizer",
)
_SCALER_CLASS_ALT = "|".join(_SCALER_CLASSES)
_SCALER_ASSIGN_RE = re.compile(rf"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:{_SCALER_CLASS_ALT})\s*\(")
_SCALER_FIT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\.(?:fit_transform|fit)\s*\(([^)]*)\)")
_SCALER_DIRECT_FIT_RE = re.compile(
    rf"\b(?:{_SCALER_CLASS_ALT})\s*\(\s*\)\s*\.(?:fit_transform|fit)\s*\(([^)]*)\)"
)
_TRAIN_TEST_SPLIT_RE = re.compile(r"\btrain_test_split\s*\(")

_LEAKAGE_REMEDIATION = (
    "Split your data first, then fit preprocessors only on training data: "
    "scaler.fit(X_train).transform(X_test)"
)


def _check_data_leakage(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    split_match = _TRAIN_TEST_SPLIT_RE.search(text)
    if not split_match:
        return
    split_pos = split_match.start()
    scaler_vars = {m.group(1) for m in _SCALER_ASSIGN_RE.finditer(text)}

    flagged_lines: set[int] = set()

    for match in _SCALER_FIT_RE.finditer(text):
        var_name, arg = match.group(1), match.group(2)
        if var_name not in scaler_vars or match.start() >= split_pos or "train" in arg.lower():
            continue
        line, _ = _line_and_column(text, match.start())
        if line in flagged_lines:
            continue
        flagged_lines.add(line)
        yield (
            "preprocessing-fit-before-split",
            "MEDIUM",
            "Possible data leakage — preprocessing fitted on full dataset "
            "before train/test split. This leaks test set statistics into "
            "training.",
            _LEAKAGE_REMEDIATION,
            line,
        )

    for match in _SCALER_DIRECT_FIT_RE.finditer(text):
        arg = match.group(1)
        if match.start() >= split_pos or "train" in arg.lower():
            continue
        line, _ = _line_and_column(text, match.start())
        if line in flagged_lines:
            continue
        flagged_lines.add(line)
        yield (
            "preprocessing-fit-before-split",
            "MEDIUM",
            "Possible data leakage — preprocessing fitted on full dataset "
            "before train/test split. This leaks test set statistics into "
            "training.",
            _LEAKAGE_REMEDIATION,
            line,
        )


_DF_SAVE_RE = re.compile(r"\.(?:to_csv|to_parquet)\s*\(\s*[\"']([^\"']+)[\"']")
_NP_SAVE_RE = re.compile(r"\bnp\.save\s*\(\s*[\"']([^\"']+)[\"']")
_TORCH_SAVE_RE = re.compile(r"\btorch\.save\s*\([^,]*,\s*[\"']([^\"']+)[\"']")
_CHMOD_ANYWHERE_RE = re.compile(r"\bos\.chmod\s*\(|\bchmod\s+0?[0-7]{3}\b")

_SAVE_PATH_REMEDIATION = (
    "Save model artifacts and datasets to paths with appropriate "
    "permissions. Avoid /tmp/ for sensitive data. Consider encrypted "
    "storage."
)


def _looks_like_risky_save_path(path: str) -> bool:
    # These are pattern-detection literals describing a *scanned* file's save
    # path, not an actual temp file this process creates — not a real S108.
    return (
        "/tmp/" in path  # noqa: S108
        or "/var/tmp/" in path  # noqa: S108
        or path.startswith("./data/")
    )


def _check_risky_save_paths(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    if _CHMOD_ANYWHERE_RE.search(text):
        return
    for pattern in (_DF_SAVE_RE, _NP_SAVE_RE, _TORCH_SAVE_RE):
        for match in pattern.finditer(text):
            path = match.group(1)
            if not _looks_like_risky_save_path(path):
                continue
            line, _ = _line_and_column(text, match.start())
            yield (
                "risky-save-path",
                "LOW",
                "Training data or model saved to temporary or potentially "
                "world-readable path",
                _SAVE_PATH_REMEDIATION,
                line,
            )


_PATH_READ_RE = re.compile(
    r"\b(?:open|pd\.read_csv|pd\.read_json|pd\.read_parquet)\s*\(\s*[\"']([^\"']+)[\"']"
)

_HARDCODED_PII_PATH_REMEDIATION = (
    "Load data paths from configuration or environment variables. Document "
    "what personal data is stored at this path and ensure appropriate "
    "access controls."
)


def _check_hardcoded_pii_paths(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    for match in _PATH_READ_RE.finditer(text):
        path = match.group(1)
        if not _PII_KEYWORD_RE.search(path):
            continue
        line, _ = _line_and_column(text, match.start())
        yield (
            "hardcoded-pii-path",
            "MEDIUM",
            "Hardcoded path suggesting PII data — path contains terms "
            "associated with personal information",
            _HARDCODED_PII_PATH_REMEDIATION,
            line,
        )


# ---------------------------------------------------------------------------
# File / notebook scanning
# ---------------------------------------------------------------------------


def _scan_file_level(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    """Run every whole-file-context check against `text` once."""
    yield from _check_http_downloads(text)
    yield from _check_missing_checksum(text)
    yield from _check_unverified_dataset(text)
    yield from _check_pii_columns(text)
    yield from _check_pii_logging(text)
    yield from _check_data_leakage(text)
    yield from _check_risky_save_paths(text)
    yield from _check_hardcoded_pii_paths(text)


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for data pipeline security/privacy risks."""
    if path.suffix == ".ipynb":
        return _scan_notebook(path)
    if path.suffix == ".py":
        return _scan_text_file(path)
    return []


def _scan_text_file(path: Path) -> list[Finding]:
    text = path.read_text(errors="ignore")
    if has_ignore_file_marker(text):
        return []

    findings = []
    for rule, severity, message, remediation, line in _scan_file_level(text):
        findings.append(_build_finding(rule, severity, message, remediation, path, line, 1))
    return filter_suppressed(findings, text)


def _scan_notebook(path: Path) -> list[Finding]:
    try:
        notebook = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []

    if notebook_has_ignore_file_marker(notebook):
        return []

    combined_lines: list[str] = []
    combined_line_cell: list[int] = []
    combined_line_number: list[int] = []

    for cell_number, cell in enumerate(notebook.get("cells", []), start=1):
        if cell.get("cell_type") != "code":
            continue
        source = cell.get("source", "")
        text = "".join(source) if isinstance(source, list) else source
        for line_number, line in enumerate(text.splitlines(), start=1):
            combined_lines.append(line)
            combined_line_cell.append(cell_number)
            combined_line_number.append(line_number)

    combined_text = "\n".join(combined_lines)
    findings = []
    for rule, severity, message, remediation, fl_line in _scan_file_level(combined_text):
        index = fl_line - 1
        if 0 <= index < len(combined_line_cell):
            findings.append(
                _build_finding(
                    rule, severity, message, remediation, path,
                    combined_line_number[index], 1, cell=combined_line_cell[index],
                )
            )
    return filter_notebook_suppressed(findings, notebook)


def _build_finding(
    rule: str,
    severity: Severity,
    message: str,
    remediation: str,
    path: Path,
    line: int,
    column: int,
    cell: int | None = None,
) -> Finding:
    return Finding(
        rule=rule,
        type="data_pipeline",
        severity=severity,
        file=str(path),
        line=line,
        column=column,
        message=message,
        detail=message,
        remediation=remediation,
        cell=cell,
    )


_SCAN_EXTENSIONS = frozenset({".py", ".ipynb"})


def scan_path(root: Path) -> Iterator[Finding]:
    """Walk `root` and yield data pipeline findings from `.py`/`.ipynb` files."""
    for path in walk_files(root, include_extensions=_SCAN_EXTENSIONS):
        yield from scan_file(path)


def count_files(root: Path) -> int:
    """Count how many files `scan_path(root)` would examine."""
    return sum(1 for _ in walk_files(root, include_extensions=_SCAN_EXTENSIONS))
