"""Cloud misconfiguration detection.

Flags public S3 write ACLs, world-readable file permissions, and hardcoded
bucket names in `.py` files and notebook code-cell sources only
(see docs/DECISIONS.md ADR-006).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

from vigilml.scanner import Finding, Severity
from vigilml.utils.file_walker import walk_files

_S3_PUBLIC_ACL_RE = re.compile(r"ACL\s*=\s*['\"]public-read(?:-write)?['\"]")
_BUCKET_NAME_RE = re.compile(r"Bucket\s*=\s*['\"]([A-Za-z0-9.\-_]+)['\"]")
_CHMOD_SHELL_777_RE = re.compile(r"chmod\s+777\b")
_OS_CHMOD_777_RE = re.compile(r"os\.chmod\([^,]+,\s*0o?777\)")

_S3_PUBLIC_WRITE_REMEDIATION = (
    "Remove the public-read ACL. Restrict bucket access with IAM policies "
    "and bucket policies instead of object-level public ACLs."
)
_HARDCODED_BUCKET_REMEDIATION = (
    "Load the bucket name from an environment variable or config file "
    "instead of hardcoding it, so it can vary per environment."
)
_WORLD_READABLE_REMEDIATION = (
    "Use a more restrictive permission mode (e.g. 0o640 or 0o600). "
    "World-writable/readable permissions expose files to any local user."
)


def _scan_line(line: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    """Yield (rule, severity, message, remediation, column) for `line`."""
    if match := _S3_PUBLIC_ACL_RE.search(line):
        yield (
            "s3-public-write",
            "MEDIUM",
            "S3 object ACL grants public read access",
            _S3_PUBLIC_WRITE_REMEDIATION,
            match.start() + 1,
        )
    if match := _BUCKET_NAME_RE.search(line):
        yield (
            "hardcoded-bucket-name",
            "LOW",
            "Hardcoded S3 bucket name detected",
            _HARDCODED_BUCKET_REMEDIATION,
            match.start() + 1,
        )
    if match := (_CHMOD_SHELL_777_RE.search(line) or _OS_CHMOD_777_RE.search(line)):
        yield (
            "world-readable-permissions",
            "MEDIUM",
            "World-readable/writable file permissions (777) detected",
            _WORLD_READABLE_REMEDIATION,
            match.start() + 1,
        )


def scan_file(path: Path) -> list[Finding]:
    """Scan a single `.py` or `.ipynb` file for cloud misconfigurations."""
    if path.suffix == ".ipynb":
        return _scan_notebook(path)
    if path.suffix == ".py":
        return _scan_text_file(path)
    return []


def _scan_text_file(path: Path) -> list[Finding]:
    text = path.read_text(errors="ignore")
    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, severity, message, remediation, column in _scan_line(line):
            findings.append(
                _build_finding(rule, severity, message, remediation, path, line_number, column)
            )
    return findings


def _scan_notebook(path: Path) -> list[Finding]:
    try:
        notebook = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []

    findings = []
    for cell_number, cell in enumerate(notebook.get("cells", []), start=1):
        if cell.get("cell_type") != "code":
            continue

        source = cell.get("source", "")
        text = "".join(source) if isinstance(source, list) else source

        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule, severity, message, remediation, column in _scan_line(line):
                findings.append(
                    _build_finding(
                        rule, severity, message, remediation, path, line_number, column,
                        cell=cell_number,
                    )
                )
    return findings


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
        type="cloud",
        severity=severity,
        file=str(path),
        line=line,
        column=column,
        message=message,
        detail=message,
        remediation=remediation,
        cell=cell,
    )


def scan_path(root: Path) -> Iterator[Finding]:
    """Walk `root` and yield cloud misconfiguration findings."""
    for path in walk_files(root, include_extensions=frozenset({".py", ".ipynb"})):
        yield from scan_file(path)
