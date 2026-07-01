"""Hardcoded credential detection for `.py` and `.ipynb` files.

Only scans the `source` field of `code` cells in notebooks — never
`outputs` or `metadata` (see docs/DECISIONS.md ADR-006).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from vigilml.scanner import Finding, Severity
from vigilml.utils.file_walker import walk_files


@dataclass(frozen=True)
class _CredentialRule:
    rule: str
    pattern: re.Pattern[str]
    severity: Severity
    message: str
    remediation: str


_RULES: tuple[_CredentialRule, ...] = (
    _CredentialRule(
        rule="anthropic-api-key",
        pattern=re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
        severity="CRITICAL",
        message="Anthropic API key detected",
        remediation=(
            "Remove the key from source code. Store it in an environment variable "
            "and load with os.getenv('ANTHROPIC_API_KEY')."
        ),
    ),
    _CredentialRule(
        rule="openai-api-key",
        pattern=re.compile(r"sk-(?!ant-)[A-Za-z0-9_-]{20,}"),
        severity="CRITICAL",
        message="OpenAI API key detected",
        remediation=(
            "Remove the key from source code. Store it in an environment variable "
            "and load with os.getenv('OPENAI_API_KEY')."
        ),
    ),
    _CredentialRule(
        rule="huggingface-token",
        pattern=re.compile(r"hf_[A-Za-z0-9]{20,}"),
        severity="CRITICAL",
        message="HuggingFace access token detected",
        remediation=(
            "Remove the token from source code. Store it in an environment variable "
            "and load with os.getenv('HF_TOKEN')."
        ),
    ),
    _CredentialRule(
        rule="aws-access-key",
        pattern=re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        severity="CRITICAL",
        message="AWS access key ID detected",
        remediation=(
            "Remove the key from source code. Use environment variables, an AWS "
            "credentials file, or an IAM role instead. Rotate this key immediately."
        ),
    ),
    _CredentialRule(
        rule="aws-secret-key",
        pattern=re.compile(
            r"(?i)aws[_-]?secret(?:[_-]?access)?(?:[_-]?key)?\s*=\s*['\"]([A-Za-z0-9/+=]{40})['\"]"
        ),
        severity="CRITICAL",
        message="AWS secret access key detected",
        remediation=(
            "Remove the secret from source code. Use environment variables, an AWS "
            "credentials file, or an IAM role instead. Rotate this key immediately."
        ),
    ),
    _CredentialRule(
        rule="gcp-api-key",
        pattern=re.compile(r"AIza[0-9A-Za-z_-]{35}"),
        severity="CRITICAL",
        message="GCP API key detected",
        remediation=(
            "Remove the key from source code. Store it in an environment variable "
            "and restrict the key's allowed APIs and referrers in the GCP console."
        ),
    ),
    _CredentialRule(
        rule="gcp-service-account-key",
        pattern=re.compile(r"-----BEGIN PRIVATE KEY-----"),
        severity="CRITICAL",
        message="GCP service account private key detected",
        remediation=(
            "Remove the service account key file from source code. Use workload "
            "identity federation or a secrets manager instead, and revoke this key."
        ),
    ),
)


def _redact(value: str) -> str:
    """Show the first 4 characters of a credential, redact the rest."""
    if len(value) <= 4:
        return "****"
    return f"{value[:4]}{'*' * (len(value) - 4)}"


def _scan_line(line: str) -> Iterator[tuple[_CredentialRule, str, int]]:
    """Yield (rule, matched value, column) for each credential found in `line`."""
    for rule in _RULES:
        match = rule.pattern.search(line)
        if match:
            value = match.group(1) if match.groups() else match.group(0)
            yield rule, value, match.start() + 1


def scan_file(path: Path) -> list[Finding]:
    """Scan a single `.py` or `.ipynb` file for hardcoded credentials."""
    if path.suffix == ".ipynb":
        return _scan_notebook(path)
    return _scan_text_file(path)


def _scan_text_file(path: Path) -> list[Finding]:
    text = path.read_text(errors="ignore")
    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, value, column in _scan_line(line):
            findings.append(_build_finding(rule, path, line_number, column, value))
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
            for rule, value, column in _scan_line(line):
                findings.append(
                    _build_finding(rule, path, line_number, column, value, cell=cell_number)
                )
    return findings


def _build_finding(
    rule: _CredentialRule,
    path: Path,
    line: int,
    column: int,
    value: str,
    cell: int | None = None,
) -> Finding:
    return Finding(
        rule=rule.rule,
        type="credential",
        severity=rule.severity,
        file=str(path),
        line=line,
        column=column,
        message=rule.message,
        detail=f"Found pattern matching {rule.message.lower()}: {_redact(value)}",
        remediation=rule.remediation,
        cell=cell,
    )


def scan_path(root: Path) -> Iterator[Finding]:
    """Walk `root` and yield credential findings from every `.py`/`.ipynb` file."""
    for path in walk_files(root, include_extensions=frozenset({".py", ".ipynb"})):
        yield from scan_file(path)
