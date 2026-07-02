# vigilml: ignore-file
# This file's own credential-pattern regexes (and one docstring example)
# match this scanner's — and other scanners' — own detection rules when
# vigilml scans its own source. All findings here are false positives.
"""Hardcoded credential detection for source, config, and env files.

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
from vigilml.utils.suppression import (
    filter_notebook_suppressed,
    filter_suppressed,
    has_ignore_file_marker,
    notebook_has_ignore_file_marker,
)

_INCLUDE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".ipynb",
        ".env",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".cfg",
        ".ini",
        ".conf",
        ".sh",
        ".bash",
        ".zsh",
        ".dockerfile",
        ".tfvars",
        ".properties",
        ".pem",
        ".key",
    }
)

_INCLUDE_FILENAMES: frozenset[str] = frozenset(
    {
        ".env",
        ".env.local",
        ".env.production",
        ".env.staging",
        ".env.dev",
        "Dockerfile",
    }
)


@dataclass(frozen=True)
class _CredentialRule:
    rule: str
    pattern: re.Pattern[str]
    severity: Severity
    message: str
    remediation: str
    value_group: int = 0


@dataclass(frozen=True)
class _VarAssignmentRule:
    """Flags `NAME = value` / `NAME: value` assignments by variable name.

    `keywords` are matched as case-insensitive substrings of the variable
    name. `check_placeholder` additionally requires the assigned value not
    look like a placeholder (see `_PLACEHOLDER_WORDS`) — used only by the
    generic catch-all rule, since service-specific env var names (e.g.
    `PINECONE_API_KEY`) are unambiguous enough not to need it, and real key
    material can coincidentally contain a placeholder substring.
    `require_assignment_context` additionally requires the match to look
    like a bare assignment statement rather than a keyword argument inside
    a function call (see `_is_assignment_context`) — used only by the
    generic catch-all rule, since short generic words like "key" are
    common, non-secret keyword-argument names (e.g. boto3's
    `Key="path/in/bucket"`), whereas service-specific env var names are
    unambiguous regardless of context.
    """

    rule: str
    keywords: tuple[str, ...]
    severity: Severity
    message: str
    remediation: str
    min_length: int = 16
    check_placeholder: bool = False
    require_assignment_context: bool = False


def _secrets_manager_remediation(var_hint: str) -> str:
    return (
        f"Remove the value from source code. Store it in an environment variable "
        f"and load with os.getenv('{var_hint}')."
    )


_RULES: tuple[_CredentialRule, ...] = (
    _CredentialRule(
        rule="anthropic-api-key",
        pattern=re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
        severity="CRITICAL",
        message="Anthropic API key detected",
        remediation=_secrets_manager_remediation("ANTHROPIC_API_KEY"),
    ),
    _CredentialRule(
        rule="openai-api-key",
        pattern=re.compile(r"sk-(?!ant-)[A-Za-z0-9_-]{20,}"),
        severity="CRITICAL",
        message="OpenAI API key detected",
        remediation=_secrets_manager_remediation("OPENAI_API_KEY"),
    ),
    _CredentialRule(
        rule="huggingface-token",
        pattern=re.compile(r"hf_[A-Za-z0-9]{20,}"),
        severity="CRITICAL",
        message="HuggingFace access token detected",
        remediation=_secrets_manager_remediation("HF_TOKEN"),
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
        value_group=1,
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
        rule="gcp-oauth-token",
        pattern=re.compile(r"ya29\.[A-Za-z0-9_-]{20,}"),
        severity="HIGH",
        message="GCP OAuth access token detected",
        remediation=(
            "Remove the token from source code. OAuth access tokens are short-lived "
            "but should never be hardcoded — obtain them at runtime via the GCP client "
            "library instead."
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
    _CredentialRule(
        rule="azure-connection-string",
        pattern=re.compile(
            r"DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]+"
        ),
        severity="CRITICAL",
        message="Azure storage connection string detected",
        remediation=(
            "Remove the connection string from source code. Store it in an environment "
            "variable or Azure Key Vault, and rotate the account key immediately."
        ),
    ),
    _CredentialRule(
        rule="replicate-api-token",
        pattern=re.compile(r"\br8_[A-Za-z0-9]{20,}\b"),
        severity="CRITICAL",
        message="Replicate API token detected",
        remediation=_secrets_manager_remediation("REPLICATE_API_TOKEN"),
    ),
    _CredentialRule(
        rule="databricks-token",
        pattern=re.compile(r"\bdapi[0-9a-f]{32}\b"),
        severity="CRITICAL",
        message="Databricks personal access token detected",
        remediation=_secrets_manager_remediation("DATABRICKS_TOKEN")
        + " Rotate this token immediately.",
    ),
    _CredentialRule(
        rule="mongodb-connection-string",
        pattern=re.compile(r"mongodb(?:\+srv)?://[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]+"),
        severity="CRITICAL",
        message="MongoDB connection string with embedded credentials detected",
        remediation=(
            "Remove the connection string from source code. Store credentials in an "
            "environment variable or secrets manager, and rotate the password."
        ),
    ),
    _CredentialRule(
        rule="postgresql-connection-string",
        pattern=re.compile(r"postgres(?:ql)?://[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]+"),
        severity="CRITICAL",
        message="PostgreSQL connection string with embedded credentials detected",
        remediation=(
            "Remove the connection string from source code. Store credentials in an "
            "environment variable or secrets manager, and rotate the password."
        ),
    ),
    _CredentialRule(
        rule="mysql-connection-string",
        pattern=re.compile(r"mysql://[^:\s'\"]+:[^@\s'\"]+@[^\s'\"]+"),
        severity="CRITICAL",
        message="MySQL connection string with embedded credentials detected",
        remediation=(
            "Remove the connection string from source code. Store credentials in an "
            "environment variable or secrets manager, and rotate the password."
        ),
    ),
    _CredentialRule(
        rule="redis-connection-string",
        pattern=re.compile(r"redis://:[^@\s'\"]+@[^\s'\"]+"),
        severity="HIGH",
        message="Redis connection string with embedded password detected",
        remediation=(
            "Remove the connection string from source code. Store the password in an "
            "environment variable or secrets manager, and rotate it."
        ),
    ),
    _CredentialRule(
        rule="slack-bot-token",
        pattern=re.compile(r"xoxb-[A-Za-z0-9-]{10,}"),
        severity="CRITICAL",
        message="Slack bot token detected",
        remediation=_secrets_manager_remediation("SLACK_BOT_TOKEN")
        + " Rotate this token immediately.",
    ),
    _CredentialRule(
        rule="slack-webhook-url",
        pattern=re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
        severity="HIGH",
        message="Slack webhook URL detected",
        remediation=(
            "Remove the webhook URL from source code and store it in an environment "
            "variable — anyone with this URL can post messages to the channel."
        ),
    ),
    _CredentialRule(
        rule="sentry-dsn",
        pattern=re.compile(r"https://[A-Za-z0-9]+@(?:[A-Za-z0-9.-]+\.)?sentry\.io/[0-9]+"),
        severity="MEDIUM",
        message="Sentry DSN detected",
        remediation=(
            "Store the DSN in an environment variable instead of hardcoding it. DSNs "
            "are not highly sensitive but should still be kept out of source control."
        ),
    ),
    _CredentialRule(
        rule="rsa-private-key",
        pattern=re.compile(r"-----BEGIN RSA PRIVATE KEY-----"),
        severity="CRITICAL",
        message="RSA private key detected",
        remediation=(
            "Remove the private key from source code. Use a secrets manager such as "
            "AWS Secrets Manager, HashiCorp Vault, or environment variables. Never "
            "commit private keys."
        ),
    ),
    _CredentialRule(
        rule="ec-private-key",
        pattern=re.compile(r"-----BEGIN EC PRIVATE KEY-----"),
        severity="CRITICAL",
        message="EC private key detected",
        remediation=(
            "Remove the private key from source code. Use a secrets manager such as "
            "AWS Secrets Manager, HashiCorp Vault, or environment variables. Never "
            "commit private keys."
        ),
    ),
    _CredentialRule(
        rule="openssh-private-key",
        pattern=re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
        severity="CRITICAL",
        message="OpenSSH private key detected",
        remediation=(
            "Remove the private key from source code. Use a secrets manager such as "
            "AWS Secrets Manager, HashiCorp Vault, or environment variables. Never "
            "commit private keys."
        ),
    ),
)

_GENERIC_SECRET_KEYWORDS: tuple[str, ...] = (
    "SECRET",
    "KEY",
    "TOKEN",
    "PASSWORD",
    "PASSWD",
    "PWD",
    "CREDENTIAL",
    "API_KEY",
)

_PLACEHOLDER_WORDS: tuple[str, ...] = (
    "example",
    "test",
    "fake",
    "placeholder",
    "your",
    "change",
    "xxx",
    "replace",
    "dummy",
    "sample",
    "insert",
    "here",
    "xxxxxx",
    "changeme",
    "todo",
)

_VAR_RULES: tuple[_VarAssignmentRule, ...] = (
    _VarAssignmentRule(
        rule="cloudflare-api-token",
        keywords=("CLOUDFLARE", "CF_"),
        severity="HIGH",
        message="Cloudflare API token detected",
        remediation=_secrets_manager_remediation("CLOUDFLARE_API_TOKEN"),
    ),
    _VarAssignmentRule(
        rule="wandb-api-key",
        keywords=("WANDB_API_KEY",),
        severity="HIGH",
        message="Weights & Biases API key detected",
        remediation=_secrets_manager_remediation("WANDB_API_KEY"),
    ),
    _VarAssignmentRule(
        rule="neptune-api-token",
        keywords=("NEPTUNE_API_TOKEN",),
        severity="HIGH",
        message="Neptune.ai API token detected",
        remediation=_secrets_manager_remediation("NEPTUNE_API_TOKEN"),
    ),
    _VarAssignmentRule(
        rule="pinecone-api-key",
        keywords=("PINECONE_API_KEY",),
        severity="HIGH",
        message="Pinecone API key detected",
        remediation=_secrets_manager_remediation("PINECONE_API_KEY"),
    ),
    _VarAssignmentRule(
        rule="weaviate-api-key",
        keywords=("WEAVIATE_API_KEY",),
        severity="HIGH",
        message="Weaviate API key detected",
        remediation=_secrets_manager_remediation("WEAVIATE_API_KEY"),
    ),
    _VarAssignmentRule(
        rule="qdrant-api-key",
        keywords=("QDRANT_API_KEY",),
        severity="HIGH",
        message="Qdrant API key detected",
        remediation=_secrets_manager_remediation("QDRANT_API_KEY"),
    ),
    _VarAssignmentRule(
        rule="langsmith-api-key",
        keywords=("LANGCHAIN_API_KEY", "LANGSMITH_API_KEY"),
        severity="HIGH",
        message="LangSmith API key detected",
        remediation=_secrets_manager_remediation("LANGSMITH_API_KEY"),
    ),
    _VarAssignmentRule(
        rule="cohere-api-key",
        keywords=("COHERE_API_KEY",),
        severity="HIGH",
        message="Cohere API key detected",
        remediation=_secrets_manager_remediation("COHERE_API_KEY"),
    ),
    _VarAssignmentRule(
        rule="mistral-api-key",
        keywords=("MISTRAL_API_KEY",),
        severity="HIGH",
        message="Mistral API key detected",
        remediation=_secrets_manager_remediation("MISTRAL_API_KEY"),
    ),
    _VarAssignmentRule(
        rule="together-api-key",
        keywords=("TOGETHER_API_KEY",),
        severity="HIGH",
        message="Together AI API key detected",
        remediation=_secrets_manager_remediation("TOGETHER_API_KEY"),
    ),
    _VarAssignmentRule(
        rule="modal-token",
        keywords=("MODAL_TOKEN_ID", "MODAL_TOKEN_SECRET"),
        severity="HIGH",
        message="Modal token detected",
        remediation=_secrets_manager_remediation("MODAL_TOKEN_SECRET"),
    ),
    _VarAssignmentRule(
        rule="hardcoded-secret-variable",
        keywords=_GENERIC_SECRET_KEYWORDS,
        severity="MEDIUM",
        message="Possible hardcoded secret in variable name suggesting sensitive value",
        remediation=(
            "Move this value to an environment variable or secrets manager instead of "
            "hardcoding it in source code."
        ),
        min_length=17,
        check_placeholder=True,
        require_assignment_context=True,
    ),
)

# Matches `NAME = value`, `NAME: value` (YAML), and `"NAME": value` (JSON),
# in both quoted (group 2/3) and bare/unquoted (group 4) forms.
_ASSIGNMENT_PATTERN = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\b['\"]?\s*[:=]\s*(?:(['\"])(.*?)\2|([A-Za-z0-9_.\-/+=]+))"
)


def _redact(value: str) -> str:
    """Show the first 4 characters of a credential, redact the rest."""
    if len(value) <= 4:
        return "****"
    return f"{value[:4]}{'*' * (len(value) - 4)}"


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(word in lowered for word in _PLACEHOLDER_WORDS)


def _is_assignment_context(line: str, start: int, end: int) -> bool:
    """True if the match spanning `line[start:end]` looks like a bare
    assignment statement (`NAME = value`, optionally `self.NAME = value` /
    `cls.NAME = value`) rather than a keyword argument inside a function
    call.

    Keyword arguments are excluded via two signals: something other than
    `self.`/`cls.` precedes the identifier on the line (e.g. `func(`,
    `a, `, `dict(`), or the match is followed by a comma — which catches
    the common multi-line-call style where each keyword argument sits
    alone on its own line (e.g. boto3's `Key="path",` inside a multi-line
    `s3.put_object(...)` call), where there is nothing else on the line to
    signal "this is inside a call".
    """
    prefix = line[:start].rstrip()
    if prefix and not (prefix.endswith("self.") or prefix.endswith("cls.")):
        return False
    remainder = line[end:].lstrip()
    return not remainder.startswith(",")


def _find_assignments(line: str) -> Iterator[tuple[str, str, int, int, bool]]:
    """Yield (identifier, value, start, end, is_assignment_context) for each
    assignment-like expression in `line`."""
    for match in _ASSIGNMENT_PATTERN.finditer(line):
        value = match.group(3) if match.group(3) is not None else match.group(4)
        if not value:
            continue
        start, end = match.start(), match.end()
        yield match.group(1), value, start, end, _is_assignment_context(line, start, end)


def _match_var_rule(
    identifier: str, value: str, is_assignment_context: bool
) -> _VarAssignmentRule | None:
    upper = identifier.upper()
    for rule in _VAR_RULES:
        if not any(keyword in upper for keyword in rule.keywords):
            continue
        if rule.require_assignment_context and not is_assignment_context:
            continue
        if len(value) < rule.min_length:
            continue
        if rule.check_placeholder and _is_placeholder(value):
            continue
        return rule
    return None


def _overlaps(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    return any(start < s_end and end > s_start for s_start, s_end in spans)


def _scan_line(line: str) -> Iterator[tuple[_CredentialRule | _VarAssignmentRule, str, int]]:
    """Yield (rule, matched value, 1-based column) for each credential found in `line`."""
    matched_spans: list[tuple[int, int]] = []

    for rule in _RULES:
        match = rule.pattern.search(line)
        if match:
            value = match.group(rule.value_group) if rule.value_group else match.group(0)
            matched_spans.append((match.start(), match.end()))
            yield rule, value, match.start() + 1

    for identifier, value, start, end, is_assignment_context in _find_assignments(line):
        if _overlaps(start, end, matched_spans):
            continue

        var_rule = _match_var_rule(identifier, value, is_assignment_context)
        if var_rule is not None:
            matched_spans.append((start, end))
            yield var_rule, value, start + 1


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for hardcoded credentials.

    `.ipynb` files are parsed as notebooks and only `code` cell `source`
    fields are scanned; every other file is scanned as plain text.
    """
    if path.suffix == ".ipynb":
        return _scan_notebook(path)
    return _scan_text_file(path)


def _scan_text_file(path: Path) -> list[Finding]:
    text = path.read_text(errors="ignore")
    if has_ignore_file_marker(text):
        return []

    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, value, column in _scan_line(line):
            findings.append(_build_finding(rule, path, line_number, column, value))
    return filter_suppressed(findings, text)


def _scan_notebook(path: Path) -> list[Finding]:
    try:
        notebook = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []

    if notebook_has_ignore_file_marker(notebook):
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
    return filter_notebook_suppressed(findings, notebook)


def _build_finding(
    rule: _CredentialRule | _VarAssignmentRule,
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
    """Walk `root` and yield credential findings from every scannable file."""
    for path in walk_files(
        root, include_extensions=_INCLUDE_EXTENSIONS, include_filenames=_INCLUDE_FILENAMES
    ):
        yield from scan_file(path)


def count_files(root: Path) -> int:
    """Count how many files `scan_path(root)` would examine."""
    return sum(
        1
        for _ in walk_files(
            root, include_extensions=_INCLUDE_EXTENSIONS, include_filenames=_INCLUDE_FILENAMES
        )
    )
