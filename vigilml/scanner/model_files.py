"""Unsafe model deserialisation detection.

Flags pickle/joblib binary files by extension, and unsafe deserialisation
calls (`pickle.load`/`pickle.loads`, `torch.load` without `weights_only=True`)
in `.py` files and notebook code-cell sources (see docs/DECISIONS.md ADR-006).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

from vigilml.scanner import Finding, Severity
from vigilml.utils.file_walker import walk_files

_UNSAFE_FILE_EXTENSIONS: dict[str, str] = {
    ".pkl": "unsafe-pickle-file",
    ".pickle": "unsafe-pickle-file",
    ".joblib": "unsafe-joblib-file",
}

_PICKLE_LOADS_RE = re.compile(r"pickle\.loads\(")
_PICKLE_LOAD_RE = re.compile(r"pickle\.load\(")
_TORCH_LOAD_RE = re.compile(r"torch\.load\(([^)]*)\)")

_PICKLE_REMEDIATION = (
    "Avoid deserialising pickle data, especially from untrusted sources — "
    "pickle.load can execute arbitrary code. Use a safe format such as "
    "safetensors, or validate the source before loading."
)
_TORCH_REMEDIATION = (
    "Pass weights_only=True to torch.load() so only tensor data is "
    "deserialised, not arbitrary Python objects."
)
_UNSAFE_FILE_REMEDIATION = (
    "Convert this file to a safe serialisation format such as safetensors. "
    "Pickle-based formats can execute arbitrary code when deserialised."
)


def _scan_line(line: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    """Yield (rule, severity, message, remediation, column) for `line`."""
    if match := _PICKLE_LOADS_RE.search(line):
        yield (
            "pickle-loads",
            "HIGH",
            "pickle.loads() call detected",
            _PICKLE_REMEDIATION,
            match.start() + 1,
        )
    if match := _PICKLE_LOAD_RE.search(line):
        yield (
            "pickle-load",
            "HIGH",
            "pickle.load() call detected",
            _PICKLE_REMEDIATION,
            match.start() + 1,
        )
    if (match := _TORCH_LOAD_RE.search(line)) and "weights_only=True" not in match.group(1):
        yield (
            "torch-load-without-weights-only",
            "LOW",
            "torch.load() call without weights_only=True",
            _TORCH_REMEDIATION,
            match.start() + 1,
        )


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for unsafe model files or deserialisation calls."""
    if path.suffix in _UNSAFE_FILE_EXTENSIONS:
        return [_unsafe_file_finding(path)]
    if path.suffix == ".ipynb":
        return _scan_notebook(path)
    if path.suffix == ".py":
        return _scan_text_file(path)
    return []


def _unsafe_file_finding(path: Path) -> Finding:
    rule = _UNSAFE_FILE_EXTENSIONS[path.suffix]
    return Finding(
        rule=rule,
        type="model_file",
        severity="HIGH",
        file=str(path),
        line=1,
        message=f"Unsafe model file format detected ({path.suffix})",
        detail=f"{path.name} uses an unsafe binary serialisation format",
        remediation=_UNSAFE_FILE_REMEDIATION,
    )


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
        type="model_file",
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
    """Walk `root` and yield model-file findings from binary and source files."""
    extensions = frozenset({".py", ".ipynb", *_UNSAFE_FILE_EXTENSIONS})
    for path in walk_files(root, include_extensions=extensions):
        yield from scan_file(path)
