"""Shared data models for VigilML scanners."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]


@dataclass(frozen=True)
class Finding:
    """A single security finding produced by a scanner.

    `detail` must never contain the raw value of a detected credential —
    callers are required to redact before constructing a Finding
    (see docs/DECISIONS.md ADR-007).
    """

    rule: str
    type: str
    severity: Severity
    file: str
    line: int
    message: str
    remediation: str
    detail: str = ""
    column: int = 0
    cell: int | None = None
