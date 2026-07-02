"""JSON output formatting matching the schema in docs/ARCHITECTURE.md."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Any

from vigilml import __version__
from vigilml.scanner import Finding, Severity

_SEVERITY_ORDER: tuple[Severity, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def build_payload(
    findings: list[Finding],
    scan_path: Path,
    duration_seconds: float,
    ignored_findings: list[dict[str, str]] | None = None,
    scanner_coverage: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    """Build the JSON-serialisable payload for a scan's findings.

    `ignored_findings` are findings suppressed by a `.vigilml.yml` ignore
    rule — each dict has "rule", "file", "reason" (see docs/ARCHITECTURE.md).
    `scanner_coverage` maps each scanner name that ran to
    `{"files_scanned": N, "findings": N}`.
    """
    ignored_findings = ignored_findings or []
    scanner_coverage = scanner_coverage or {}
    counts: dict[str, int] = dict.fromkeys(_SEVERITY_ORDER, 0)
    for finding in findings:
        counts[finding.severity] += 1
    counts["ignored"] = len(ignored_findings)

    return {
        "version": __version__,
        "scanned_at": datetime.now(timezone.utc).isoformat(),
        "scan_path": str(scan_path),
        "duration_seconds": duration_seconds,
        "total_findings": len(findings),
        "summary": counts,
        "findings": [_finding_to_dict(finding) for finding in findings],
        "ignored_findings": ignored_findings,
        "scanner_coverage": scanner_coverage,
    }


def _finding_to_dict(finding: Finding) -> dict[str, Any]:
    payload = {
        "type": finding.type,
        "severity": finding.severity,
        "file": finding.file,
        "line": finding.line,
        "column": finding.column,
        "rule": finding.rule,
        "message": finding.message,
        "detail": finding.detail,
        "remediation": finding.remediation,
    }
    if finding.cell is not None:
        payload["cell"] = finding.cell
    return payload


def render(
    findings: list[Finding],
    scan_path: Path,
    duration_seconds: float,
    *,
    ignored_findings: list[dict[str, str]] | None = None,
    scanner_coverage: dict[str, dict[str, int]] | None = None,
    file: IO[str] | None = None,
) -> None:
    """Write the JSON payload to `file` (defaults to stdout) and nothing else.

    Rich's Console is not used here — it would treat "[" as markup and wrap
    long lines to the terminal width, both of which would corrupt the JSON.
    """
    payload = build_payload(
        findings, scan_path, duration_seconds, ignored_findings, scanner_coverage
    )
    (file or sys.stdout).write(json.dumps(payload, indent=2) + "\n")
