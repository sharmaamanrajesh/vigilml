"""Unit tests for vigilml.output.terminal."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from vigilml.output.terminal import render
from vigilml.scanner import Finding

pytestmark = pytest.mark.unit


def _finding(
    severity: str = "CRITICAL", rule: str = "openai-api-key", cell: int | None = None
) -> Finding:
    return Finding(
        rule=rule,
        type="credential",
        severity=severity,  # type: ignore[arg-type]
        file="train.py",
        line=7,
        message="OpenAI API key detected",
        remediation="Remove the key from source code.",
        detail="sk-p****",
        cell=cell,
    )


def test_clean_scan_shows_no_issues_found() -> None:
    buf = io.StringIO()
    render([], Path("."), 1.23, file=buf)

    assert "No issues found" in buf.getvalue()


def test_findings_are_grouped_by_severity() -> None:
    buf = io.StringIO()
    findings = [
        _finding(severity="CRITICAL"),
        _finding(severity="LOW", rule="torch-load-without-weights-only"),
    ]
    render(findings, Path("."), 1.0, file=buf)

    output = buf.getvalue()
    assert "CRITICAL" in output
    assert "LOW" in output
    assert "train.py:7" in output


def test_remediation_is_shown() -> None:
    buf = io.StringIO()
    render([_finding()], Path("."), 1.0, file=buf)

    assert "Remove the key from source code." in buf.getvalue()


def test_summary_shows_total_finding_count() -> None:
    buf = io.StringIO()
    findings = [_finding(severity="CRITICAL"), _finding(severity="CRITICAL")]
    render(findings, Path("."), 1.0, file=buf)

    assert "2" in buf.getvalue()


def test_cell_reference_shown_for_notebook_finding() -> None:
    buf = io.StringIO()
    render([_finding(cell=3)], Path("."), 1.0, file=buf)

    assert "cell 3" in buf.getvalue()


def test_quiet_mode_outputs_exactly_one_line_with_findings() -> None:
    buf = io.StringIO()
    render([_finding()], Path("."), 1.0, quiet=True, file=buf)

    lines = [line for line in buf.getvalue().splitlines() if line.strip()]
    assert len(lines) == 1


def test_quiet_mode_outputs_exactly_one_line_when_clean() -> None:
    buf = io.StringIO()
    render([], Path("."), 1.0, quiet=True, file=buf)

    lines = [line for line in buf.getvalue().splitlines() if line.strip()]
    assert len(lines) == 1
    assert "No issues found" in lines[0]


def test_no_color_strips_all_ansi_codes() -> None:
    buf = io.StringIO()
    render([_finding()], Path("."), 1.0, no_color=True, file=buf)

    assert "\x1b[" not in buf.getvalue()


def test_color_enabled_by_default_emits_ansi_codes() -> None:
    buf = io.StringIO()
    render([_finding()], Path("."), 1.0, file=buf)

    assert "\x1b[" in buf.getvalue()


def test_no_color_quiet_mode_has_no_ansi_codes_either() -> None:
    buf = io.StringIO()
    render([_finding()], Path("."), 1.0, no_color=True, quiet=True, file=buf)

    assert "\x1b[" not in buf.getvalue()


def test_ignored_count_shown_in_summary() -> None:
    buf = io.StringIO()
    render([_finding()], Path("."), 1.0, ignored_count=1, file=buf)

    assert "Ignored: 1" in buf.getvalue()


def test_ignored_only_scan_does_not_show_no_issues_found() -> None:
    buf = io.StringIO()
    render([], Path("."), 1.0, ignored_count=1, file=buf)

    assert "No issues found" not in buf.getvalue()
    assert "Ignored: 1" in buf.getvalue()


def test_quiet_mode_mentions_ignored_count() -> None:
    buf = io.StringIO()
    render([_finding()], Path("."), 1.0, quiet=True, ignored_count=2, file=buf)

    assert "2 ignored" in buf.getvalue()
