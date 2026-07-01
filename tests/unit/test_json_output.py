"""Unit tests for vigilml.output.json_output."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from vigilml.output.json_output import build_payload, render
from vigilml.scanner import Finding

pytestmark = pytest.mark.unit


def _finding(severity: str = "CRITICAL", rule: str = "openai-api-key") -> Finding:
    return Finding(
        rule=rule,
        type="credential",
        severity=severity,  # type: ignore[arg-type]
        file="train.py",
        line=7,
        column=14,
        message="OpenAI API key detected",
        remediation="Remove the key from source code.",
        detail="sk-p****",
    )


def test_build_payload_top_level_fields() -> None:
    payload = build_payload([_finding()], Path("/repo"), 2.3)

    assert payload["version"]
    assert payload["scan_path"] == "/repo"
    assert payload["duration_seconds"] == 2.3
    assert payload["total_findings"] == 1
    assert "scanned_at" in payload


def test_build_payload_summary_counts_by_severity() -> None:
    findings = [
        _finding(severity="CRITICAL"),
        _finding(severity="CRITICAL"),
        _finding(severity="LOW"),
    ]
    payload = build_payload(findings, Path("."), 1.0)

    assert payload["summary"] == {"CRITICAL": 2, "HIGH": 0, "MEDIUM": 0, "LOW": 1, "ignored": 0}


def test_build_payload_finding_fields() -> None:
    payload = build_payload([_finding()], Path("."), 1.0)
    finding = payload["findings"][0]

    assert finding["type"] == "credential"
    assert finding["severity"] == "CRITICAL"
    assert finding["file"] == "train.py"
    assert finding["line"] == 7
    assert finding["column"] == 14
    assert finding["rule"] == "openai-api-key"
    assert finding["message"]
    assert finding["remediation"]
    assert finding["detail"]


def test_build_payload_includes_cell_when_present() -> None:
    finding = Finding(
        rule="r",
        type="credential",
        severity="LOW",
        file="nb.ipynb",
        line=2,
        message="m",
        remediation="rem",
        cell=3,
    )
    payload = build_payload([finding], Path("."), 1.0)

    assert payload["findings"][0]["cell"] == 3


def test_build_payload_omits_cell_when_absent() -> None:
    payload = build_payload([_finding()], Path("."), 1.0)

    assert "cell" not in payload["findings"][0]


def test_build_payload_clean_scan_has_zero_findings() -> None:
    payload = build_payload([], Path("."), 1.0)

    assert payload["total_findings"] == 0
    assert payload["findings"] == []


def test_render_writes_parseable_json() -> None:
    buf = io.StringIO()
    render([_finding()], Path("/repo"), 1.0, file=buf)

    payload = json.loads(buf.getvalue())
    assert payload["total_findings"] == 1


def test_render_output_contains_nothing_but_json() -> None:
    buf = io.StringIO()
    render([], Path("."), 1.0, file=buf)

    json.loads(buf.getvalue())


def test_render_handles_findings_with_special_characters() -> None:
    finding = Finding(
        rule="r",
        type="credential",
        severity="LOW",
        file="weird [file].py",
        line=1,
        message="message with [brackets] and \"quotes\"",
        remediation="rem",
    )
    buf = io.StringIO()
    render([finding], Path("."), 1.0, file=buf)

    payload = json.loads(buf.getvalue())
    assert payload["findings"][0]["file"] == "weird [file].py"


def test_build_payload_includes_ignored_findings() -> None:
    ignored = [{"rule": "credentials", "file": "scripts/generate_keys.py", "reason": "test keys"}]
    payload = build_payload([], Path("."), 1.0, ignored_findings=ignored)

    assert payload["ignored_findings"] == ignored
    assert payload["summary"]["ignored"] == 1


def test_build_payload_ignored_findings_defaults_to_empty() -> None:
    payload = build_payload([_finding()], Path("."), 1.0)

    assert payload["ignored_findings"] == []
    assert payload["summary"]["ignored"] == 0
