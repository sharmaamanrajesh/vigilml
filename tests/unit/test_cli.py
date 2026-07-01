"""Unit tests for the vigilml CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import responses
from click.testing import CliRunner

from vigilml.cli import main
from vigilml.scanner.dependencies import OSV_API_URL

pytestmark = pytest.mark.unit

_OPENAI_KEY_LINE = 'openai.api_key = "sk-proj-abc1234567890XXXXXXXXXXXXXXXXXXXXXXXXXX"\n'


def test_scan_clean_directory_exits_zero(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text("x = 1\n")
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(tmp_path)])

    assert result.exit_code == 0
    assert "No issues found" in result.output


def test_scan_vulnerable_directory_exits_one(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(_OPENAI_KEY_LINE)
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(tmp_path)])

    assert result.exit_code == 1
    assert "openai-api-key" in result.output


def test_scan_aggregates_findings_from_all_four_scanners(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(_OPENAI_KEY_LINE)
    (tmp_path / "model.pkl").write_bytes(b"")
    (tmp_path / "upload.py").write_text('ACL="public-read"\n')
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(tmp_path), "--json"])
    payload = json.loads(result.output)

    rules = {f["rule"] for f in payload["findings"]}
    assert rules == {"openai-api-key", "unsafe-pickle-file", "s3-public-write"}


def test_json_flag_outputs_valid_json_with_findings(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(_OPENAI_KEY_LINE)
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(tmp_path), "--json"])
    payload = json.loads(result.output)

    assert payload["total_findings"] == 1
    assert result.exit_code == 1


def test_json_flag_clean_directory_exits_zero(tmp_path: Path) -> None:
    (tmp_path / "clean.py").write_text("x = 1\n")
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(tmp_path), "--json"])
    payload = json.loads(result.output)

    assert payload["total_findings"] == 0
    assert result.exit_code == 0


def test_no_colour_flag_strips_ansi_codes(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(_OPENAI_KEY_LINE)
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(tmp_path), "--no-colour"])

    assert "\x1b[" not in result.output


def test_colour_present_by_default(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(_OPENAI_KEY_LINE)
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(tmp_path)])

    assert "\x1b[" in result.output


def test_quiet_flag_outputs_exactly_one_line(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(_OPENAI_KEY_LINE)
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(tmp_path), "--quiet"])

    lines = [line for line in result.output.splitlines() if line.strip()]
    assert len(lines) == 1


@responses.activate
def test_scan_detects_vulnerable_dependency(tmp_path: Path) -> None:
    responses.add(
        responses.POST,
        OSV_API_URL,
        json={"vulns": [{"id": "GHSA-1234"}]},
        status=200,
    )
    (tmp_path / "requirements.txt").write_text("torch==1.9.0\n")
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(tmp_path), "--json"])
    payload = json.loads(result.output)

    assert payload["total_findings"] == 1
    assert payload["findings"][0]["rule"] == "GHSA-1234"


def test_scan_nonexistent_path_fails_with_nonzero_exit() -> None:
    runner = CliRunner()

    result = runner.invoke(main, ["scan", "/no/such/path/at/all"])

    assert result.exit_code != 0


def test_config_disables_a_rule(tmp_path: Path) -> None:
    (tmp_path / "upload.py").write_text('ACL="public-read"\n')
    config_path = tmp_path / ".vigilml.yml"
    config_path.write_text("rules:\n  cloud:\n    enabled: false\n")
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(tmp_path), "--config", str(config_path), "--json"])
    payload = json.loads(result.output)

    assert payload["total_findings"] == 0
    assert result.exit_code == 0


def test_config_overrides_severity(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(_OPENAI_KEY_LINE)
    config_path = tmp_path / ".vigilml.yml"
    config_path.write_text("rules:\n  credentials:\n    severity_override: LOW\n")
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(tmp_path), "--config", str(config_path), "--json"])
    payload = json.loads(result.output)

    assert payload["findings"][0]["severity"] == "LOW"


def test_config_excludes_path(tmp_path: Path) -> None:
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / "old.py").write_text(_OPENAI_KEY_LINE)
    config_path = tmp_path / ".vigilml.yml"
    config_path.write_text("scan:\n  exclude_paths:\n    - legacy/\n")
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(tmp_path), "--config", str(config_path), "--json"])
    payload = json.loads(result.output)

    assert payload["total_findings"] == 0


def test_config_ignores_specific_path_and_rule(tmp_path: Path) -> None:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "generate_keys.py").write_text(_OPENAI_KEY_LINE)
    config_path = tmp_path / ".vigilml.yml"
    config_path.write_text(
        "ignore:\n"
        "  - path: scripts/generate_keys.py\n"
        "    rule: credentials\n"
        "    reason: test fixture keys\n"
    )
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(tmp_path), "--config", str(config_path), "--json"])
    payload = json.loads(result.output)

    assert payload["total_findings"] == 0
    assert payload["summary"]["ignored"] == 1
    assert payload["ignored_findings"][0]["reason"] == "test fixture keys"
    assert result.exit_code == 0


def test_without_config_flag_uses_defaults(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(_OPENAI_KEY_LINE)
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(tmp_path), "--json"])
    payload = json.loads(result.output)

    assert payload["total_findings"] == 1
    assert payload["findings"][0]["severity"] == "CRITICAL"


def test_scan_accepts_single_file_with_finding(tmp_path: Path) -> None:
    f = tmp_path / "train.py"
    f.write_text(_OPENAI_KEY_LINE)
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(f), "--json"])
    payload = json.loads(result.output)

    assert result.exit_code == 1
    assert payload["total_findings"] == 1
    assert payload["findings"][0]["rule"] == "openai-api-key"


def test_scan_accepts_single_clean_file_exits_zero(tmp_path: Path) -> None:
    f = tmp_path / "clean.py"
    f.write_text("x = 1\n")
    runner = CliRunner()

    result = runner.invoke(main, ["scan", str(f)])

    assert result.exit_code == 0
