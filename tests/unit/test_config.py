"""Unit tests for vigilml.utils.config."""

from __future__ import annotations

from pathlib import Path

import pytest

from vigilml.scanner import Finding
from vigilml.utils.config import Config, IgnoreRule, RuleConfig, apply_config, load_config

pytestmark = pytest.mark.unit


def _finding(rule_type: str = "credential", severity: str = "LOW", file: str = "a.py") -> Finding:
    return Finding(
        rule="some-rule",
        type=rule_type,
        severity=severity,  # type: ignore[arg-type]
        file=file,
        line=1,
        message="m",
        remediation="r",
    )


def test_load_config_returns_defaults_when_path_is_none() -> None:
    config = load_config(None)

    assert config.exclude_paths
    assert config.rule("credentials").enabled is True
    assert config.rule("credentials").severity_override is None


def test_load_config_parses_rule_toggles(tmp_path: Path) -> None:
    path = tmp_path / ".vigilml.yml"
    path.write_text("rules:\n  cloud:\n    enabled: false\n")

    config = load_config(path)

    assert config.rule("cloud").enabled is False
    assert config.rule("credentials").enabled is True


def test_load_config_parses_severity_override(tmp_path: Path) -> None:
    path = tmp_path / ".vigilml.yml"
    path.write_text("rules:\n  credentials:\n    severity_override: CRITICAL\n")

    config = load_config(path)

    assert config.rule("credentials").severity_override == "CRITICAL"


def test_load_config_parses_min_severity(tmp_path: Path) -> None:
    path = tmp_path / ".vigilml.yml"
    path.write_text("rules:\n  dependencies:\n    min_severity: HIGH\n")

    config = load_config(path)

    assert config.rule("dependencies").min_severity == "HIGH"


def test_load_config_parses_exclude_paths(tmp_path: Path) -> None:
    path = tmp_path / ".vigilml.yml"
    path.write_text("scan:\n  exclude_paths:\n    - legacy/\n    - notebooks/archive/\n")

    config = load_config(path)

    assert config.exclude_paths == ("legacy/", "notebooks/archive/")


def test_load_config_parses_ignore_list(tmp_path: Path) -> None:
    path = tmp_path / ".vigilml.yml"
    path.write_text(
        "ignore:\n"
        "  - path: scripts/generate_keys.py\n"
        "    rule: credentials\n"
        "    reason: test fixture keys\n"
    )

    config = load_config(path)

    assert len(config.ignores) == 1
    assert config.ignores[0].path == "scripts/generate_keys.py"
    assert config.ignores[0].rule == "credentials"
    assert config.ignores[0].reason == "test fixture keys"


def test_load_config_empty_file_returns_defaults(tmp_path: Path) -> None:
    path = tmp_path / ".vigilml.yml"
    path.write_text("")

    config = load_config(path)

    assert config.rule("credentials").enabled is True


# ── apply_config ─────────────────────────────────────────────────────────────


def test_apply_config_overrides_severity() -> None:
    config = Config(rules={"credentials": RuleConfig(severity_override="CRITICAL")})
    findings = [_finding(rule_type="credential", severity="LOW")]

    kept, ignored = apply_config(findings, config)

    assert kept[0].severity == "CRITICAL"
    assert ignored == []


def test_apply_config_filters_below_min_severity() -> None:
    config = Config(rules={"dependencies": RuleConfig(min_severity="HIGH")})
    findings = [
        _finding(rule_type="dependency", severity="LOW"),
        _finding(rule_type="dependency", severity="CRITICAL"),
    ]

    kept, ignored = apply_config(findings, config)

    assert len(kept) == 1
    assert kept[0].severity == "CRITICAL"


def test_apply_config_ignores_matching_path_and_rule() -> None:
    config = Config(ignores=(IgnoreRule(path="scripts/generate_keys.py", rule="credentials"),))
    findings = [
        _finding(rule_type="credential", file="repo/scripts/generate_keys.py"),
        _finding(rule_type="credential", file="repo/train.py"),
    ]

    kept, ignored = apply_config(findings, config)

    assert len(kept) == 1
    assert kept[0].file == "repo/train.py"
    assert len(ignored) == 1
    assert ignored[0].file == "repo/scripts/generate_keys.py"


def test_apply_config_excludes_findings_under_excluded_paths() -> None:
    config = Config(exclude_paths=("legacy/",))
    findings = [
        _finding(file="legacy/old.py"),
        _finding(file="current.py"),
    ]

    kept, ignored = apply_config(findings, config)

    assert len(kept) == 1
    assert kept[0].file == "current.py"
