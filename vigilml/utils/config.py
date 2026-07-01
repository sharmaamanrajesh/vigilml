"""Loads and applies `.vigilml.yml` configuration.

See docs/DECISIONS.md ADR-004 for why PyYAML is used here, and ADR-004 in
the same file plus docs/ARCHITECTURE.md for the config/JSON schema this
implements (rule toggles, severity overrides, path excludes, ignore list).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

import yaml

from vigilml.scanner import Finding, Severity

_SEVERITY_RANK: dict[Severity, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Finding.type is singular ("credential"); .vigilml.yml's rule keys are
# plural ("credentials"), matching the scanner module names.
RULE_NAME_BY_FINDING_TYPE: dict[str, str] = {
    "credential": "credentials",
    "model_file": "model_files",
    "cloud": "cloud",
    "dependency": "dependencies",
}

DEFAULT_EXCLUDE_PATHS: tuple[str, ...] = (
    ".git/",
    "__pycache__/",
    "*.pyc",
    ".venv/",
    "venv/",
    "env/",
    "node_modules/",
    "dist/",
    "build/",
    "*.egg-info/",
)


@dataclass(frozen=True)
class RuleConfig:
    """Per-rule-category settings (e.g. the `credentials` block in .vigilml.yml)."""

    enabled: bool = True
    severity_override: Severity | None = None
    min_severity: Severity = "LOW"


@dataclass(frozen=True)
class IgnoreRule:
    """A single entry from the `ignore:` list — suppresses matching findings."""

    path: str
    rule: str
    reason: str = ""


@dataclass(frozen=True)
class Config:
    """Parsed `.vigilml.yml` settings, with sensible defaults when absent."""

    exclude_paths: tuple[str, ...] = DEFAULT_EXCLUDE_PATHS
    rules: dict[str, RuleConfig] = field(default_factory=dict)
    ignores: tuple[IgnoreRule, ...] = ()

    def rule(self, name: str) -> RuleConfig:
        """Return the RuleConfig for `name`, or defaults if not configured."""
        return self.rules.get(name, RuleConfig())


def load_config(path: Path | None) -> Config:
    """Load a `.vigilml.yml` file, or return defaults if `path` is None."""
    if path is None:
        return Config()

    data = yaml.safe_load(path.read_text()) or {}
    return _parse_config(data)


def _parse_config(data: dict[str, Any]) -> Config:
    scan = data.get("scan") or {}
    exclude_paths = tuple(scan.get("exclude_paths", DEFAULT_EXCLUDE_PATHS))

    rules = {
        name: RuleConfig(
            enabled=(rule_data or {}).get("enabled", True),
            severity_override=(rule_data or {}).get("severity_override"),
            min_severity=(rule_data or {}).get("min_severity", "LOW"),
        )
        for name, rule_data in (data.get("rules") or {}).items()
    }

    ignores = tuple(
        IgnoreRule(path=item["path"], rule=item["rule"], reason=item.get("reason", ""))
        for item in (data.get("ignore") or [])
    )

    return Config(exclude_paths=exclude_paths, rules=rules, ignores=ignores)


def apply_config(findings: list[Finding], config: Config) -> tuple[list[Finding], list[Finding]]:
    """Apply exclude paths, the ignore list, severity overrides, and min_severity.

    Returns (kept, ignored) — `ignored` only contains findings suppressed by
    an explicit `ignore:` entry, not ones dropped by exclude_paths/min_severity.
    """
    kept = []
    ignored = []
    for finding in findings:
        if _is_excluded(finding, config):
            continue
        if _is_ignored(finding, config):
            ignored.append(finding)
            continue

        finding = _with_severity_override(finding, config)
        if _meets_min_severity(finding, config):
            kept.append(finding)

    return kept, ignored


def _is_excluded(finding: Finding, config: Config) -> bool:
    file_path = finding.file.replace("\\", "/")
    for pattern in config.exclude_paths:
        stripped = pattern.rstrip("/")
        if fnmatch.fnmatch(file_path, stripped) or f"/{stripped}/" in f"/{file_path}":
            return True
    return False


def _find_ignore_rule(finding: Finding, config: Config) -> IgnoreRule | None:
    file_path = finding.file.replace("\\", "/")
    rule_name = RULE_NAME_BY_FINDING_TYPE.get(finding.type, finding.type)
    for rule in config.ignores:
        if rule.rule == rule_name and file_path.endswith(rule.path):
            return rule
    return None


def _is_ignored(finding: Finding, config: Config) -> bool:
    return _find_ignore_rule(finding, config) is not None


def ignore_reason_for(finding: Finding, config: Config) -> str:
    """Return the `reason` text from the ignore rule that suppressed `finding`."""
    rule = _find_ignore_rule(finding, config)
    return rule.reason if rule else ""


def _with_severity_override(finding: Finding, config: Config) -> Finding:
    rule_name = RULE_NAME_BY_FINDING_TYPE.get(finding.type, finding.type)
    override = config.rule(rule_name).severity_override
    if override is None or override == finding.severity:
        return finding
    return replace(finding, severity=override)


def _meets_min_severity(finding: Finding, config: Config) -> bool:
    rule_name = RULE_NAME_BY_FINDING_TYPE.get(finding.type, finding.type)
    threshold = config.rule(rule_name).min_severity
    return _SEVERITY_RANK[finding.severity] >= _SEVERITY_RANK[threshold]
