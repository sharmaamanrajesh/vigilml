"""VigilML CLI entrypoint."""

from __future__ import annotations

import sys
import time
from pathlib import Path

import click

from vigilml.output import json_output, terminal
from vigilml.scanner import Finding
from vigilml.scanner.cloud import scan_path as scan_cloud
from vigilml.scanner.credentials import scan_path as scan_credentials
from vigilml.scanner.dependencies import scan_path as scan_dependencies
from vigilml.scanner.model_files import scan_path as scan_model_files
from vigilml.utils.config import (
    RULE_NAME_BY_FINDING_TYPE,
    Config,
    apply_config,
    ignore_reason_for,
    load_config,
)


@click.group()
def main() -> None:
    """VigilML — Security scanner for the AI development lifecycle."""


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Output findings as JSON.")
@click.option("--no-colour", "no_colour", is_flag=True, help="Disable ANSI colour codes.")
@click.option("--quiet", is_flag=True, help="Only print the summary line.")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a .vigilml.yml config file.",
)
def scan(
    path: Path, as_json: bool, no_colour: bool, quiet: bool, config_path: Path | None
) -> None:
    """Scan PATH for AI/ML security issues."""
    config = load_config(config_path)
    started = time.monotonic()
    findings = _run_enabled_scanners(path, config)
    findings, ignored = apply_config(findings, config)
    duration_seconds = time.monotonic() - started

    if as_json:
        ignored_payload = [_ignored_to_dict(f, config) for f in ignored]
        json_output.render(findings, path, duration_seconds, ignored_findings=ignored_payload)
    else:
        terminal.render(
            findings,
            path,
            duration_seconds,
            no_color=no_colour,
            quiet=quiet,
            ignored_count=len(ignored),
        )

    sys.exit(1 if findings else 0)


def _run_enabled_scanners(path: Path, config: Config) -> list[Finding]:
    findings: list[Finding] = []
    if config.rule("credentials").enabled:
        findings.extend(scan_credentials(path))
    if config.rule("model_files").enabled:
        findings.extend(scan_model_files(path))
    if config.rule("cloud").enabled:
        findings.extend(scan_cloud(path))
    if config.rule("dependencies").enabled:
        findings.extend(scan_dependencies(path))
    return findings


def _ignored_to_dict(finding: Finding, config: Config) -> dict[str, str]:
    return {
        "rule": RULE_NAME_BY_FINDING_TYPE.get(finding.type, finding.type),
        "file": finding.file,
        "reason": ignore_reason_for(finding, config),
    }


if __name__ == "__main__":
    main()
