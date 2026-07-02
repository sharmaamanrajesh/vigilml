"""VigilML CLI entrypoint."""

from __future__ import annotations

import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import click

from vigilml import __version__
from vigilml.output import json_output, terminal
from vigilml.scanner import Finding
from vigilml.scanner.cloud import count_files as count_cloud
from vigilml.scanner.cloud import scan_path as scan_cloud
from vigilml.scanner.credentials import count_files as count_credentials
from vigilml.scanner.credentials import scan_path as scan_credentials
from vigilml.scanner.data_pipeline import count_files as count_data_pipeline
from vigilml.scanner.data_pipeline import scan_path as scan_data_pipeline
from vigilml.scanner.dependencies import count_files as count_dependencies
from vigilml.scanner.dependencies import scan_path as scan_dependencies
from vigilml.scanner.model_files import count_files as count_model_files
from vigilml.scanner.model_files import scan_path as scan_model_files
from vigilml.scanner.notebook_risks import count_files as count_notebook_risks
from vigilml.scanner.notebook_risks import scan_path as scan_notebook_risks
from vigilml.scanner.prompt_injection import count_files as count_prompt_injection
from vigilml.scanner.prompt_injection import scan_path as scan_prompt_injection
from vigilml.utils.config import (
    RULE_NAME_BY_FINDING_TYPE,
    Config,
    apply_config,
    ignore_reason_for,
    load_config,
)


@dataclass(frozen=True)
class _ScannerSpec:
    name: str
    scan: Callable[[Path], Iterator[Finding]]
    count: Callable[[Path], int]


_SCANNERS: tuple[_ScannerSpec, ...] = (
    _ScannerSpec("credentials", scan_credentials, count_credentials),
    _ScannerSpec("model_files", scan_model_files, count_model_files),
    _ScannerSpec("cloud", scan_cloud, count_cloud),
    _ScannerSpec("dependencies", scan_dependencies, count_dependencies),
    _ScannerSpec("prompt_injection", scan_prompt_injection, count_prompt_injection),
    _ScannerSpec("data_pipeline", scan_data_pipeline, count_data_pipeline),
    _ScannerSpec("notebook_risks", scan_notebook_risks, count_notebook_risks),
)
_SCANNER_NAMES: tuple[str, ...] = tuple(s.name for s in _SCANNERS)


@click.group()
@click.version_option(version=__version__, prog_name="vigilml")
def main() -> None:
    """VigilML — Security scanner for the AI development lifecycle."""


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option("--json", "as_json", is_flag=True, help="Output findings as JSON.")
@click.option("--no-colour", "no_colour", is_flag=True, help="Disable ANSI colour codes.")
@click.option("--quiet", is_flag=True, help="Only print the summary line.")
@click.option(
    "--stats-only",
    "stats_only",
    is_flag=True,
    help="Print only the summary panel, with no individual findings listed.",
)
@click.option(
    "--scanners",
    "scanners",
    default="all",
    show_default=True,
    help=(
        "Comma-separated list of scanners to run, or 'all'. Valid names: "
        + ", ".join(_SCANNER_NAMES)
        + ", all."
    ),
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to a .vigilml.yml config file.",
)
def scan(
    path: Path,
    as_json: bool,
    no_colour: bool,
    quiet: bool,
    stats_only: bool,
    scanners: str,
    config_path: Path | None,
) -> None:
    """Scan PATH for AI/ML security issues."""
    selected = _parse_scanners(scanners)
    config = load_config(config_path)
    started = time.monotonic()
    findings, coverage = _run_scanners(path, config, selected)
    findings, ignored = apply_config(findings, config)
    duration_seconds = time.monotonic() - started

    if as_json:
        ignored_payload = [_ignored_to_dict(f, config) for f in ignored]
        json_output.render(
            findings,
            path,
            duration_seconds,
            ignored_findings=ignored_payload,
            scanner_coverage=coverage,
        )
    else:
        terminal.render(
            findings,
            path,
            duration_seconds,
            no_color=no_colour,
            quiet=quiet,
            stats_only=stats_only,
            ignored_count=len(ignored),
        )

    sys.exit(1 if findings else 0)


def _parse_scanners(raw: str) -> tuple[str, ...]:
    """Parse `--scanners`' raw value into the scanner names to run.

    Accepts 'all' (the default) or a comma-separated list of scanner names.
    Raises `click.UsageError` — listing every valid name — if any given name
    isn't recognised.
    """
    stripped = raw.strip()
    if stripped.lower() == "all":
        return _SCANNER_NAMES

    requested = tuple(token.strip().lower() for token in stripped.split(",") if token.strip())
    invalid = [name for name in requested if name not in _SCANNER_NAMES]
    if invalid:
        valid_list = ", ".join((*_SCANNER_NAMES, "all"))
        raise click.UsageError(
            f"Invalid scanner name(s): {', '.join(invalid)}. Valid scanners are: {valid_list}."
        )
    return requested


def _run_scanners(
    path: Path, config: Config, selected: tuple[str, ...]
) -> tuple[list[Finding], dict[str, dict[str, int]]]:
    findings: list[Finding] = []
    coverage: dict[str, dict[str, int]] = {}
    for spec in _SCANNERS:
        if spec.name not in selected or not config.rule(spec.name).enabled:
            continue
        scanner_findings = list(spec.scan(path))
        findings.extend(scanner_findings)
        coverage[spec.name] = {
            "files_scanned": spec.count(path),
            "findings": len(scanner_findings),
        }
    return findings, coverage


def _ignored_to_dict(finding: Finding, config: Config) -> dict[str, str]:
    return {
        "rule": RULE_NAME_BY_FINDING_TYPE.get(finding.type, finding.type),
        "file": finding.file,
        "reason": ignore_reason_for(finding, config),
    }


if __name__ == "__main__":
    main()
