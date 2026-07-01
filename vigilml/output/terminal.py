"""Rich-based terminal output for VigilML scan results.

See docs/DECISIONS.md ADR-002 — never use print() here, always go through
a Console so --no-colour and --quiet stay centrally controlled.
"""

from __future__ import annotations

from pathlib import Path
from typing import IO

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from vigilml.scanner import Finding, Severity

_SEVERITY_ORDER: tuple[Severity, ...] = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

_SEVERITY_STYLES: dict[Severity, str] = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
}


def render(
    findings: list[Finding],
    scan_path: Path,
    duration_seconds: float,
    *,
    no_color: bool = False,
    quiet: bool = False,
    ignored_count: int = 0,
    file: IO[str] | None = None,
) -> None:
    """Render scan findings to the terminal, grouped by severity."""
    # force_terminal so --no-colour/colour behaviour is explicit, not
    # dependent on whether stdout happens to be a real tty (e.g. in CI logs).
    console = Console(
        file=file,
        force_terminal=True,
        color_system=None if no_color else "standard",
        highlight=False,
    )

    if quiet:
        console.print(_summary_line(findings, duration_seconds, ignored_count))
        return

    if not findings and not ignored_count:
        text = Text()
        text.append("No issues found", style="bold green")
        text.append(f" — scanned {scan_path} in {duration_seconds:.2f}s")
        console.print(text)
        return

    for severity in _SEVERITY_ORDER:
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue
        style = _SEVERITY_STYLES[severity]
        console.print(f"\n[{style}]{severity}[/] ({len(group)})")
        for finding in group:
            _render_finding(console, finding, style)

    console.print()
    console.print(_summary_panel(findings, scan_path, duration_seconds, ignored_count))


def _render_finding(console: Console, finding: Finding, style: str) -> None:
    location = f"{finding.file}:{finding.line}"
    if finding.cell is not None:
        location += f" (cell {finding.cell})"

    line = Text("  ")
    line.append("•", style=style)
    line.append(f" {location} — {finding.message} [{finding.rule}]")
    console.print(line)

    if finding.detail:
        console.print(Text(f"      {finding.detail}"))

    remediation = Text("      ")
    remediation.append("Remediation: ", style="dim")
    remediation.append(finding.remediation)
    console.print(remediation)


def _summary_counts(findings: list[Finding]) -> dict[Severity, int]:
    counts: dict[Severity, int] = dict.fromkeys(_SEVERITY_ORDER, 0)
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def _summary_line(findings: list[Finding], duration_seconds: float, ignored_count: int) -> str:
    if not findings and not ignored_count:
        return f"No issues found ({duration_seconds:.2f}s)"
    counts = _summary_counts(findings)
    parts = ", ".join(f"{count} {severity}" for severity, count in counts.items() if count)
    ignored_suffix = f", {ignored_count} ignored" if ignored_count else ""
    return f"{len(findings)} finding(s) ({parts}{ignored_suffix}) in {duration_seconds:.2f}s"


def _summary_panel(
    findings: list[Finding], scan_path: Path, duration_seconds: float, ignored_count: int
) -> Panel:
    counts = _summary_counts(findings)
    lines = [f"Scanned: {scan_path}", f"Duration: {duration_seconds:.2f}s", ""]
    lines.extend(f"{severity}: {count}" for severity, count in counts.items())
    lines.append(f"\nTotal: {len(findings)} finding(s)")
    if ignored_count:
        lines.append(f"Ignored: {ignored_count} finding(s)")
    return Panel(Text("\n".join(lines)), title="Summary", border_style="bold")
