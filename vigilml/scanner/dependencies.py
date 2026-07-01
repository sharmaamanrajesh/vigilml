"""ML dependency CVE detection via the OSV.dev API.

See docs/DECISIONS.md ADR-003 — OSV.dev needs no API key and has solid PyPI
coverage. Network calls are wrapped in a timeout and degrade to an empty
result if the API is unreachable, so a scan never crashes on network issues.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import requests
import tomllib

from vigilml.scanner import Finding, Severity
from vigilml.utils.file_walker import walk_files

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_SECONDS = 5

ML_PACKAGES: frozenset[str] = frozenset(
    {
        "torch",
        "torchvision",
        "numpy",
        "scipy",
        "pillow",
        "transformers",
        "tensorflow",
        "tensorflow-cpu",
        "tensorflow-gpu",
        "keras",
        "scikit-learn",
        "langchain",
        "langchain-core",
        "langchain-community",
        "openai",
        "anthropic",
        "diffusers",
        "accelerate",
        "peft",
        "trl",
        "sentence-transformers",
    }
)

# Only "==" is queried — ">=", "~=", etc. are a minimum/range, not the
# version actually installed, so querying OSV for the bound would false-positive.
_PIP_SPEC_RE = re.compile(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-]+)")
_CONDA_SPEC_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*=\s*([A-Za-z0-9_.\-]+)")

_REMEDIATION_TEMPLATE = "Upgrade {name} to a patched version. See {vuln_id} for details."

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MODERATE": "MEDIUM",
    "LOW": "LOW",
}


def parse_requirements_txt(text: str) -> list[tuple[str, str, int]]:
    """Return (name, version, line) tuples for pinned packages in a requirements file."""
    packages = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        if match := _PIP_SPEC_RE.match(line):
            packages.append((match.group(1).lower(), match.group(2), line_number))
    return packages


def parse_pyproject_toml(text: str) -> list[tuple[str, str, int]]:
    """Return (name, version, line) tuples from PEP 621 [project.dependencies]."""
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []

    dependencies = data.get("project", {}).get("dependencies", [])
    packages = []
    for spec in dependencies:
        if match := _PIP_SPEC_RE.match(spec.strip()):
            name = match.group(1).lower()
            packages.append((name, match.group(2), _find_line_number(text, name)))
    return packages


def parse_environment_yml(text: str) -> list[tuple[str, str, int]]:
    """Return (name, version, line) tuples from a conda environment.yml's dependencies."""
    packages = []
    in_dependencies = False
    in_pip_section = False
    dependencies_indent = 0

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        indent = len(raw_line) - len(raw_line.lstrip(" "))

        if not in_dependencies:
            if stripped == "dependencies:":
                in_dependencies = True
                dependencies_indent = indent
            continue

        if not stripped:
            continue
        if indent <= dependencies_indent and not stripped.startswith("-"):
            break

        if stripped in ("- pip:", "pip:"):
            in_pip_section = True
            continue

        item = stripped[1:].strip() if stripped.startswith("-") else stripped
        if not item:
            continue

        pattern = _PIP_SPEC_RE if in_pip_section else _CONDA_SPEC_RE
        if match := pattern.match(item):
            packages.append((match.group(1).lower(), match.group(2), line_number))

    return packages


def _find_line_number(text: str, name: str) -> int:
    pattern = re.compile(rf"\b{re.escape(name)}\b", re.IGNORECASE)
    for line_number, line in enumerate(text.splitlines(), start=1):
        if pattern.search(line):
            return line_number
    return 1


def query_osv(name: str, version: str) -> list[dict[str, Any]]:
    """Query OSV.dev for vulnerabilities affecting `name`==`version` on PyPI."""
    try:
        response = requests.post(
            OSV_API_URL,
            json={"package": {"name": name, "ecosystem": "PyPI"}, "version": version},
            timeout=OSV_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
    except requests.RequestException:
        return []

    vulns: list[dict[str, Any]] = response.json().get("vulns", [])
    return vulns


def _severity_for(vuln: dict[str, Any]) -> Severity:
    severity = str(vuln.get("database_specific", {}).get("severity", "")).upper()
    return _SEVERITY_MAP.get(severity, "MEDIUM")


def _finding_for_vuln(
    vuln: dict[str, Any], name: str, version: str, path: Path, line: int
) -> Finding:
    vuln_id = vuln.get("id", "UNKNOWN")
    summary = str(vuln.get("summary", "")).strip()
    return Finding(
        rule=vuln_id,
        type="dependency",
        severity=_severity_for(vuln),
        file=str(path),
        line=line,
        message=f"{name} {version} has a known vulnerability ({vuln_id})",
        detail=summary or f"{name}=={version} matches a known OSV.dev advisory",
        remediation=_REMEDIATION_TEMPLATE.format(name=name, vuln_id=vuln_id),
    )


def _is_dependency_file(path: Path) -> bool:
    return (
        path.name == "pyproject.toml"
        or (path.name.startswith("requirements") and path.suffix == ".txt")
        or (path.name.startswith("environment") and path.suffix in {".yml", ".yaml"})
    )


def scan_file(path: Path) -> list[Finding]:
    """Parse a dependency file and check its ML packages against OSV.dev."""
    text = path.read_text(errors="ignore")
    if path.name == "pyproject.toml":
        packages = parse_pyproject_toml(text)
    elif path.name.startswith("environment") and path.suffix in {".yml", ".yaml"}:
        packages = parse_environment_yml(text)
    elif path.name.startswith("requirements") and path.suffix == ".txt":
        packages = parse_requirements_txt(text)
    else:
        return []

    findings = []
    for name, version, line in packages:
        if name not in ML_PACKAGES:
            continue
        for vuln in query_osv(name, version):
            findings.append(_finding_for_vuln(vuln, name, version, path, line))
    return findings


def scan_path(root: Path) -> Iterator[Finding]:
    """Walk `root` and yield CVE findings from requirements/pyproject/environment files."""
    if root.is_file():
        if _is_dependency_file(root):
            yield from scan_file(root)
        return
    extensions = frozenset({".txt", ".toml", ".yml", ".yaml"})
    for path in walk_files(root, include_extensions=extensions):
        if _is_dependency_file(path):
            yield from scan_file(path)
