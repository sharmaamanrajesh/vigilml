"""Unit tests for vigilml.scanner.dependencies."""

from __future__ import annotations

from pathlib import Path

import pytest
import requests
import responses

from vigilml.scanner.dependencies import (
    ML_PACKAGES,
    OSV_API_URL,
    parse_environment_yml,
    parse_pyproject_toml,
    parse_requirements_txt,
    query_osv,
    scan_file,
    scan_path,
)

pytestmark = pytest.mark.unit


# ── Parsing ──────────────────────────────────────────────────────────────────


def test_parse_requirements_txt_extracts_pinned_packages() -> None:
    text = "torch==1.9.0\nnumpy==1.21.0\n# a comment\n\npandas==1.3.0\n"

    packages = parse_requirements_txt(text)

    assert ("torch", "1.9.0", 1) in packages
    assert ("numpy", "1.21.0", 2) in packages
    assert ("pandas", "1.3.0", 5) in packages


def test_parse_requirements_txt_skips_comments_and_options() -> None:
    text = "-r base.txt\n# torch==9.9.9\ntorch==2.2.0\n"

    packages = parse_requirements_txt(text)

    assert packages == [("torch", "2.2.0", 3)]


def test_parse_requirements_txt_skips_unpinned_packages() -> None:
    text = "torch\nnumpy==1.26.0\n"

    packages = parse_requirements_txt(text)

    assert packages == [("numpy", "1.26.0", 2)]


def test_parse_requirements_txt_skips_range_specifiers() -> None:
    # >=, ~=, etc. name a minimum/range, not the version actually installed —
    # treating the bound as the installed version would false-positive.
    text = "torch>=2.2.0\nnumpy~=1.26.0\ntransformers<=4.40.0\n"

    assert parse_requirements_txt(text) == []


def test_parse_pyproject_toml_extracts_pep621_dependencies() -> None:
    text = (
        "[project]\n"
        'name = "x"\n'
        'dependencies = ["torch==2.2.0", "click==8.1"]\n'
    )

    packages = parse_pyproject_toml(text)

    names = {(name, version) for name, version, _ in packages}
    assert ("torch", "2.2.0") in names
    assert ("click", "8.1") in names


def test_parse_pyproject_toml_handles_malformed_toml() -> None:
    assert parse_pyproject_toml("not valid [[[ toml") == []


def test_parse_environment_yml_extracts_conda_dependencies() -> None:
    text = (
        "name: ml-project\n"
        "channels:\n"
        "  - conda-forge\n"
        "dependencies:\n"
        "  - python=3.10\n"
        "  - numpy=1.21.0\n"
    )

    packages = parse_environment_yml(text)

    names = {(name, version) for name, version, _ in packages}
    assert ("numpy", "1.21.0") in names
    assert ("python", "3.10") in names


def test_parse_environment_yml_extracts_nested_pip_dependencies() -> None:
    text = (
        "name: ml-project\n"
        "dependencies:\n"
        "  - python=3.10\n"
        "  - pip:\n"
        "    - torch==1.9.0\n"
        "    - transformers==4.18.0\n"
    )

    packages = parse_environment_yml(text)

    names = {(name, version) for name, version, _ in packages}
    assert ("torch", "1.9.0") in names
    assert ("transformers", "4.18.0") in names


def test_parse_environment_yml_stops_at_next_top_level_key() -> None:
    text = "dependencies:\n  - numpy=1.21.0\nother_key:\n  - numpy=9.9.9\n"

    packages = parse_environment_yml(text)

    assert packages == [("numpy", "1.21.0", 2)]


# ── OSV.dev querying ─────────────────────────────────────────────────────────


@responses.activate
def test_query_osv_returns_vulns_from_response() -> None:
    responses.add(
        responses.POST,
        OSV_API_URL,
        json={"vulns": [{"id": "GHSA-1234", "summary": "bad bug"}]},
        status=200,
    )

    vulns = query_osv("torch", "1.9.0")

    assert vulns == [{"id": "GHSA-1234", "summary": "bad bug"}]


@responses.activate
def test_query_osv_returns_empty_list_when_no_vulns() -> None:
    responses.add(responses.POST, OSV_API_URL, json={}, status=200)

    assert query_osv("numpy", "1.26.0") == []


@responses.activate
def test_query_osv_degrades_gracefully_on_network_error() -> None:
    responses.add(
        responses.POST, OSV_API_URL, body=requests.exceptions.ConnectionError("network down")
    )

    assert query_osv("torch", "1.9.0") == []


@responses.activate
def test_query_osv_degrades_gracefully_on_server_error() -> None:
    responses.add(responses.POST, OSV_API_URL, status=500)

    assert query_osv("torch", "1.9.0") == []


# ── scan_file ────────────────────────────────────────────────────────────────


@responses.activate
def test_scan_file_flags_vulnerable_ml_package(tmp_path: Path) -> None:
    responses.add(
        responses.POST,
        OSV_API_URL,
        json={"vulns": [{"id": "GHSA-1234", "summary": "remote code execution"}]},
        status=200,
    )
    path = tmp_path / "requirements.txt"
    path.write_text("torch==1.9.0\n")

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "GHSA-1234"
    assert findings[0].file == str(path)
    assert findings[0].line == 1
    assert findings[0].remediation


@responses.activate
def test_scan_file_skips_non_ml_packages(tmp_path: Path) -> None:
    responses.add(
        responses.POST,
        OSV_API_URL,
        json={"vulns": [{"id": "GHSA-9999"}]},
        status=200,
    )
    path = tmp_path / "requirements.txt"
    path.write_text("pandas==1.3.0\n")

    assert scan_file(path) == []


@responses.activate
def test_scan_file_returns_empty_when_no_vulns_found(tmp_path: Path) -> None:
    responses.add(responses.POST, OSV_API_URL, json={"vulns": []}, status=200)
    path = tmp_path / "requirements.txt"
    path.write_text("torch==2.2.0\n")

    assert scan_file(path) == []


def test_scan_file_returns_empty_for_unrelated_file(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("torch==1.9.0\n")

    assert scan_file(path) == []


@responses.activate
def test_scan_file_severity_maps_from_database_specific(tmp_path: Path) -> None:
    responses.add(
        responses.POST,
        OSV_API_URL,
        json={"vulns": [{"id": "GHSA-1", "database_specific": {"severity": "MODERATE"}}]},
        status=200,
    )
    path = tmp_path / "requirements.txt"
    path.write_text("torch==1.9.0\n")

    findings = scan_file(path)

    assert findings[0].severity == "MEDIUM"


# ── scan_path ────────────────────────────────────────────────────────────────


@responses.activate
def test_scan_path_aggregates_across_dependency_files(tmp_path: Path) -> None:
    responses.add(responses.POST, OSV_API_URL, json={"vulns": [{"id": "GHSA-1"}]}, status=200)

    (tmp_path / "requirements.txt").write_text("torch==1.9.0\n")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "x"\ndependencies = ["numpy==1.21.0"]\n'
    )
    (tmp_path / "README.md").write_text("not a dependency file\n")

    findings = list(scan_path(tmp_path))

    assert len(findings) == 2
    assert {f.file for f in findings} == {
        str(tmp_path / "requirements.txt"),
        str(tmp_path / "pyproject.toml"),
    }


@responses.activate
def test_scan_path_accepts_single_requirements_file(tmp_path: Path) -> None:
    responses.add(responses.POST, OSV_API_URL, json={"vulns": [{"id": "GHSA-1"}]}, status=200)
    path = tmp_path / "requirements.txt"
    path.write_text("torch==1.9.0\n")

    findings = list(scan_path(path))

    assert len(findings) == 1
    assert findings[0].file == str(path)


def test_scan_path_single_non_dependency_file_yields_nothing(tmp_path: Path) -> None:
    path = tmp_path / "notes.txt"
    path.write_text("torch==1.9.0\n")

    assert list(scan_path(path)) == []


# ── ML_PACKAGES coverage ─────────────────────────────────────────────────────


def test_ml_packages_includes_extended_package_list() -> None:
    expected = {
        "torch", "torchvision", "numpy", "scipy", "pillow",
        "transformers", "tensorflow", "tensorflow-cpu", "tensorflow-gpu",
        "keras", "scikit-learn", "langchain", "langchain-core",
        "langchain-community", "openai", "anthropic", "diffusers",
        "accelerate", "peft", "trl", "sentence-transformers",
    }
    assert expected <= ML_PACKAGES
