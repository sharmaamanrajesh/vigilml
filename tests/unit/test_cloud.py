"""Unit tests for vigilml.scanner.cloud."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigilml.scanner.cloud import scan_file, scan_path

pytestmark = pytest.mark.unit


def test_detects_s3_public_read_acl(tmp_path: Path) -> None:
    path = tmp_path / "upload.py"
    path.write_text(
        "s3.put_object(\n"
        '    Bucket="results",\n'
        '    Key="out.json",\n'
        '    ACL="public-read",\n'
        ")\n"
    )

    findings = scan_file(path)

    assert any(f.rule == "s3-public-write" for f in findings)
    s3_finding = next(f for f in findings if f.rule == "s3-public-write")
    assert s3_finding.severity == "MEDIUM"
    assert s3_finding.line == 4


def test_detects_s3_public_read_write_acl(tmp_path: Path) -> None:
    path = tmp_path / "upload.py"
    path.write_text('s3.put_object(Bucket="b", Key="k", ACL="public-read-write")\n')

    findings = scan_file(path)

    assert any(f.rule == "s3-public-write" for f in findings)


def test_private_acl_is_not_flagged(tmp_path: Path) -> None:
    path = tmp_path / "upload.py"
    path.write_text('s3.put_object(Bucket="results", Key="out.json", ACL="private")\n')

    findings = scan_file(path)

    assert not any(f.rule == "s3-public-write" for f in findings)


def test_detects_hardcoded_bucket_name(tmp_path: Path) -> None:
    path = tmp_path / "upload.py"
    path.write_text('s3.put_object(Bucket="my-ml-results", Key="out.json")\n')

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "hardcoded-bucket-name"
    assert findings[0].severity == "LOW"


def test_bucket_name_from_env_var_is_not_flagged(tmp_path: Path) -> None:
    path = tmp_path / "upload.py"
    path.write_text('s3.put_object(Bucket=os.getenv("BUCKET_NAME"), Key="out.json")\n')

    assert scan_file(path) == []


def test_detects_chmod_777_shell_command(tmp_path: Path) -> None:
    path = tmp_path / "setup.py"
    path.write_text('os.system("chmod 777 /data/models")\n')

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "world-readable-permissions"
    assert findings[0].severity == "MEDIUM"


def test_detects_os_chmod_with_octal_777(tmp_path: Path) -> None:
    path = tmp_path / "setup.py"
    path.write_text('os.chmod("/data/models", 0o777)\n')

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "world-readable-permissions"


def test_chmod_644_is_not_flagged(tmp_path: Path) -> None:
    path = tmp_path / "setup.py"
    path.write_text('os.chmod("/data/models", 0o644)\n')

    assert scan_file(path) == []


def test_clean_python_file_has_no_findings(tmp_path: Path) -> None:
    path = tmp_path / "clean.py"
    path.write_text(
        "import boto3\nimport os\n\n"
        "BUCKET = os.getenv('BUCKET_NAME')\n\n"
        "def upload(path):\n"
        "    s3 = boto3.client('s3')\n"
        "    s3.put_object(Bucket=BUCKET, Key='out.json', ACL='private')\n"
    )

    assert scan_file(path) == []


def test_finding_includes_remediation(tmp_path: Path) -> None:
    path = tmp_path / "upload.py"
    path.write_text('ACL="public-read"\n')

    findings = scan_file(path)

    assert findings[0].remediation


def test_detects_pattern_in_notebook_code_cell(tmp_path: Path) -> None:
    notebook = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {},
        "cells": [
            {"cell_type": "markdown", "metadata": {}, "source": ["# intro"], "id": "c0"},
            {
                "cell_type": "code",
                "execution_count": 1,
                "metadata": {},
                "outputs": [],
                "source": ["import boto3\n", "s3 = boto3.client('s3')"],
                "id": "c1",
            },
            {
                "cell_type": "code",
                "execution_count": 2,
                "metadata": {},
                "outputs": [{"output_type": "stream", "text": ["ok\n"]}],
                "source": [
                    "# upload\n",
                    "s3.put_object(Bucket='r', Key='k', ACL='public-read')\n",
                ],
                "id": "c2",
            },
        ],
    }
    path = tmp_path / "notebook.ipynb"
    path.write_text(json.dumps(notebook))

    findings = scan_file(path)

    assert any(f.rule == "s3-public-write" and f.cell == 3 and f.line == 2 for f in findings)


def test_notebook_output_cells_are_not_scanned(tmp_path: Path) -> None:
    notebook = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {},
        "cells": [
            {
                "cell_type": "code",
                "execution_count": 1,
                "metadata": {},
                "outputs": [{"output_type": "stream", "text": ["ACL='public-read'\n"]}],
                "source": ["print('hello')"],
                "id": "c0",
            },
        ],
    }
    path = tmp_path / "notebook.ipynb"
    path.write_text(json.dumps(notebook))

    assert scan_file(path) == []


def test_clean_notebook_has_no_findings(tmp_path: Path) -> None:
    notebook = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {},
        "cells": [
            {
                "cell_type": "code",
                "execution_count": 1,
                "metadata": {},
                "outputs": [],
                "source": ["import boto3\n", "s3 = boto3.client('s3')"],
                "id": "c0",
            },
        ],
    }
    path = tmp_path / "notebook.ipynb"
    path.write_text(json.dumps(notebook))

    assert scan_file(path) == []


def test_scan_path_aggregates_findings(tmp_path: Path) -> None:
    (tmp_path / "upload.py").write_text(
        's3.put_object(Bucket="my-ml-results", Key="k", ACL="public-read")\n'
    )
    (tmp_path / "setup.py").write_text('os.chmod("/data", 0o777)\n')
    (tmp_path / "clean.py").write_text("x = 1\n")

    findings = list(scan_path(tmp_path))

    rules = {f.rule for f in findings}
    assert rules == {"s3-public-write", "hardcoded-bucket-name", "world-readable-permissions"}
