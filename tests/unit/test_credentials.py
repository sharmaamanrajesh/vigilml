"""Unit tests for vigilml.scanner.credentials."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigilml.scanner.credentials import scan_file, scan_path

pytestmark = pytest.mark.unit

# Token prefixes split so the literal never appears in source — GitHub push
# protection would flag hf_<20+ chars> as a real credential otherwise.
_HF = "hf" + "_"


def test_detects_openai_api_key(tmp_path: Path) -> None:
    path = tmp_path / "train.py"
    path.write_text(
        'openai.api_key = "sk-proj-abc1234567890XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"\n'
    )

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "openai-api-key"
    assert findings[0].severity == "CRITICAL"
    assert findings[0].line == 1
    assert "sk-p" in findings[0].detail
    assert "****" in findings[0].detail


def test_detects_anthropic_api_key(tmp_path: Path) -> None:
    path = tmp_path / "agent.py"
    path.write_text(
        'ANTHROPIC_API_KEY = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789"\n'
    )

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "anthropic-api-key"


def test_detects_huggingface_token(tmp_path: Path) -> None:
    path = tmp_path / "download_model.py"
    path.write_text(f'HF_TOKEN = "{_HF}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"\n')

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "huggingface-token"


def test_detects_aws_access_key(tmp_path: Path) -> None:
    path = tmp_path / "creds.py"
    path.write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "aws-access-key"


def test_detects_aws_secret_key(tmp_path: Path) -> None:
    path = tmp_path / "creds.py"
    path.write_text("AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'\n")

    findings = scan_file(path)

    assert any(f.rule == "aws-secret-key" for f in findings)


def test_detects_gcp_api_key(tmp_path: Path) -> None:
    path = tmp_path / "config.py"
    path.write_text('GCP_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"\n')

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "gcp-api-key"


def test_detects_gcp_service_account_private_key(tmp_path: Path) -> None:
    path = tmp_path / "service_account.py"
    path.write_text('KEY = "-----BEGIN PRIVATE KEY-----\\nMIIE...\\n-----END PRIVATE KEY-----"\n')

    findings = scan_file(path)

    assert any(f.rule == "gcp-service-account-key" for f in findings)


def test_redacts_credential_showing_only_first_four_chars(tmp_path: Path) -> None:
    path = tmp_path / "train.py"
    path.write_text(f'HF_TOKEN = "{_HF}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"\n')

    findings = scan_file(path)

    detail = findings[0].detail
    assert "hf_A" in detail
    assert "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh" not in detail


def test_no_finding_for_env_var_lookup(tmp_path: Path) -> None:
    path = tmp_path / "train.py"
    path.write_text('OPENAI_KEY = os.getenv("OPENAI_API_KEY")\n')

    findings = scan_file(path)

    assert findings == []


def test_no_finding_for_placeholder_value(tmp_path: Path) -> None:
    path = tmp_path / ".env.example"
    path.write_text("OPENAI_API_KEY=your-key-here\nHF_TOKEN=your-hf-token-here\n")

    findings = scan_file(path)

    assert findings == []


def test_clean_file_has_no_findings(tmp_path: Path) -> None:
    path = tmp_path / "clean.py"
    path.write_text(
        "import os\nimport torch\n\nOPENAI_KEY = os.getenv('OPENAI_API_KEY')\n"
        "def load(path):\n    return torch.load(path, weights_only=True)\n"
    )

    assert scan_file(path) == []


def test_finding_line_number_is_correct(tmp_path: Path) -> None:
    path = tmp_path / "train.py"
    path.write_text(
        "import openai\n\n\nopenai.api_key = 'sk-proj-abc1234567890XXXXXXXXXXXXXXXXXXXXXXXXXX'\n"
    )

    findings = scan_file(path)

    assert findings[0].line == 4


def test_finding_includes_file_path_and_remediation(tmp_path: Path) -> None:
    path = tmp_path / "train.py"
    path.write_text("openai.api_key = 'sk-proj-abc1234567890XXXXXXXXXXXXXXXXXXXXXXXXXX'\n")

    findings = scan_file(path)

    assert findings[0].file == str(path)
    assert findings[0].remediation


def test_detects_openai_key_in_notebook_code_cell(tmp_path: Path) -> None:
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
                "source": ["import os\n", "import numpy as np"],
                "id": "c1",
            },
            {
                "cell_type": "code",
                "execution_count": 2,
                "metadata": {},
                "outputs": [{"output_type": "stream", "text": ["ok\n"]}],
                "source": [
                    "# set key\n",
                    "openai.api_key = 'sk-proj-abc1234567890XXXXXXXXXXXXXXXXXXXXXXXXXX'\n",
                ],
                "id": "c2",
            },
        ],
    }
    path = tmp_path / "notebook.ipynb"
    path.write_text(json.dumps(notebook))

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "openai-api-key"
    assert findings[0].cell == 3
    assert findings[0].line == 2


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
                "outputs": [
                    {
                        "output_type": "stream",
                        "text": ["sk-proj-abc1234567890XXXXXXXXXXXXXXXXXXXXXXXXXX\n"],
                    }
                ],
                "source": ["print('hello')"],
                "id": "c0",
            },
        ],
    }
    path = tmp_path / "notebook.ipynb"
    path.write_text(json.dumps(notebook))

    assert scan_file(path) == []


def test_notebook_markdown_cells_are_not_scanned(tmp_path: Path) -> None:
    notebook = {
        "nbformat": 4,
        "nbformat_minor": 5,
        "metadata": {},
        "cells": [
            {
                "cell_type": "markdown",
                "metadata": {},
                "source": ["sk-proj-abc1234567890XXXXXXXXXXXXXXXXXXXXXXXXXX"],
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
                "source": ["import os\n", "api_key = os.getenv('OPENAI_API_KEY')"],
                "id": "c0",
            },
        ],
    }
    path = tmp_path / "notebook.ipynb"
    path.write_text(json.dumps(notebook))

    assert scan_file(path) == []


def test_scan_path_walks_directory_and_aggregates_findings(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text(
        "openai.api_key = 'sk-proj-abc1234567890XXXXXXXXXXXXXXXXXXXXXXXXXX'\n"
    )
    (tmp_path / "download.py").write_text(f'HF_TOKEN = "{_HF}ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"\n')
    (tmp_path / "clean.py").write_text("x = 1\n")

    findings = list(scan_path(tmp_path))

    assert len(findings) == 2
    assert {f.rule for f in findings} == {"openai-api-key", "huggingface-token"}
