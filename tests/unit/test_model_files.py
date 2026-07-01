"""Unit tests for vigilml.scanner.model_files."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vigilml.scanner.model_files import scan_file, scan_path

pytestmark = pytest.mark.unit


def test_flags_pkl_file_as_unsafe(tmp_path: Path) -> None:
    path = tmp_path / "model.pkl"
    path.write_bytes(b"")

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "unsafe-pickle-file"
    assert findings[0].severity == "HIGH"
    assert findings[0].file == str(path)


def test_flags_pickle_file_as_unsafe(tmp_path: Path) -> None:
    path = tmp_path / "model.pickle"
    path.write_bytes(b"")

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "unsafe-pickle-file"


def test_flags_joblib_file_as_unsafe(tmp_path: Path) -> None:
    path = tmp_path / "model.joblib"
    path.write_bytes(b"")

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "unsafe-joblib-file"
    assert findings[0].severity == "HIGH"


def test_safetensors_file_is_not_flagged(tmp_path: Path) -> None:
    path = tmp_path / "model.safetensors"
    path.write_bytes(b"")

    assert scan_file(path) == []


def test_detects_pickle_load(tmp_path: Path) -> None:
    path = tmp_path / "inference.py"
    path.write_text("model = pickle.load(open('model.pkl', 'rb'))\n")

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "pickle-load"
    assert findings[0].severity == "HIGH"
    assert findings[0].line == 1


def test_detects_pickle_loads(tmp_path: Path) -> None:
    path = tmp_path / "inference.py"
    path.write_text("model = pickle.loads(data)\n")

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "pickle-loads"
    assert findings[0].severity == "HIGH"


def test_detects_torch_load_without_weights_only(tmp_path: Path) -> None:
    path = tmp_path / "inference.py"
    path.write_text("model = torch.load('model.pt')\n")

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "torch-load-without-weights-only"
    assert findings[0].severity == "LOW"


def test_torch_load_with_weights_only_true_is_not_flagged(tmp_path: Path) -> None:
    path = tmp_path / "inference.py"
    path.write_text("model = torch.load('model.pt', weights_only=True)\n")

    assert scan_file(path) == []


def test_torch_load_with_weights_only_false_is_flagged(tmp_path: Path) -> None:
    path = tmp_path / "inference.py"
    path.write_text("model = torch.load('model.pt', weights_only=False)\n")

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "torch-load-without-weights-only"


def test_clean_python_file_has_no_findings(tmp_path: Path) -> None:
    path = tmp_path / "clean.py"
    path.write_text(
        "import torch\n\n\ndef load(path):\n    return torch.load(path, weights_only=True)\n"
    )

    assert scan_file(path) == []


def test_finding_includes_remediation(tmp_path: Path) -> None:
    path = tmp_path / "inference.py"
    path.write_text("pickle.load(f)\n")

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
                "source": ["import torch\n", "import pickle"],
                "id": "c1",
            },
            {
                "cell_type": "code",
                "execution_count": 2,
                "metadata": {},
                "outputs": [{"output_type": "stream", "text": ["ok\n"]}],
                "source": ["# load model\n", "model = torch.load('model.pt')\n"],
                "id": "c2",
            },
        ],
    }
    path = tmp_path / "notebook.ipynb"
    path.write_text(json.dumps(notebook))

    findings = scan_file(path)

    assert len(findings) == 1
    assert findings[0].rule == "torch-load-without-weights-only"
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
                "outputs": [{"output_type": "stream", "text": ["pickle.load(f)\n"]}],
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
                "source": ["import torch\n", "torch.load('model.pt', weights_only=True)"],
                "id": "c0",
            },
        ],
    }
    path = tmp_path / "notebook.ipynb"
    path.write_text(json.dumps(notebook))

    assert scan_file(path) == []


def test_scan_path_finds_both_files_and_code_patterns(tmp_path: Path) -> None:
    (tmp_path / "model.pkl").write_bytes(b"")
    (tmp_path / "inference.py").write_text("torch.load('m.pt')\npickle.load(f)\n")
    (tmp_path / "clean.py").write_text("x = 1\n")

    findings = list(scan_path(tmp_path))

    rules = {f.rule for f in findings}
    assert rules == {"unsafe-pickle-file", "torch-load-without-weights-only", "pickle-load"}
