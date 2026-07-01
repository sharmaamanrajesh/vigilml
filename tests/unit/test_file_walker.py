"""Unit tests for vigilml.utils.file_walker."""

from __future__ import annotations

from pathlib import Path

import pytest

from vigilml.utils.file_walker import walk_files

pytestmark = pytest.mark.unit


def test_yields_python_and_notebook_files(tmp_path: Path) -> None:
    (tmp_path / "train.py").write_text("print('hi')\n")
    (tmp_path / "notebook.ipynb").write_text("{}")
    (tmp_path / "README.md").write_text("# readme\n")

    found = {p.name for p in walk_files(tmp_path)}

    assert found == {"train.py", "notebook.ipynb"}


def test_recurses_into_subdirectories(tmp_path: Path) -> None:
    nested = tmp_path / "src" / "nested"
    nested.mkdir(parents=True)
    (nested / "deep.py").write_text("x = 1\n")

    found = {p.name for p in walk_files(tmp_path)}

    assert "deep.py" in found


def test_excludes_default_directories(tmp_path: Path) -> None:
    for excluded_dir in (".git", "__pycache__", ".venv", "venv", "env", "node_modules"):
        d = tmp_path / excluded_dir
        d.mkdir()
        (d / "should_not_appear.py").write_text("x = 1\n")

    (tmp_path / "visible.py").write_text("x = 1\n")

    found = {p.name for p in walk_files(tmp_path)}

    assert found == {"visible.py"}


def test_respects_gitignore_patterns(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("legacy/\nsecret.py\n")
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    (legacy / "old.py").write_text("x = 1\n")
    (tmp_path / "secret.py").write_text("x = 1\n")
    (tmp_path / "keep.py").write_text("x = 1\n")

    found = {p.name for p in walk_files(tmp_path)}

    assert found == {"keep.py"}


def test_custom_include_extensions(tmp_path: Path) -> None:
    (tmp_path / "config.yml").write_text("key: value\n")
    (tmp_path / "ignored.py").write_text("x = 1\n")

    found = {p.name for p in walk_files(tmp_path, include_extensions=frozenset({".yml"}))}

    assert found == {"config.yml"}


def test_returns_a_generator_not_a_list(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_text("x = 1\n")

    result = walk_files(tmp_path)

    assert not isinstance(result, list)


def test_missing_root_yields_nothing(tmp_path: Path) -> None:
    missing = tmp_path / "does_not_exist"

    assert list(walk_files(missing)) == []


def test_single_file_is_yielded_directly(tmp_path: Path) -> None:
    f = tmp_path / "train.py"
    f.write_text("x = 1\n")

    found = list(walk_files(f))

    assert found == [f]


def test_single_file_wrong_extension_yields_nothing(tmp_path: Path) -> None:
    f = tmp_path / "README.md"
    f.write_text("# readme\n")

    assert list(walk_files(f)) == []


def test_single_file_respects_custom_include_extensions(tmp_path: Path) -> None:
    f = tmp_path / "requirements.txt"
    f.write_text("torch==1.9.0\n")

    found = list(walk_files(f, include_extensions=frozenset({".txt"})))
    excluded = list(walk_files(f, include_extensions=frozenset({".py"})))

    assert found == [f]
    assert excluded == []
