"""Generator-based file system traversal for VigilML scanners.

See docs/DECISIONS.md ADR-005 — large repos can have tens of thousands of
files, so the walker must stream paths rather than build a list in memory.
"""

from __future__ import annotations

import fnmatch
from collections.abc import Iterator
from pathlib import Path

DEFAULT_EXCLUDE_DIRS: frozenset[str] = frozenset(
    {".git", "__pycache__", ".venv", "venv", "env", "node_modules", "dist", "build"}
)

DEFAULT_INCLUDE_EXTENSIONS: frozenset[str] = frozenset({".py", ".ipynb"})


def walk_files(
    root: Path,
    include_extensions: frozenset[str] | None = None,
    include_filenames: frozenset[str] | None = None,
    include_name_substrings: frozenset[str] | None = None,
    exclude_dirs: frozenset[str] | None = None,
) -> Iterator[Path]:
    """Yield files under `root` whose suffix is in `include_extensions`.

    `include_filenames` additionally matches on the full file name, for
    extension-less files (`Dockerfile`) or dotfiles whose "suffix" (per
    `Path.suffix`) doesn't equal the name (`.env`, `.env.local`).
    `include_name_substrings` matches case-insensitively on any substring
    of the file name, for extension-less files whose name varies
    (`TestDockerfile`, `backend.Dockerfile.prod`).

    When `root` is a regular file, yield it directly (if it matches)
    instead of walking. When `root` is a directory, recurse as normal.
    Directories named in `exclude_dirs`, directories ending in `.egg-info`,
    and paths matched by a `.gitignore` at `root` (if present) are never
    descended into or yielded.
    """
    extensions = (
        include_extensions if include_extensions is not None else DEFAULT_INCLUDE_EXTENSIONS
    )
    filenames = include_filenames if include_filenames is not None else frozenset()
    substrings = include_name_substrings if include_name_substrings is not None else frozenset()

    if root.is_file():
        if _matches(root, extensions, filenames, substrings):
            yield root
        return

    if not root.is_dir():
        return

    excluded = exclude_dirs if exclude_dirs is not None else DEFAULT_EXCLUDE_DIRS
    gitignore_patterns = _load_gitignore_patterns(root)

    yield from _walk(root, root, extensions, filenames, substrings, excluded, gitignore_patterns)


def _matches(
    entry: Path,
    extensions: frozenset[str],
    filenames: frozenset[str],
    substrings: frozenset[str],
) -> bool:
    if entry.suffix in extensions or entry.name in filenames:
        return True
    if substrings:
        lowered = entry.name.lower()
        return any(substring in lowered for substring in substrings)
    return False


def _walk(
    directory: Path,
    root: Path,
    extensions: frozenset[str],
    filenames: frozenset[str],
    substrings: frozenset[str],
    excluded: frozenset[str],
    gitignore_patterns: list[str],
) -> Iterator[Path]:
    try:
        entries = sorted(directory.iterdir())
    except (PermissionError, FileNotFoundError):
        return

    for entry in entries:
        if _is_gitignored(entry, root, gitignore_patterns):
            continue

        if entry.is_dir():
            if entry.name in excluded or entry.suffix == ".egg-info":
                continue
            yield from _walk(
                entry, root, extensions, filenames, substrings, excluded, gitignore_patterns
            )
        elif entry.is_file() and _matches(entry, extensions, filenames, substrings):
            yield entry


def _load_gitignore_patterns(root: Path) -> list[str]:
    """Read simple, non-negated patterns from a `.gitignore` at `root`."""
    gitignore = root / ".gitignore"
    if not gitignore.is_file():
        return []

    patterns = []
    for line in gitignore.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        patterns.append(line.rstrip("/"))
    return patterns


def _is_gitignored(path: Path, root: Path, patterns: list[str]) -> bool:
    if not patterns:
        return False

    relative = str(path.relative_to(root))
    return any(
        fnmatch.fnmatch(path.name, pattern) or fnmatch.fnmatch(relative, pattern)
        for pattern in patterns
    )
