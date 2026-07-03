# vigilml: ignore-file
# This file's own message/remediation strings describe the exact code
# patterns (eval(), os.system(), pickle.load(), etc.) it detects, which
# match this scanner's own rules when vigilml scans its own source. All
# findings here are false positives.
"""Unsafe model deserialisation detection.

Flags unsafe binary model formats by extension, unsafe deserialisation and
code-execution call patterns, and unverified model-loading calls in `.py`
files and notebook code-cell sources (see docs/DECISIONS.md ADR-006).
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from vigilml.scanner import Finding, Severity
from vigilml.utils.file_walker import walk_files
from vigilml.utils.suppression import (
    filter_notebook_suppressed,
    filter_suppressed,
    has_ignore_file_marker,
    notebook_has_ignore_file_marker,
)


@dataclass(frozen=True)
class _FileRule:
    rule: str
    severity: Severity
    message: str
    remediation: str


_UNSAFE_FILE_REMEDIATION = (
    "Convert this file to a safe serialisation format such as safetensors. "
    "Pickle-based formats can execute arbitrary code when deserialised."
)

_DILL_FILE_RULE = _FileRule(
    rule="unsafe-dill-file",
    severity="HIGH",
    message=(
        "dill serialisation file detected — dill is a pickle superset and carries "
        "identical arbitrary code execution risk when loaded from untrusted sources"
    ),
    remediation=(
        "Replace dill serialisation with safetensors or ONNX format. If dill is "
        "required, verify the file hash against a known-good value before loading."
    ),
)

_PT_FILE_RULE = _FileRule(
    rule="unsafe-pt-file",
    severity="MEDIUM",
    message=(
        "PyTorch .pt file detected — verify it is loaded with torch.load(weights_only=True)"
    ),
    remediation=(
        "Ensure all torch.load() calls for this file use weights_only=True. Consider "
        "converting to safetensors format."
    ),
)

_HDF5_FILE_RULE = _FileRule(
    rule="unsafe-hdf5-file",
    severity="MEDIUM",
    message=(
        "HDF5 model file detected — HDF5 files can embed executable Lambda layers in "
        "Keras models"
    ),
    remediation=(
        "Load HDF5 files only from trusted sources. Use keras.saving.save_model() with "
        "save_format='keras' for newer Keras versions which uses a safer format."
    ),
)

_CKPT_FILE_RULE = _FileRule(
    rule="unsafe-checkpoint-file",
    severity="MEDIUM",
    message=(
        "TensorFlow/PyTorch checkpoint file detected — checkpoint files use "
        "pickle-based serialisation"
    ),
    remediation=(
        "Verify the checkpoint source before loading. For PyTorch use "
        "weights_only=True. For TensorFlow prefer SavedModel format over checkpoints."
    ),
)

_NUMPY_FILE_RULE = _FileRule(
    rule="numpy-array-file",
    severity="LOW",
    message="NumPy array file detected — flag if loaded with allow_pickle=True",
    remediation=(
        "Avoid allow_pickle=True when loading this file unless the array genuinely "
        "contains trusted object data."
    ),
)

_BIN_FILE_RULE = _FileRule(
    rule="huggingface-bin-file",
    severity="MEDIUM",
    message=(
        "HuggingFace model binary detected — .bin weight files use pickle "
        "serialisation internally"
    ),
    remediation=(
        "Download model files only from verified HuggingFace model cards. Prefer "
        "models that offer safetensors format. Pin a specific commit hash in "
        "from_pretrained() calls."
    ),
)

_FILE_RULES: dict[str, _FileRule] = {
    ".pkl": _FileRule(
        rule="unsafe-pickle-file",
        severity="HIGH",
        message="Unsafe model file format detected (.pkl)",
        remediation=_UNSAFE_FILE_REMEDIATION,
    ),
    ".pickle": _FileRule(
        rule="unsafe-pickle-file",
        severity="HIGH",
        message="Unsafe model file format detected (.pickle)",
        remediation=_UNSAFE_FILE_REMEDIATION,
    ),
    ".joblib": _FileRule(
        rule="unsafe-joblib-file",
        severity="HIGH",
        message="Unsafe model file format detected (.joblib)",
        remediation=_UNSAFE_FILE_REMEDIATION,
    ),
    ".dill": _DILL_FILE_RULE,
    ".pt": _PT_FILE_RULE,
    ".h5": _HDF5_FILE_RULE,
    ".hdf5": _HDF5_FILE_RULE,
    ".ckpt": _CKPT_FILE_RULE,
    ".npy": _NUMPY_FILE_RULE,
    ".npz": _NUMPY_FILE_RULE,
}

# ---------------------------------------------------------------------------
# Simple, single-line code patterns
# ---------------------------------------------------------------------------

_PICKLE_LOADS_RE = re.compile(r"pickle\.loads\(")
_PICKLE_LOAD_RE = re.compile(r"pickle\.load\(")
_TORCH_LOAD_RE = re.compile(r"torch\.load\(([^)]*)\)")
_DILL_LOADS_RE = re.compile(r"dill\.loads\(")
_DILL_LOAD_RE = re.compile(r"dill\.load\(")
_NUMPY_LOAD_RE = re.compile(r"\b(?:numpy|np)\.load\(([^)]*)\)")
_SHELVE_OPEN_RE = re.compile(r"shelve\.open\(")
_MARSHAL_LOADS_RE = re.compile(r"marshal\.loads\(")
_OS_SYSTEM_RE = re.compile(r"os\.system\(")
_SHELL_TRUE_RE = re.compile(r"shell\s*=\s*True")
# The negative lookbehind excludes method calls such as PyTorch's
# `model.eval()` — only the eval/exec builtins are dangerous.
_EVAL_RE = re.compile(r"(?<![\w.])eval\(([^)]*)\)")
_EXEC_RE = re.compile(r"(?<![\w.])exec\(([^)]*)\)")
_TRUST_REMOTE_CODE_RE = re.compile(r"trust_remote_code\s*=\s*True")

_PICKLE_REMEDIATION = (
    "Avoid deserialising pickle data, especially from untrusted sources — "
    "pickle.load can execute arbitrary code. Use a safe format such as "
    "safetensors, or validate the source before loading."
)
_TORCH_REMEDIATION = (
    "Pass weights_only=True to torch.load() so only tensor data is "
    "deserialised, not arbitrary Python objects."
)
_DILL_CALL_REMEDIATION = (
    "Avoid dill for model persistence. Use safetensors or ONNX. If dill is "
    "required, only load from sources you control and have verified."
)
_NUMPY_ALLOW_PICKLE_REMEDIATION = (
    "Remove allow_pickle=True unless absolutely required. If loading object "
    "arrays, consider converting data to a safe format first."
)
_SHELVE_REMEDIATION = (
    "Replace shelve with a safe key-value store such as SQLite (via sqlite3) "
    "or a JSON file for simple cases."
)
_MARSHAL_REMEDIATION = (
    "Do not use marshal for data persistence or IPC. Use JSON, msgpack, or "
    "Protocol Buffers instead."
)
_OS_SYSTEM_REMEDIATION = (
    "Replace os.system() with subprocess.run() using a list argument (not a "
    "shell string) and shell=False."
)
_SUBPROCESS_SHELL_REMEDIATION = (
    "Remove shell=True and pass the command as a list: "
    "subprocess.run(['cmd', 'arg1', 'arg2'])"
)
_EVAL_REMEDIATION = (
    "Remove eval() entirely. If evaluating mathematical expressions use "
    "ast.literal_eval() or the numexpr library. If parsing config use JSON "
    "or TOML."
)
_EXEC_REMEDIATION = (
    "Remove exec() entirely. Refactor to use explicit function calls or "
    "importlib for dynamic imports."
)
_TRUST_REMOTE_CODE_REMEDIATION = (
    "Remove trust_remote_code=True unless you have audited every file in the "
    "model repository. Only set this for models you fully control or have "
    "thoroughly reviewed."
)


def _is_string_literal(value: str) -> bool:
    stripped = value.strip()
    return bool(stripped) and stripped[0] in "'\""


def _scan_line(line: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    """Yield (rule, severity, message, remediation, column) for `line`."""
    if match := _PICKLE_LOADS_RE.search(line):
        yield (
            "pickle-loads",
            "HIGH",
            "pickle.loads() call detected",
            _PICKLE_REMEDIATION,
            match.start() + 1,
        )
    if match := _PICKLE_LOAD_RE.search(line):
        yield (
            "pickle-load",
            "HIGH",
            "pickle.load() call detected",
            _PICKLE_REMEDIATION,
            match.start() + 1,
        )
    if (match := _TORCH_LOAD_RE.search(line)) and "weights_only=True" not in match.group(1):
        yield (
            "torch-load-without-weights-only",
            "LOW",
            "torch.load() call without weights_only=True",
            _TORCH_REMEDIATION,
            match.start() + 1,
        )
    if match := _DILL_LOADS_RE.search(line):
        yield (
            "dill-loads",
            "HIGH",
            "dill.load() call detected — dill deserialises arbitrary Python objects "
            "and can execute malicious code",
            _DILL_CALL_REMEDIATION,
            match.start() + 1,
        )
    if match := _DILL_LOAD_RE.search(line):
        yield (
            "dill-load",
            "HIGH",
            "dill.load() call detected — dill deserialises arbitrary Python objects "
            "and can execute malicious code",
            _DILL_CALL_REMEDIATION,
            match.start() + 1,
        )
    if (match := _NUMPY_LOAD_RE.search(line)) and "allow_pickle=True" in re.sub(
        r"\s+", "", match.group(1)
    ):
        yield (
            "numpy-allow-pickle",
            "HIGH",
            "numpy.load() with allow_pickle=True detected — allows arbitrary "
            "Python object deserialisation",
            _NUMPY_ALLOW_PICKLE_REMEDIATION,
            match.start() + 1,
        )
    if match := _SHELVE_OPEN_RE.search(line):
        yield (
            "shelve-open",
            "MEDIUM",
            "shelve.open() detected — Python shelve uses pickle internally and "
            "carries the same deserialisation risks",
            _SHELVE_REMEDIATION,
            match.start() + 1,
        )
    if match := _MARSHAL_LOADS_RE.search(line):
        yield (
            "marshal-loads",
            "HIGH",
            "marshal.loads() detected — marshal deserialises Python bytecode and "
            "can execute arbitrary code",
            _MARSHAL_REMEDIATION,
            match.start() + 1,
        )
    if match := _OS_SYSTEM_RE.search(line):
        yield (
            "os-system",
            "HIGH",
            "os.system() call detected — vulnerable to command injection if any "
            "part of the command string is user-controlled",
            _OS_SYSTEM_REMEDIATION,
            match.start() + 1,
        )
    if match := _SHELL_TRUE_RE.search(line):
        yield (
            "subprocess-shell-true",
            "HIGH",
            "subprocess called with shell=True — shell=True enables command "
            "injection if any part of the command is user-controlled",
            _SUBPROCESS_SHELL_REMEDIATION,
            match.start() + 1,
        )
    if (match := _EVAL_RE.search(line)) and not _is_string_literal(match.group(1)):
        yield (
            "eval-non-literal",
            "CRITICAL",
            "eval() called with a non-literal argument — eval executes arbitrary "
            "Python code",
            _EVAL_REMEDIATION,
            match.start() + 1,
        )
    if (match := _EXEC_RE.search(line)) and not _is_string_literal(match.group(1)):
        yield (
            "exec-non-literal",
            "CRITICAL",
            "exec() called with a non-literal argument — exec executes arbitrary "
            "Python code",
            _EXEC_REMEDIATION,
            match.start() + 1,
        )
    if match := _TRUST_REMOTE_CODE_RE.search(line):
        yield (
            "trust-remote-code",
            "CRITICAL",
            "trust_remote_code=True detected — this allows the model repository "
            "to execute arbitrary Python code on your machine during model loading",
            _TRUST_REMOTE_CODE_REMEDIATION,
            match.start() + 1,
        )


# ---------------------------------------------------------------------------
# Calls whose arguments must be inspected as a whole (nesting- and
# multi-line-aware) rather than line-by-line — e.g. `yaml.load(open(x),
# Loader=yaml.UnsafeLoader)` splits its `Loader=` kwarg onto another line in
# common real-world formatting, and a naive `[^)]*\)` regex would stop at the
# first `)` (the one closing the nested `open(...)` call).
# ---------------------------------------------------------------------------

_CALL_NAMES: tuple[str, ...] = ("yaml.load", "from_pretrained", "hf_hub_download")
_CALL_PATTERN = re.compile(r"\b(" + "|".join(re.escape(n) for n in _CALL_NAMES) + r")\s*\(")

_YAML_SAFE_LOADER_REMEDIATION = (
    "Replace yaml.load(data) with yaml.safe_load(data) or explicitly pass "
    "Loader=yaml.SafeLoader."
)
_YAML_UNSAFE_LOADER_REMEDIATION = (
    "Replace with yaml.safe_load() immediately. The unsafe loaders exist only "
    "for backwards compatibility and should never be used with untrusted data."
)
_MODEL_ID_VARIABLE_REMEDIATION = (
    "Use string literals for model IDs where possible so the source is "
    "auditable in code review. If dynamic, validate the model ID against an "
    "allowlist."
)
_MISSING_REVISION_REMEDIATION = (
    "Add revision='main' or a specific commit hash: "
    "from_pretrained('org/model', revision='abc123def456'). This ensures "
    "reproducibility and guards against supply chain changes."
)


def _extract_call_args(text: str, start: int) -> str | None:
    """Return the text of a call's arguments, given the index just after its
    opening `(`, handling nested brackets and string quotes so a nested call
    (or a multi-line argument list) doesn't terminate extraction early."""
    depth = 1
    i = start
    in_string: str | None = None
    while i < len(text):
        ch = text[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == in_string:
                in_string = None
        elif ch in "'\"":
            in_string = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return text[start:i]
        i += 1
    return None


def _line_and_column(text: str, offset: int) -> tuple[int, int]:
    line_start = text.rfind("\n", 0, offset) + 1
    line = text.count("\n", 0, offset) + 1
    return line, offset - line_start + 1


def _check_yaml_load(args_text: str) -> tuple[str, Severity, str, str] | None:
    normalized = re.sub(r"\s+", "", args_text)
    if "Loader=yaml.SafeLoader" in normalized:
        return None
    if "Loader=yaml.Loader" in normalized or "Loader=yaml.UnsafeLoader" in normalized:
        return (
            "yaml-unsafe-loader",
            "CRITICAL",
            "yaml.load() with unsafe Loader explicitly set — this allows "
            "arbitrary Python code execution when parsing YAML",
            _YAML_UNSAFE_LOADER_REMEDIATION,
        )
    return (
        "yaml-load-without-safeloader",
        "HIGH",
        "yaml.load() without SafeLoader detected — PyYAML's default loader "
        "can execute arbitrary Python when parsing untrusted YAML",
        _YAML_SAFE_LOADER_REMEDIATION,
    )


def _check_model_download(args_text: str) -> Iterator[tuple[str, Severity, str, str]]:
    if args_text.strip() and not _is_string_literal(args_text):
        yield (
            "model-id-variable",
            "MEDIUM",
            "from_pretrained() called with a variable model ID — the model "
            "source cannot be verified statically",
            _MODEL_ID_VARIABLE_REMEDIATION,
        )
    if not re.search(r"\brevision\s*=", args_text):
        yield (
            "missing-revision",
            "MEDIUM",
            "Model loaded without pinning a revision or commit hash — the "
            "model weights could change between runs without notice",
            _MISSING_REVISION_REMEDIATION,
        )


def _scan_calls(text: str) -> Iterator[tuple[str, Severity, str, str, int, int]]:
    """Yield (rule, severity, message, remediation, line, column) for calls
    that need full, nesting-aware argument inspection."""
    for match in _CALL_PATTERN.finditer(text):
        args_text = _extract_call_args(text, match.end())
        if args_text is None:
            continue
        line, column = _line_and_column(text, match.start())

        if match.group(1) == "yaml.load":
            result = _check_yaml_load(args_text)
            if result is not None:
                rule, severity, message, remediation = result
                yield rule, severity, message, remediation, line, column
        else:
            for rule, severity, message, remediation in _check_model_download(args_text):
                yield rule, severity, message, remediation, line, column


# ---------------------------------------------------------------------------
# AST-based scanning — the primary path for Python source. Parsing instead
# of pattern-matching means comments, docstrings, and method calls such as
# PyTorch's `model.eval()` can never be mistaken for the eval() builtin,
# and call arguments are inspected structurally. The regex scan above is
# kept only as a fallback for source that does not parse.
# ---------------------------------------------------------------------------

_CodeFinding = tuple[str, Severity, str, str, int, int]

# `np` is seeded so `np.load(..., allow_pickle=True)` is caught in notebook
# cells whose `import numpy as np` lives in a different cell.
_DEFAULT_ALIASES: dict[str, str] = {"np": "numpy"}

_HF_MODULES = frozenset(
    {"transformers", "huggingface_hub", "diffusers", "sentence_transformers", "peft"}
)

_SIMPLE_CALL_RULES: dict[str, tuple[str, Severity, str, str]] = {
    "pickle.loads": ("pickle-loads", "HIGH", "pickle.loads() call detected", _PICKLE_REMEDIATION),
    "pickle.load": ("pickle-load", "HIGH", "pickle.load() call detected", _PICKLE_REMEDIATION),
    "dill.loads": (
        "dill-loads",
        "HIGH",
        "dill.loads() call detected — dill deserialises arbitrary Python objects "
        "and can execute malicious code",
        _DILL_CALL_REMEDIATION,
    ),
    "dill.load": (
        "dill-load",
        "HIGH",
        "dill.load() call detected — dill deserialises arbitrary Python objects "
        "and can execute malicious code",
        _DILL_CALL_REMEDIATION,
    ),
    "shelve.open": (
        "shelve-open",
        "MEDIUM",
        "shelve.open() detected — Python shelve uses pickle internally and "
        "carries the same deserialisation risks",
        _SHELVE_REMEDIATION,
    ),
    "marshal.loads": (
        "marshal-loads",
        "HIGH",
        "marshal.loads() detected — marshal deserialises Python bytecode and "
        "can execute arbitrary code",
        _MARSHAL_REMEDIATION,
    ),
    "os.system": (
        "os-system",
        "HIGH",
        "os.system() call detected — vulnerable to command injection if any "
        "part of the command string is user-controlled",
        _OS_SYSTEM_REMEDIATION,
    ),
}


def _collect_imports(tree: ast.AST) -> tuple[dict[str, str], bool]:
    """Return (alias map, True if a HuggingFace library is imported).

    The alias map resolves local names to what they were bound to at import
    time, e.g. `import numpy as np` maps np -> numpy and `from torch import
    load as tl` maps tl -> torch.load.
    """
    aliases = dict(_DEFAULT_ALIASES)
    has_hf_import = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in _HF_MODULES:
                    has_hf_import = True
                if alias.asname:
                    aliases[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module:
            if node.module.split(".")[0] in _HF_MODULES:
                has_hf_import = True
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases, has_hf_import


def _resolved_call_name(func: ast.expr, aliases: dict[str, str]) -> str | None:
    """Return the dotted name a call targets with import aliases resolved,
    or None when the target is not a plain name/attribute chain."""
    parts: list[str] = []
    node = func
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(node.id)
    parts.reverse()
    parts[0] = aliases.get(parts[0], parts[0])
    return ".".join(parts)


def _is_str_constant(node: ast.expr) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _keyword_value(call: ast.Call, name: str) -> ast.expr | None:
    for keyword in call.keywords:
        if keyword.arg == name:
            return keyword.value
    return None


def _keyword_is_true(call: ast.Call, name: str) -> bool:
    value = _keyword_value(call, name)
    return isinstance(value, ast.Constant) and value.value is True


def _check_yaml_load_call(call: ast.Call) -> tuple[str, Severity, str, str] | None:
    loader = _keyword_value(call, "Loader")
    if loader is None and len(call.args) >= 2:
        loader = call.args[1]
    loader_name: str | None = None
    if isinstance(loader, ast.Attribute):
        loader_name = loader.attr
    elif isinstance(loader, ast.Name):
        loader_name = loader.id
    if loader_name is not None and loader_name.endswith("SafeLoader"):
        return None
    if loader_name in ("Loader", "UnsafeLoader"):
        return (
            "yaml-unsafe-loader",
            "CRITICAL",
            "yaml.load() with unsafe Loader explicitly set — this allows "
            "arbitrary Python code execution when parsing YAML",
            _YAML_UNSAFE_LOADER_REMEDIATION,
        )
    return (
        "yaml-load-without-safeloader",
        "HIGH",
        "yaml.load() without SafeLoader detected — PyYAML's default loader "
        "can execute arbitrary Python when parsing untrusted YAML",
        _YAML_SAFE_LOADER_REMEDIATION,
    )


def _check_model_download_call(call: ast.Call) -> Iterator[tuple[str, Severity, str, str]]:
    if call.args and not _is_str_constant(call.args[0]):
        yield (
            "model-id-variable",
            "MEDIUM",
            "from_pretrained() called with a variable model ID — the model "
            "source cannot be verified statically",
            _MODEL_ID_VARIABLE_REMEDIATION,
        )
    if _keyword_value(call, "revision") is None:
        yield (
            "missing-revision",
            "MEDIUM",
            "Model loaded without pinning a revision or commit hash — the "
            "model weights could change between runs without notice",
            _MISSING_REVISION_REMEDIATION,
        )


def _scan_call(
    call: ast.Call, aliases: dict[str, str], has_hf_import: bool
) -> Iterator[tuple[str, Severity, str, str]]:
    """Yield (rule, severity, message, remediation) for one call node."""
    name = _resolved_call_name(call.func, aliases)

    if name in _SIMPLE_CALL_RULES:
        yield _SIMPLE_CALL_RULES[name]
    elif name == "torch.load" and not _keyword_is_true(call, "weights_only"):
        yield (
            "torch-load-without-weights-only",
            "LOW",
            "torch.load() call without weights_only=True",
            _TORCH_REMEDIATION,
        )
    elif name == "numpy.load" and _keyword_is_true(call, "allow_pickle"):
        yield (
            "numpy-allow-pickle",
            "HIGH",
            "numpy.load() with allow_pickle=True detected — allows arbitrary "
            "Python object deserialisation",
            _NUMPY_ALLOW_PICKLE_REMEDIATION,
        )
    elif name == "yaml.load":
        if (result := _check_yaml_load_call(call)) is not None:
            yield result
    elif name in ("eval", "exec"):
        if call.args and not _is_str_constant(call.args[0]):
            yield (
                f"{name}-non-literal",
                "CRITICAL",
                f"{name}() called with a non-literal argument — {name} executes "
                "arbitrary Python code",
                _EVAL_REMEDIATION if name == "eval" else _EXEC_REMEDIATION,
            )
    elif (name is not None and name.rsplit(".", 1)[-1] == "hf_hub_download") or (
        # Only flag `X.from_pretrained(...)` when the file actually uses a
        # HuggingFace library — a project's own from_pretrained classmethod
        # (e.g. nanoGPT's GPT.from_pretrained) is not a supply chain risk.
        has_hf_import
        and isinstance(call.func, ast.Attribute)
        and call.func.attr == "from_pretrained"
    ):
        yield from _check_model_download_call(call)

    if _keyword_is_true(call, "shell"):
        yield (
            "subprocess-shell-true",
            "HIGH",
            "subprocess called with shell=True — shell=True enables command "
            "injection if any part of the command is user-controlled",
            _SUBPROCESS_SHELL_REMEDIATION,
        )
    if _keyword_is_true(call, "trust_remote_code"):
        yield (
            "trust-remote-code",
            "CRITICAL",
            "trust_remote_code=True detected — this allows the model repository "
            "to execute arbitrary Python code on your machine during model loading",
            _TRUST_REMOTE_CODE_REMEDIATION,
        )


def _scan_tree(tree: ast.AST) -> list[_CodeFinding]:
    aliases, has_hf_import = _collect_imports(tree)
    results: list[_CodeFinding] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        for rule, severity, message, remediation in _scan_call(node, aliases, has_hf_import):
            results.append(
                (rule, severity, message, remediation, node.lineno, node.col_offset + 1)
            )
    results.sort(key=lambda item: (item[4], item[5]))
    return results


def _scan_source_with_regex(text: str) -> list[_CodeFinding]:
    """Line/regex scan used only when Python source cannot be parsed."""
    results: list[_CodeFinding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, severity, message, remediation, column in _scan_line(line):
            results.append((rule, severity, message, remediation, line_number, column))
    for rule, severity, message, remediation, line_number, column in _scan_calls(text):
        results.append((rule, severity, message, remediation, line_number, column))
    results.sort(key=lambda item: (item[4], item[5]))
    return results


def _scan_python_source(text: str) -> list[_CodeFinding]:
    """Scan Python source text, preferring AST analysis over regexes."""
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return _scan_source_with_regex(text)
    return _scan_tree(tree)


_MAGIC_LINE_RE = re.compile(r"\s*[%!?]")


def _blank_magic_lines(text: str) -> str:
    """Blank out IPython magic/shell lines so a notebook cell parses as
    plain Python; the line count (and thus line numbers) is preserved."""
    return "\n".join(
        "" if _MAGIC_LINE_RE.match(line) else line for line in text.splitlines()
    )


def _scan_cell_source(text: str) -> list[_CodeFinding]:
    """Scan one notebook code cell: AST if it parses (retrying with IPython
    magics blanked out), regex fallback otherwise."""
    for candidate in (text, _blank_magic_lines(text)):
        try:
            tree = ast.parse(candidate)
        except (SyntaxError, ValueError):
            continue
        return _scan_tree(tree)
    return _scan_source_with_regex(text)


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for unsafe model files, deserialisation calls, or
    unverified model-loading patterns."""
    if path.suffix == ".bin":
        return _scan_bin_file(path)
    if path.suffix in _FILE_RULES:
        return [_unsafe_file_finding(path)]
    if path.suffix == ".ipynb":
        return _scan_notebook(path)
    if path.suffix == ".py":
        return _scan_text_file(path)
    return []


def _unsafe_file_finding(path: Path) -> Finding:
    rule = _FILE_RULES[path.suffix]
    return Finding(
        rule=rule.rule,
        type="model_file",
        severity=rule.severity,
        file=str(path),
        line=1,
        message=rule.message,
        detail=rule.message,
        remediation=rule.remediation,
    )


def _scan_bin_file(path: Path) -> list[Finding]:
    if not (path.parent / "config.json").is_file():
        return []
    return [
        Finding(
            rule=_BIN_FILE_RULE.rule,
            type="model_file",
            severity=_BIN_FILE_RULE.severity,
            file=str(path),
            line=1,
            message=_BIN_FILE_RULE.message,
            detail=_BIN_FILE_RULE.message,
            remediation=_BIN_FILE_RULE.remediation,
        )
    ]


def _scan_text_file(path: Path) -> list[Finding]:
    text = path.read_text(errors="ignore")
    if has_ignore_file_marker(text):
        return []

    findings = [
        _build_finding(rule, severity, message, remediation, path, line_number, column)
        for rule, severity, message, remediation, line_number, column in _scan_python_source(text)
    ]
    return filter_suppressed(findings, text)


def _scan_notebook(path: Path) -> list[Finding]:
    try:
        notebook = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []

    if notebook_has_ignore_file_marker(notebook):
        return []

    findings = []
    for cell_number, cell in enumerate(notebook.get("cells", []), start=1):
        if cell.get("cell_type") != "code":
            continue

        source = cell.get("source", "")
        text = "".join(source) if isinstance(source, list) else source

        for rule, severity, message, remediation, line_number, column in _scan_cell_source(text):
            findings.append(
                _build_finding(
                    rule, severity, message, remediation, path, line_number, column,
                    cell=cell_number,
                )
            )
    return filter_notebook_suppressed(findings, notebook)


def _build_finding(
    rule: str,
    severity: Severity,
    message: str,
    remediation: str,
    path: Path,
    line: int,
    column: int,
    cell: int | None = None,
) -> Finding:
    return Finding(
        rule=rule,
        type="model_file",
        severity=severity,
        file=str(path),
        line=line,
        column=column,
        message=message,
        detail=message,
        remediation=remediation,
        cell=cell,
    )


def _scannable_extensions() -> frozenset[str]:
    return frozenset({".py", ".ipynb", ".bin", *_FILE_RULES.keys()})


def scan_path(root: Path) -> Iterator[Finding]:
    """Walk `root` and yield model-file findings from binary and source files."""
    for path in walk_files(root, include_extensions=_scannable_extensions()):
        yield from scan_file(path)


def count_files(root: Path) -> int:
    """Count how many files `scan_path(root)` would examine."""
    return sum(1 for _ in walk_files(root, include_extensions=_scannable_extensions()))
