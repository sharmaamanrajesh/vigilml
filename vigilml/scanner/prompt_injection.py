"""Prompt injection detection for LLM-integrated `.py`/`.ipynb` files.

This scanner works at file level, not via full taint analysis (see
docs/DECISIONS.md): it does not trace a value from its source to an LLM
call. If a file both constructs a prompt from external/user-controlled data
AND calls an LLM API anywhere in the file, it is flagged — this gives
useful signal without requiring a real data-flow analyzer, at the cost of
flagging some code that already sanitises its inputs (intentional; the
finding exists to prompt human review, not to prove exploitability).
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path

from vigilml.scanner import Finding, Severity
from vigilml.utils.file_walker import walk_files
from vigilml.utils.suppression import (
    filter_notebook_suppressed,
    filter_suppressed,
    has_ignore_file_marker,
    notebook_has_ignore_file_marker,
)

# ---------------------------------------------------------------------------
# Step 5A — LLM sink detection: "does this file call an LLM API anywhere?"
# ---------------------------------------------------------------------------

_LLM_SINK_LITERAL_RES: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"openai\.chat\.completions\.create\s*\(",
        r"openai\.completions\.create\s*\(",
        r"client\.chat\.completions\.create\s*\(",
        r"\bChatCompletion\.create\s*\(",
        r"anthropic\.messages\.create\s*\(",
        r"client\.messages\.create\s*\(",
        r"\.invoke\s*\(",
        r"(?i)(?:chain|llm|agent|pipeline)\w*\.run\s*\(",
        r"\bchain\s*\(",
        r"\bllm\s*\(",
        r"\bChatOpenAI\s*\(",
        r"\bChatAnthropic\s*\(",
        r"\bLLMChain\s*\(",
    )
)
# Generic fallback: any call whose function name or object contains one of
# these keywords — catches custom wrappers (`generate_response(`, `.chat(`,
# `run_inference(`) without needing an exhaustive literal list.
_LLM_SINK_GENERIC_RE = re.compile(
    r"(?i)\w*(?:llm|chat|completion|generate|prompt|inference)\w*\s*\("
)

# A file only counts as containing an LLM sink if it imports an LLM SDK or
# framework. Without this gate, any ML repo with a local `model.generate()`
# sampling loop (nanoGPT, most training codebases) would count as an LLM
# app and every file read in it would be flagged as an injection risk.
_LLM_IMPORT_RE = re.compile(
    r"(?m)^\s*(?:import|from)\s+(?:openai|anthropic|langchain\w*|llama_index|"
    r"litellm|cohere|mistralai|groq|ollama|google\.generativeai|vertexai|"
    r"guidance|semantic_kernel|dspy|haystack)\b"
)


def _has_llm_sink(text: str) -> bool:
    """True if `text` imports an LLM SDK and contains a call site that
    looks like an LLM API call."""
    if not _LLM_IMPORT_RE.search(text):
        return False
    return any(pattern.search(text) for pattern in _LLM_SINK_LITERAL_RES) or bool(
        _LLM_SINK_GENERIC_RE.search(text)
    )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_PROMPT_VAR_KEYWORDS: tuple[str, ...] = (
    "prompt",
    "message",
    "query",
    "instruction",
    "content",
    "text",
    "request",
)
# Covers system_prompt/user_message/input_text as substrings of the base
# keywords above, without needing to list every compound name separately.

_STRING_LITERAL_RE = re.compile(r"^[fFrRbB]{0,2}(['\"]).*\1$")


def _is_prompt_var(name: str) -> bool:
    lowered = name.lower()
    return any(keyword in lowered for keyword in _PROMPT_VAR_KEYWORDS)


def _is_literal_token(token: str) -> bool:
    stripped = token.strip()
    if not stripped:
        return True
    if _STRING_LITERAL_RE.match(stripped):
        return True
    return bool(re.fullmatch(r"-?\d+(\.\d+)?", stripped))


def _split_top_level(args: str) -> list[str]:
    """Split a call's argument text on top-level commas, ignoring commas
    nested inside brackets/parens or string literals."""
    parts: list[str] = []
    depth = 0
    in_string: str | None = None
    current = []
    i = 0
    while i < len(args):
        ch = args[i]
        if in_string:
            current.append(ch)
            if ch == "\\":
                if i + 1 < len(args):
                    current.append(args[i + 1])
                    i += 2
                    continue
            elif ch == in_string:
                in_string = None
        elif ch in "'\"":
            in_string = ch
            current.append(ch)
        elif ch in "([{":
            depth += 1
            current.append(ch)
        elif ch in ")]}":
            depth -= 1
            current.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
        i += 1
    if current:
        parts.append("".join(current))
    return [p for p in (part.strip() for part in parts) if p]


def _extract_paren_args(text: str, start: int) -> str | None:
    """Return a call's arguments given the index just after its opening `(`,
    handling nested brackets and string quotes."""
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


def _has_variable_arg(args: str) -> bool:
    """True if at least one top-level argument (or the value side of a
    `kw=value` argument) is not a literal."""
    for part in _split_top_level(args):
        value = part.split("=", 1)[1] if "=" in part and not part.startswith("=") else part
        if not _is_literal_token(value):
            return True
    return False


# ---------------------------------------------------------------------------
# Step 5B — direct injection: prompt construction patterns (per line)
# ---------------------------------------------------------------------------

_FSTRING_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\b['\"]?\s*[:=]\s*[fF](['\"])((?:(?!\2).)*)\2"
)
_FSTRING_INTERP_RE = re.compile(r"\{[^{}]+\}")

_FSTRING_REMEDIATION = (
    "Validate and sanitise all user-supplied values before including them in "
    "prompts. Consider using a prompt template library that escapes special "
    "characters, or implement an allowlist for accepted input."
)


def _check_fstring_prompt(line: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    match = _FSTRING_ASSIGN_RE.search(line)
    if not match:
        return
    var_name, body = match.group(1), match.group(3)
    if not _is_prompt_var(var_name) or not _FSTRING_INTERP_RE.search(body):
        return
    yield (
        "fstring-prompt-construction",
        "HIGH",
        "f-string prompt construction with variable interpolation — if the "
        "variable contains user input this is a prompt injection risk",
        _FSTRING_REMEDIATION,
        match.start() + 1,
    )


_CONCAT_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+\+.+)$")

_CONCAT_REMEDIATION = (
    "Use parameterised prompt templates rather than string concatenation. "
    "Validate all variable content before including in prompts."
)


def _check_concat_prompt(line: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    match = _CONCAT_ASSIGN_RE.match(line)
    if not match:
        return
    var_name, rhs = match.group(1), match.group(2)
    if not _is_prompt_var(var_name):
        return
    operands = rhs.split("+")
    if len(operands) < 2:
        return
    if not any(not _is_literal_token(operand) for operand in operands):
        return
    yield (
        "string-concat-prompt-construction",
        "HIGH",
        "String concatenation used to build prompt — unsanitised variables "
        "in prompts create prompt injection risk",
        _CONCAT_REMEDIATION,
        match.start(1) + 1,
    )


_FORMAT_CALL_RE = re.compile(
    r"(?:\b(?P<var>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*)?"
    r"(?P<receiver>(?:['\"][^'\"]*['\"])|[A-Za-z_][A-Za-z0-9_.]*)"
    r"\.format\s*\("
)
_FORMAT_RECEIVER_KEYWORDS = _PROMPT_VAR_KEYWORDS + ("template",)  # vigilml: ignore

_FORMAT_REMEDIATION = (
    "Validate all values passed to .format() on prompt templates. Prefer "
    "explicit sanitisation or a dedicated prompt templating library."
)


def _check_format_prompt(line: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    for match in _FORMAT_CALL_RE.finditer(line):
        var, receiver = match.group("var"), match.group("receiver")
        if var and _is_prompt_var(var):
            is_prompt_like = True
        elif not receiver.startswith(("'", '"')):
            last_segment = receiver.rsplit(".", 1)[-1]
            is_prompt_like = any(
                keyword in last_segment.lower() for keyword in _FORMAT_RECEIVER_KEYWORDS
            )
        else:
            # A literal string receiver with no prompt-like assignment
            # target (e.g. a bare `"{}-{}".format(...)` call, or an
            # assignment to an unrelated variable name) isn't prompt
            # construction as far as this scanner can tell.
            is_prompt_like = False
        if not is_prompt_like:
            continue
        args = _extract_paren_args(line, match.end())
        if args is None or not args.strip() or not _has_variable_arg(args):
            continue
        yield (
            "format-string-prompt-construction",
            "HIGH",
            ".format() used to build prompt with variable arguments — "
            "creates prompt injection risk if variables contain user input",
            _FORMAT_REMEDIATION,
            match.start() + 1,
        )


_PERCENT_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['\"].*['\"])\s*%\s*(.+)$")

_PERCENT_REMEDIATION = (
    "Prefer f-strings or .format() with explicit sanitisation, and validate "
    "all user-supplied values before including in prompts."
)


def _check_percent_prompt(line: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    match = _PERCENT_ASSIGN_RE.match(line)
    if not match:
        return
    var_name, _template, arg = match.group(1), match.group(2), match.group(3)
    if not _is_prompt_var(var_name) or _is_literal_token(arg):
        return
    yield (
        "percent-format-prompt-construction",
        "MEDIUM",
        "% formatting used to build prompt with variable arguments",
        _PERCENT_REMEDIATION,
        match.start(1) + 1,
    )


# ---------------------------------------------------------------------------
# Step 5C — high-risk sources (per line, only when the file also has a sink)
# ---------------------------------------------------------------------------

_WEB_CONTENT_RE = re.compile(
    r"=\s*(?:requests\.get\([^)]*\)\.text\b"
    r"|\w*(?:response|resp|res)\w*\.(?:text\b|json\s*\(\)))"
)
_WEB_CONTENT_REMEDIATION = (
    "Never pass raw web content directly to an LLM. Extract only the "
    "specific fields you need, validate the content, and consider using a "
    "content security policy for your prompts."
)

_SYS_ARGV_RE = re.compile(r"\bsys\.argv\b")
_ARGPARSE_RE = re.compile(r"\.parse_args\s*\(")
_CLICK_ARG_RE = re.compile(r"@click\.(?:argument|option)\b")
_INPUT_CALL_RE = re.compile(r"\binput\s*\(")
_CLI_INPUT_REMEDIATION = (
    "Validate and sanitise all CLI input before passing to an LLM. "
    "Implement an allowlist of accepted input formats. Never pass raw user "
    "input directly as prompt content."
)

_FILE_READ_RE = re.compile(
    r"open\([^)]*\)\.read\(\)|Path\([^)]*\)\.read_text\(\)|\bf\.read\(\)"
)
_FILE_READ_REMEDIATION = (
    "Validate file paths against an allowlist before reading. Sanitise "
    "file contents before including in prompts. Consider size limits on "
    "file content passed to LLMs."
)

_DB_RESULT_RE = re.compile(
    r"cursor\.fetchall\(\)|cursor\.fetchone\(\)|session\.query\([^)]*\)|\.all\(\)|\.first\(\)"
)
_DB_RESULT_REMEDIATION = (
    "Sanitise database content before including in prompts. Be especially "
    "careful with user-generated content stored in the database."
)

_ENV_VAR_RE = re.compile(r"os\.environ\b|os\.getenv\s*\(")
_ENV_VAR_REMEDIATION = (
    "Validate environment variable values before including in prompts. "
    "Prefer using env vars for configuration only, not as prompt content."
)


def _check_web_content(line: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    if match := _WEB_CONTENT_RE.search(line):
        yield (
            "web-content-in-llm-call",
            "HIGH",
            "Web response content used in LLM call — external web content "
            "can contain prompt injection payloads",
            _WEB_CONTENT_REMEDIATION,
            match.start() + 1,
        )


def _check_cli_stdin_input(line: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    match = (
        _SYS_ARGV_RE.search(line)
        or _ARGPARSE_RE.search(line)
        or _CLICK_ARG_RE.search(line)
        or _INPUT_CALL_RE.search(line)
    )
    if match:
        yield (
            "cli-stdin-input-in-llm-call",
            "CRITICAL",
            "User-supplied CLI input or stdin flows into LLM call — direct "
            "prompt injection vector",
            _CLI_INPUT_REMEDIATION,
            match.start() + 1,
        )


def _check_file_contents(line: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    if match := _FILE_READ_RE.search(line):
        yield (
            "file-contents-in-llm-call",
            "MEDIUM",
            "File contents passed to LLM — if the file path is "
            "user-controlled this is a path traversal and injection risk",
            _FILE_READ_REMEDIATION,
            match.start() + 1,
        )


def _check_db_results(line: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    if match := _DB_RESULT_RE.search(line):
        yield (
            "database-results-in-llm-call",
            "MEDIUM",
            "Database query results passed to LLM — database content may "
            "contain stored prompt injection payloads",
            _DB_RESULT_REMEDIATION,
            match.start() + 1,
        )


def _check_env_vars(line: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    if match := _ENV_VAR_RE.search(line):
        yield (
            "env-var-in-llm-prompt",
            "MEDIUM",
            "Environment variable used in LLM prompt — if environment can "
            "be influenced by an attacker this creates an injection risk",
            _ENV_VAR_REMEDIATION,
            match.start() + 1,
        )


def _scan_line(line: str, has_sink: bool) -> Iterator[tuple[str, Severity, str, str, int]]:
    """Yield (rule, severity, message, remediation, column) for `line`.

    All patterns here (direct injection + high-risk sources) only fire when
    the file also contains an LLM sink (Step 5B/5C); system-prompt exposure
    (Step 5D) is handled separately in `_check_system_prompt_exposure` since
    it does not depend on sink presence and needs multi-line string bodies.
    """
    if not has_sink:
        return
    yield from _check_fstring_prompt(line)
    yield from _check_concat_prompt(line)
    yield from _check_format_prompt(line)
    yield from _check_percent_prompt(line)
    yield from _check_web_content(line)
    yield from _check_cli_stdin_input(line)
    yield from _check_file_contents(line)
    yield from _check_db_results(line)
    yield from _check_env_vars(line)


# ---------------------------------------------------------------------------
# Step 5D — system prompt exposure (whole-file text, handles triple-quoted
# multi-line strings)
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT_ASSIGN_RE = re.compile(
    r"(?i)\b(?:system_prompt|system_message)\s*=\s*"
    r"(?P<q>'''|\"\"\"|'|\")(?P<body>.*?)(?P=q)",
    re.DOTALL,
)

_API_KEY_IN_PROMPT_RE = re.compile(
    r"sk-[A-Za-z0-9_-]{10,}"
    r"|AKIA[0-9A-Z]{16}"
    r"|hf_[A-Za-z0-9]{15,}"
    r"|https?://[^\s'\"/]+:[^\s'\"@]+@"
    r"|(?i:api[_-]?key\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,})"
)
_API_KEY_IN_PROMPT_REMEDIATION = (
    "Never embed API keys, passwords, or internal URLs in system prompts. "
    "Load sensitive values from environment variables and keep them out of "
    "the prompt entirely."
)

_INTERNAL_URL_RE = re.compile(
    r"(?i)https?://[^\s'\"]*"
    r"(?:internal|intranet|localhost|127\.0\.0\.1|192\.168\.|10\.0\.|172\.16\.)"
    r"[^\s'\"]*"
)
_INTERNAL_URL_REMEDIATION = (
    "Remove internal URLs from system prompts. Reference internal "
    "resources by name or abstract identifier rather than direct URL."
)


def _check_system_prompt_exposure(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    for assign_match in _SYSTEM_PROMPT_ASSIGN_RE.finditer(text):
        body = assign_match.group("body")
        body_start = assign_match.start("body")

        if key_match := _API_KEY_IN_PROMPT_RE.search(body):
            line, _ = _line_and_column(text, body_start + key_match.start())
            yield (
                "api-key-in-system-prompt",
                "HIGH",
                "API key or credential found embedded in system prompt "
                "string — system prompts can be extracted by users via "
                "prompt injection",
                _API_KEY_IN_PROMPT_REMEDIATION,
                line,
            )

        if url_match := _INTERNAL_URL_RE.search(body):
            line, _ = _line_and_column(text, body_start + url_match.start())
            yield (
                "internal-url-in-system-prompt",
                "MEDIUM",
                "Internal URL embedded in system prompt — system prompts "
                "can be revealed to users via prompt injection attacks",
                _INTERNAL_URL_REMEDIATION,
                line,
            )


def _line_and_column(text: str, offset: int) -> tuple[int, int]:
    line_start = text.rfind("\n", 0, offset) + 1
    line = text.count("\n", 0, offset) + 1
    return line, offset - line_start + 1


# ---------------------------------------------------------------------------
# File / notebook scanning
# ---------------------------------------------------------------------------


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for prompt injection risk patterns."""
    if path.suffix == ".ipynb":
        return _scan_notebook(path)
    if path.suffix == ".py":
        return _scan_text_file(path)
    return []


def _scan_text_file(path: Path) -> list[Finding]:
    text = path.read_text(errors="ignore")
    if has_ignore_file_marker(text):
        return []

    has_sink = _has_llm_sink(text)

    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, severity, message, remediation, column in _scan_line(line, has_sink):
            findings.append(
                _build_finding(rule, severity, message, remediation, path, line_number, column)
            )
    for rule, severity, message, remediation, fl_line in _check_system_prompt_exposure(text):
        findings.append(_build_finding(rule, severity, message, remediation, path, fl_line, 1))
    return filter_suppressed(findings, text)


def _scan_notebook(path: Path) -> list[Finding]:
    try:
        notebook = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []

    if notebook_has_ignore_file_marker(notebook):
        return []

    combined_lines: list[str] = []
    combined_line_cell: list[int] = []
    combined_line_number: list[int] = []

    for cell_number, cell in enumerate(notebook.get("cells", []), start=1):
        if cell.get("cell_type") != "code":
            continue
        source = cell.get("source", "")
        text = "".join(source) if isinstance(source, list) else source
        for line_number, line in enumerate(text.splitlines(), start=1):
            combined_lines.append(line)
            combined_line_cell.append(cell_number)
            combined_line_number.append(line_number)

    combined_text = "\n".join(combined_lines)
    has_sink = _has_llm_sink(combined_text)

    findings = []
    for index, line in enumerate(combined_lines):
        for rule, severity, message, remediation, column in _scan_line(line, has_sink):
            findings.append(
                _build_finding(
                    rule, severity, message, remediation, path,
                    combined_line_number[index], column, cell=combined_line_cell[index],
                )
            )

    for rule, severity, message, remediation, fl_line in _check_system_prompt_exposure(
        combined_text
    ):
        index = fl_line - 1
        if 0 <= index < len(combined_line_cell):
            findings.append(
                _build_finding(
                    rule, severity, message, remediation, path,
                    combined_line_number[index], 1, cell=combined_line_cell[index],
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
        type="prompt_injection",
        severity=severity,
        file=str(path),
        line=line,
        column=column,
        message=message,
        detail=message,
        remediation=remediation,
        cell=cell,
    )


_SCAN_EXTENSIONS = frozenset({".py", ".ipynb"})


def scan_path(root: Path) -> Iterator[Finding]:
    """Walk `root` and yield prompt injection findings from `.py`/`.ipynb` files."""
    for path in walk_files(root, include_extensions=_SCAN_EXTENSIONS):
        yield from scan_file(path)


def count_files(root: Path) -> int:
    """Count how many files `scan_path(root)` would examine."""
    return sum(1 for _ in walk_files(root, include_extensions=_SCAN_EXTENSIONS))
