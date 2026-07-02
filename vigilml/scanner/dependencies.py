"""ML dependency CVE and anti-pattern detection.

See docs/DECISIONS.md ADR-003 — OSV.dev needs no API key and has solid PyPI
coverage. Network calls are wrapped in a timeout and degrade to an empty
result if the API is unreachable, so a scan never crashes on network issues.

Beyond the OSV.dev CVE lookup, this scanner also flags dependency
anti-patterns that don't need an API call: unpinned security-critical
packages, known deprecated/abandoned packages, and typosquatting-risk
package names (see `_check_anti_patterns`).
"""

from __future__ import annotations

import ast
import configparser
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import requests
import tomllib

from vigilml.scanner import Finding, Severity
from vigilml.utils.file_walker import walk_files
from vigilml.utils.suppression import filter_suppressed, has_ignore_file_marker

OSV_API_URL = "https://api.osv.dev/v1/query"
OSV_TIMEOUT_SECONDS = 5

ML_PACKAGES: frozenset[str] = frozenset(
    {
        # Core ML frameworks
        "torch", "torchvision", "torchaudio", "tensorflow", "tensorflow-cpu",
        "tensorflow-gpu", "keras", "jax", "jaxlib", "flax", "paddlepaddle",
        "mxnet", "onnx", "onnxruntime", "onnxruntime-gpu",
        # HuggingFace ecosystem
        "transformers", "diffusers", "datasets", "tokenizers", "accelerate",
        "huggingface-hub", "peft", "trl", "sentence-transformers", "evaluate",
        "optimum", "timm",
        # LLM and agents
        "langchain", "langchain-core", "langchain-community",
        "langchain-openai", "langchain-anthropic", "llama-index",
        "llama-cpp-python", "openai", "anthropic", "cohere", "mistralai",
        "together", "replicate", "groq", "litellm", "guidance", "outlines",
        "instructor",
        # Classical ML and data science
        "scikit-learn", "xgboost", "lightgbm", "catboost", "scipy", "numpy",
        "pandas", "matplotlib", "seaborn", "plotly", "statsmodels",
        "imbalanced-learn",
        # Computer vision
        "opencv-python", "opencv-python-headless", "pillow", "albumentations",
        "kornia", "scikit-image", "ultralytics",
        # NLP
        "nltk", "spacy", "gensim", "textblob", "flair", "stanza",
        "sacrebleu", "rouge-score",
        # MLOps and experiment tracking
        "mlflow", "wandb", "neptune", "dvc", "bentoml", "ray", "seldon-core",
        "torchserve", "triton-client",
        # Vector databases and retrieval
        "faiss-cpu", "faiss-gpu", "chromadb", "pinecone-client",
        "weaviate-client", "qdrant-client", "pymilvus",
        # Serving and APIs
        "fastapi", "uvicorn", "gradio", "streamlit", "flask",
        # Data processing
        "pyarrow", "polars", "dask", "pyspark", "sqlalchemy",
        "psycopg2-binary", "pymongo", "redis",
        # Security critical — included regardless of ML-specificity so
        # outdated versions are flagged aggressively (see Finding rationale
        # in docs/PRD.md's "AI-specific" scope note: these libraries sit
        # directly in the request/crypto path of most model-serving stacks).
        "cryptography", "pyopenssl", "paramiko", "requests", "urllib3",
        "certifi", "aiohttp", "werkzeug", "starlette", "pydantic",
    }
)

# Flagged by the unpinned-version anti-pattern (Step 4C, anti-pattern 1)
# regardless of ML-specificity.
_SECURITY_CRITICAL_PACKAGES: frozenset[str] = frozenset(
    {
        "cryptography", "pyopenssl", "paramiko", "requests", "urllib3",
        "certifi", "pillow", "aiohttp", "werkzeug", "starlette", "pydantic",
    }
)

_DEPRECATED_MESSAGES: dict[str, str] = {
    "bert-serving-server": (
        "bert-serving-server is unmaintained — the last release was in "
        "2020. Use a maintained serving solution such as FastAPI with "
        "HuggingFace transformers or TorchServe."
    ),
    "allennlp": (
        "AllenNLP development has halted. Consider migrating to "
        "HuggingFace transformers which covers the same NLP use cases with "
        "active maintenance."
    ),
    "stanfordnlp": (
        "stanfordnlp has been replaced by stanza. Replace stanfordnlp with "
        "stanza in your dependencies."
    ),
}
_FLAIR_OLD_VERSION_MESSAGE = (
    "Old flair version detected — versions before 0.13 have known "
    "security issues in dependency chain."
)
_SPARK_MESSAGE = (
    "The 'spark' PyPI package is not Apache Spark — you likely want "
    "'pyspark'. The 'spark' package is an unrelated abandoned project."
)
_TYPOSQUAT_MESSAGES: dict[str, str] = {
    "pytorch": (
        "The package named 'pytorch' on PyPI is NOT the real PyTorch. The "
        "correct package is 'torch'. Remove 'pytorch' and replace with "
        "'torch'."
    ),
    "sklearn": (
        "The 'sklearn' package on PyPI is a stub that installs "
        "scikit-learn but has been used for typosquatting historically. "
        "Use 'scikit-learn' directly."
    ),
}
_TENSORFLOW_GPU_CONFLICT_MESSAGE = (
    "Both tensorflow and tensorflow-gpu are listed — tensorflow >= 2.0 "
    "includes GPU support natively. Remove tensorflow-gpu."
)

# Only "==" is queried — ">=", "~=", etc. are a minimum/range, not the
# version actually installed, so querying OSV for the bound would false-positive.
_PIP_SPEC_RE = re.compile(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-]+)")
_CONDA_SPEC_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*=\s*([A-Za-z0-9_.\-]+)")
# Just the package name, regardless of whether (or how) it's version-pinned
# — used by the anti-pattern passes, which care about package presence and
# pin-status independent of ML_PACKAGES membership.
_PACKAGE_NAME_RE = re.compile(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?")

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


def parse_pipfile(text: str) -> list[tuple[str, str, int]]:
    """Return (name, version, line) tuples for `==`-pinned packages in a
    Pipfile's [packages] and [dev-packages] sections."""
    return [(name, version, line) for name, version, line in _all_pipfile(text) if version]


def parse_setup_py(text: str) -> list[tuple[str, str, int]]:
    """Return (name, version, line) tuples for `==`-pinned packages in
    setup.py's install_requires list.

    Uses AST parsing (walking for an `install_requires` keyword argument);
    falls back to a best-effort regex scan of the raw text if the file
    doesn't parse as valid Python.
    """
    return [(name, version, line) for name, version, line in _all_setup_py(text) if version]


def parse_setup_cfg(text: str) -> list[tuple[str, str, int]]:
    """Return (name, version, line) tuples for `==`-pinned packages in
    setup.cfg's [options] install_requires."""
    return [(name, version, line) for name, version, line in _all_setup_cfg(text) if version]


# ---------------------------------------------------------------------------
# "All packages" extraction — every declared package regardless of pin
# status (`version` is `None` for a bare name, a range specifier, or
# Pipfile's `"*"`). Used only by the anti-pattern passes (Step 4C), which
# care about package presence/pin-status independent of ML_PACKAGES
# membership. Kept separate from the `parse_*` functions above so their
# existing pinned-only contract (and tests) are untouched.
# ---------------------------------------------------------------------------


def _all_requirements_txt(text: str) -> list[tuple[str, str | None, int]]:
    packages: list[tuple[str, str | None, int]] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        match = _PACKAGE_NAME_RE.match(line)
        if not match:
            continue
        name = match.group(1).lower()
        pin_match = _PIP_SPEC_RE.match(line)
        version = pin_match.group(2) if pin_match else None
        packages.append((name, version, line_number))
    return packages


def _all_pyproject_toml(text: str) -> list[tuple[str, str | None, int]]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []

    dependencies = data.get("project", {}).get("dependencies", [])
    packages: list[tuple[str, str | None, int]] = []
    for spec in dependencies:
        spec = spec.strip()
        match = _PACKAGE_NAME_RE.match(spec)
        if not match:
            continue
        name = match.group(1).lower()
        pin_match = _PIP_SPEC_RE.match(spec)
        version = pin_match.group(2) if pin_match else None
        packages.append((name, version, _find_line_number(text, name)))
    return packages


def _all_environment_yml(text: str) -> list[tuple[str, str | None, int]]:
    packages: list[tuple[str, str | None, int]] = []
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

        match = _PACKAGE_NAME_RE.match(item)
        if not match:
            continue
        name = match.group(1).lower()
        pattern = _PIP_SPEC_RE if in_pip_section else _CONDA_SPEC_RE
        pin_match = pattern.match(item)
        version = pin_match.group(2) if pin_match else None
        packages.append((name, version, line_number))

    return packages


def _pipfile_pinned_version(spec: Any) -> str | None:
    if isinstance(spec, str):
        return spec[2:].strip() if spec.startswith("==") else None
    if isinstance(spec, dict):
        version = spec.get("version")
        if isinstance(version, str) and version.startswith("=="):
            return version[2:].strip()
    return None


def _all_pipfile(text: str) -> list[tuple[str, str | None, int]]:
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []

    packages: list[tuple[str, str | None, int]] = []
    for section in ("packages", "dev-packages"):
        for name, spec in data.get(section, {}).items():
            version = _pipfile_pinned_version(spec)
            packages.append((name.lower(), version, _find_line_number(text, name)))
    return packages


def _packages_from_ast_node(node: ast.expr) -> list[tuple[str, str | None, int]]:
    packages: list[tuple[str, str | None, int]] = []
    if isinstance(node, (ast.List, ast.Tuple)):
        for element in node.elts:
            if isinstance(element, ast.Constant) and isinstance(element.value, str):
                spec = element.value.strip()
                match = _PACKAGE_NAME_RE.match(spec)
                if not match:
                    continue
                name = match.group(1).lower()
                pin_match = _PIP_SPEC_RE.match(spec)
                version = pin_match.group(2) if pin_match else None
                line = getattr(element, "lineno", 1)
                packages.append((name, version, line))
    return packages


def _regex_scan_install_requires(text: str) -> list[tuple[str, str | None, int]]:
    """Best-effort fallback when setup.py doesn't parse as valid Python."""
    packages: list[tuple[str, str | None, int]] = []
    in_install_requires = False
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if "install_requires" in line:
            in_install_requires = True
        if not in_install_requires:
            continue
        for quoted in re.findall(r"['\"]([^'\"]+)['\"]", line):
            quoted = quoted.strip()
            match = _PACKAGE_NAME_RE.match(quoted)
            if not match:
                continue
            name = match.group(1).lower()
            pin_match = _PIP_SPEC_RE.match(quoted)
            version = pin_match.group(2) if pin_match else None
            packages.append((name, version, line_number))
        if "]" in line and "install_requires" not in line:
            break
    return packages


def _all_setup_py(text: str) -> list[tuple[str, str | None, int]]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return _regex_scan_install_requires(text)

    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "install_requires":
            return _packages_from_ast_node(node.value)
    return []


def _all_setup_cfg(text: str) -> list[tuple[str, str | None, int]]:
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(text)
    except configparser.Error:
        return []

    if not parser.has_option("options", "install_requires"):
        return []

    raw = parser.get("options", "install_requires")
    packages: list[tuple[str, str | None, int]] = []
    for item in raw.splitlines():
        item = item.strip()
        if not item:
            continue
        match = _PACKAGE_NAME_RE.match(item)
        if not match:
            continue
        name = match.group(1).lower()
        pin_match = _PIP_SPEC_RE.match(item)
        version = pin_match.group(2) if pin_match else None
        packages.append((name, version, _find_line_number(text, name)))
    return packages


def _all_packages_for(path: Path, text: str) -> list[tuple[str, str | None, int]]:
    if path.name == "pyproject.toml":
        return _all_pyproject_toml(text)
    if path.name == "Pipfile":
        return _all_pipfile(text)
    if path.name == "setup.py":
        return _all_setup_py(text)
    if path.name == "setup.cfg":
        return _all_setup_cfg(text)
    if path.name.startswith("environment") and path.suffix in {".yml", ".yaml"}:
        return _all_environment_yml(text)
    if path.name.startswith("requirements") and path.suffix == ".txt":
        return _all_requirements_txt(text)
    return []


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


# ---------------------------------------------------------------------------
# Anti-pattern detection (Step 4C) — no API call needed.
# ---------------------------------------------------------------------------


def _version_key(version: str) -> tuple[int, ...]:
    """Parse a dotted version string into a comparable tuple of ints,
    ignoring non-numeric suffixes (e.g. "2.1.0rc1" -> (2, 1, 0))."""
    parts = []
    for segment in version.split("."):
        match = re.match(r"\d+", segment)
        parts.append(int(match.group()) if match else 0)
    return tuple(parts)


def _unpinned_security_finding(name: str, path: Path, line: int) -> Finding:
    message = (
        f"Security-critical package {name} has no pinned version — future "
        "installs may pull a vulnerable version without notice"
    )
    remediation = (
        f"Pin to a specific version: {name}==X.Y.Z and update deliberately "
        "rather than accepting automatic updates."
    )
    return Finding(
        rule="unpinned-security-critical-package",
        type="dependency",
        severity="LOW",
        file=str(path),
        line=line,
        message=message,
        detail=message,
        remediation=remediation,
    )


def _deprecated_finding(rule: str, name: str, path: Path, line: int, message: str) -> Finding:
    return Finding(
        rule=rule,
        type="dependency",
        severity="MEDIUM",
        file=str(path),
        line=line,
        message=message,
        detail=f"{name} matches a known deprecated/abandoned-package pattern",
        remediation=message,
    )


def _typosquat_finding(rule: str, name: str, path: Path, line: int, message: str) -> Finding:
    return Finding(
        rule=rule,
        type="dependency",
        severity="HIGH",
        file=str(path),
        line=line,
        message=message,
        detail=f"{name} matches a known typosquatting/naming-confusion pattern",
        remediation=message,
    )


def _check_anti_patterns(
    packages: list[tuple[str, str | None, int]], path: Path
) -> list[Finding]:
    """Flag dependency anti-patterns that don't require an OSV.dev query."""
    findings: list[Finding] = []
    tensorflow_version = next(
        (version for name, version, _ in packages if name == "tensorflow" and version), None
    )
    has_tensorflow_2_or_later = (
        tensorflow_version is not None and _version_key(tensorflow_version) >= (2, 0)
    )

    for name, version, line in packages:
        if name in _SECURITY_CRITICAL_PACKAGES and version is None:
            findings.append(_unpinned_security_finding(name, path, line))

        if name in _DEPRECATED_MESSAGES:
            findings.append(
                _deprecated_finding(
                    f"deprecated-{name}", name, path, line, _DEPRECATED_MESSAGES[name]
                )
            )
        elif name == "flair" and version is not None and _version_key(version) < (0, 13):
            findings.append(
                _deprecated_finding(
                    "deprecated-flair-version", name, path, line, _FLAIR_OLD_VERSION_MESSAGE
                )
            )
        elif name == "spark":
            findings.append(
                _deprecated_finding("deprecated-spark-package", name, path, line, _SPARK_MESSAGE)
            )

        if name in _TYPOSQUAT_MESSAGES:
            findings.append(
                _typosquat_finding(f"typosquat-{name}", name, path, line, _TYPOSQUAT_MESSAGES[name])
            )
        elif name == "tensorflow-gpu" and has_tensorflow_2_or_later:
            findings.append(
                _typosquat_finding(
                    "tensorflow-gpu-redundant",
                    name,
                    path,
                    line,
                    _TENSORFLOW_GPU_CONFLICT_MESSAGE,
                )
            )

    return findings


def _is_dependency_file(path: Path) -> bool:
    return (
        path.name in {"pyproject.toml", "Pipfile", "setup.py", "setup.cfg"}
        or (path.name.startswith("requirements") and path.suffix == ".txt")
        or (path.name.startswith("environment") and path.suffix in {".yml", ".yaml"})
    )


def scan_file(path: Path) -> list[Finding]:
    """Parse a dependency file, check its ML packages against OSV.dev, and
    flag dependency anti-patterns (unpinned security-critical packages,
    deprecated packages, typosquatting-risk names)."""
    text = path.read_text(errors="ignore")
    if has_ignore_file_marker(text):
        return []

    packages = _all_packages_for(path, text)

    findings = []
    for name, version, line in packages:
        if version is not None and name in ML_PACKAGES:
            for vuln in query_osv(name, version):
                findings.append(_finding_for_vuln(vuln, name, version, path, line))

    findings.extend(_check_anti_patterns(packages, path))
    return filter_suppressed(findings, text)


_SCAN_EXTENSIONS = frozenset({".txt", ".toml", ".yml", ".yaml", ".cfg"})
_SCAN_FILENAMES = frozenset({"Pipfile", "setup.py", "setup.cfg"})


def scan_path(root: Path) -> Iterator[Finding]:
    """Walk `root` and yield findings from requirements/pyproject/environment/
    Pipfile/setup.py/setup.cfg dependency files."""
    if root.is_file():
        if _is_dependency_file(root):
            yield from scan_file(root)
        return
    for path in walk_files(
        root, include_extensions=_SCAN_EXTENSIONS, include_filenames=_SCAN_FILENAMES
    ):
        if _is_dependency_file(path):
            yield from scan_file(path)


def count_files(root: Path) -> int:
    """Count how many files `scan_path(root)` would examine."""
    if root.is_file():
        return 1 if _is_dependency_file(root) else 0
    return sum(
        1
        for path in walk_files(
            root, include_extensions=_SCAN_EXTENSIONS, include_filenames=_SCAN_FILENAMES
        )
        if _is_dependency_file(path)
    )
