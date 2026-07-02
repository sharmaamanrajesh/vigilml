"""Cloud misconfiguration and infrastructure-risk detection.

Flags AWS/GCP/Azure misconfigurations, unsafe training-data download
patterns, insecure Dockerfiles, and unauthenticated model-serving endpoints
in `.py`/`.ipynb` files, `Dockerfile`s, and shell scripts (see
docs/DECISIONS.md ADR-006 for the notebook-only-code-cells rule).
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
# Simple, single-line patterns
# ---------------------------------------------------------------------------

_S3_PUBLIC_ACL_RE = re.compile(r"ACL\s*=\s*['\"]public-read(?:-write)?['\"]")
_BUCKET_NAME_RE = re.compile(r"Bucket\s*=\s*['\"]([A-Za-z0-9.\-_]+)['\"]")
# Matches only bucket names that look like real infrastructure — one of
# these keywords followed by further alphanumeric/hyphen characters — not
# short generic example names like "my-models" or "test-bucket".
_BUCKET_NAME_INFRA_RE = re.compile(
    r"(?i)(?:production|prod|staging|live|backup|dataset|data|models|weights|artifacts)"
    r"[A-Za-z0-9-]+"
)
_CHMOD_SHELL_777_RE = re.compile(r"chmod\s+777\b")
_OS_CHMOD_777_RE = re.compile(r"os\.chmod\([^,]+,\s*0o?777\)")
_IAM_WILDCARD_ACTION_RE = re.compile(r"[\"']Action[\"']\s*:\s*[\"']\*[\"']")
_IAM_WILDCARD_RESOURCE_RE = re.compile(r"[\"']Resource[\"']\s*:\s*[\"']\*[\"']")
_ARN_RE = re.compile(r"arn:aws:[^\s'\"]*")
_ARN_ACCOUNT_ID_RE = re.compile(r"\d{12}")
_GCS_MAKE_PUBLIC_RE = re.compile(r"\.make_public\(\)")
_AZURE_ACCOUNT_PUBLIC_BLOB_RE = re.compile(r"allow_blob_public_access\s*=\s*True")
_WGET_CURL_HTTP_RE = re.compile(
    r"(?:subprocess\.\w+|os\.system)\([^)]*\b(?:wget|curl)\b[^)]*http://"
)
_FLASK_DEBUG_TRUE_RE = re.compile(r"\.run\([^)]*debug\s*=\s*True")
_CORS_WILDCARD_RE = re.compile(r"allow_origins\s*=\s*(?:\[\s*[\"']\*[\"']\s*\]|[\"']\*[\"'])")
_GRADIO_SHARE_TRUE_RE = re.compile(r"\.launch\([^)]*share\s*=\s*True")

_S3_PUBLIC_WRITE_REMEDIATION = (
    "Remove the public-read ACL. Restrict bucket access with IAM policies "
    "and bucket policies instead of object-level public ACLs."
)
_HARDCODED_BUCKET_REMEDIATION = (
    "Load the bucket name from an environment variable or config file "
    "instead of hardcoding it, so it can vary per environment."
)
_WORLD_READABLE_REMEDIATION = (
    "Use a more restrictive permission mode (e.g. 0o640 or 0o600). "
    "World-writable/readable permissions expose files to any local user."
)
_IAM_WILDCARD_ACTION_REMEDIATION = (
    "Replace Action: '*' with the specific actions required. Follow "
    "least-privilege principle."
)
_IAM_WILDCARD_RESOURCE_REMEDIATION = (
    "Replace Resource: '*' with specific ARNs for only the resources your "
    "ML pipeline needs to access."
)
_HARDCODED_ACCOUNT_ID_REMEDIATION = (
    "Load the account ID from an environment variable or AWS STS "
    "get_caller_identity() call."
)
_GCS_MAKE_PUBLIC_REMEDIATION = (
    "Remove make_public(). Use signed URLs for temporary access or IAM "
    "bindings for authenticated access."
)
_AZURE_ACCOUNT_PUBLIC_BLOB_REMEDIATION = (
    "Set allow_blob_public_access=False on the storage account to prevent "
    "accidental public exposure of model artifacts."
)
_WGET_CURL_HTTP_REMEDIATION = "Use https:// for all downloads. Verify checksums after downloading."
_FLASK_DEBUG_REMEDIATION = (
    "Set debug=False in production. Use environment variables to control "
    "debug mode: debug=os.getenv('FLASK_DEBUG', 'False') == 'True'"
)
_CORS_WILDCARD_REMEDIATION = (
    "Restrict allow_origins to your specific frontend domains: "
    "allow_origins=['https://yourdomain.com']"
)
_GRADIO_SHARE_REMEDIATION = (
    "Remove share=True for production deployments. Use proper hosting "
    "instead of Gradio's tunnel."
)


def _looks_like_real_bucket_name(name: str) -> bool:
    """True for bucket names that look like real infrastructure rather than
    a short generic example name (`my-models`, `test-bucket`)."""
    return len(name) > 8 and bool(_BUCKET_NAME_INFRA_RE.search(name))


def _scan_line(line: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    """Yield (rule, severity, message, remediation, column) for `line`."""
    if match := _S3_PUBLIC_ACL_RE.search(line):
        yield (
            "s3-public-write",
            "MEDIUM",
            "S3 object ACL grants public read access",
            _S3_PUBLIC_WRITE_REMEDIATION,
            match.start() + 1,
        )
    if (match := _BUCKET_NAME_RE.search(line)) and _looks_like_real_bucket_name(match.group(1)):
        yield (
            "hardcoded-bucket-name",
            "LOW",
            "Hardcoded S3 bucket name detected",
            _HARDCODED_BUCKET_REMEDIATION,
            match.start() + 1,
        )
    if match := (_CHMOD_SHELL_777_RE.search(line) or _OS_CHMOD_777_RE.search(line)):
        yield (
            "world-readable-permissions",
            "MEDIUM",
            "World-readable/writable file permissions (777) detected",
            _WORLD_READABLE_REMEDIATION,
            match.start() + 1,
        )
    if match := _IAM_WILDCARD_ACTION_RE.search(line):
        yield (
            "iam-wildcard-action",
            "HIGH",
            "IAM policy with wildcard Action detected — grants unrestricted "
            "access to all AWS services",
            _IAM_WILDCARD_ACTION_REMEDIATION,
            match.start() + 1,
        )
    if match := _IAM_WILDCARD_RESOURCE_RE.search(line):
        yield (
            "iam-wildcard-resource",
            "HIGH",
            "IAM policy with wildcard Resource detected — policy applies to "
            "all AWS resources",
            _IAM_WILDCARD_RESOURCE_REMEDIATION,
            match.start() + 1,
        )
    if (match := _ARN_RE.search(line)) and _ARN_ACCOUNT_ID_RE.search(match.group(0)):
        yield (
            "hardcoded-aws-account-id",
            "MEDIUM",
            "Hardcoded AWS account ID in ARN — account IDs should not be "
            "committed to source code",
            _HARDCODED_ACCOUNT_ID_REMEDIATION,
            match.start() + 1,
        )
    if match := _GCS_MAKE_PUBLIC_RE.search(line):
        yield (
            "gcs-blob-public",
            "HIGH",
            "GCS blob made public — this grants unauthenticated read access "
            "to the blob",
            _GCS_MAKE_PUBLIC_REMEDIATION,
            match.start() + 1,
        )
    if match := _AZURE_ACCOUNT_PUBLIC_BLOB_RE.search(line):
        yield (
            "azure-account-public-blob-access",
            "HIGH",
            "Azure Storage account configured to allow public blob access "
            "at account level",
            _AZURE_ACCOUNT_PUBLIC_BLOB_REMEDIATION,
            match.start() + 1,
        )
    if match := _WGET_CURL_HTTP_RE.search(line):
        yield (
            "wget-curl-http",
            "HIGH",
            "wget/curl downloading over unencrypted HTTP in training "
            "script — training data poisoning risk",
            _WGET_CURL_HTTP_REMEDIATION,
            match.start() + 1,
        )
    if match := _FLASK_DEBUG_TRUE_RE.search(line):
        yield (
            "flask-debug-mode",
            "HIGH",
            "Flask debug mode enabled — the interactive debugger exposes a "
            "Python console that can execute arbitrary code",
            _FLASK_DEBUG_REMEDIATION,
            match.start() + 1,
        )
    if match := _CORS_WILDCARD_RE.search(line):
        yield (
            "cors-allow-all-origins",
            "MEDIUM",
            "CORS configured to allow all origins — any website can make "
            "requests to your model serving API",
            _CORS_WILDCARD_REMEDIATION,
            match.start() + 1,
        )
    if match := _GRADIO_SHARE_TRUE_RE.search(line):
        yield (
            "gradio-share-enabled",
            "MEDIUM",
            "Gradio interface launched with share=True — creates a public "
            "tunnel URL that exposes your model to the internet",
            _GRADIO_SHARE_REMEDIATION,
            match.start() + 1,
        )


# ---------------------------------------------------------------------------
# Whole-file-context checks — "is X present anywhere in this file", or a
# call's full (nesting- and multi-line-aware) argument list. Applied once
# per `.py` file's full text, or once per notebook's combined code-cell
# text (see `_scan_notebook`), not per individual line.
# ---------------------------------------------------------------------------

_S3_UPLOAD_CALL_RE = re.compile(r"\.(?:put_object|upload_file)\s*\(")
_S3_CREATE_BUCKET_RE = re.compile(r"\.create_bucket\s*\(")
_SAGEMAKER_OUTPUT_PATH_RE = re.compile(r"[\"']?(?:S3)?OutputPath[\"']?\s*:")
_BIGQUERY_CREATE_DATASET_RE = re.compile(r"\.create_dataset\s*\(")
_AZURE_CLIENT_RE = re.compile(r"\b(?:BlobServiceClient|ContainerClient)\s*\(")
_HTTP_DOWNLOAD_RE = re.compile(r"(?:requests\.get|urlopen|urlretrieve)\s*\(\s*[\"']http://")
_DISK_SAVE_RE = re.compile(r"open\([^)]*[\"'](?:w|wb|ab)[\"']")
_DOWNLOAD_CALL_RE = re.compile(r"\b(?:requests\.get|urlretrieve)\s*\(")
_ROUTE_DECORATOR_RE = re.compile(
    r"@(?:app|router)\.(?:route|get|post|put|delete|patch)\s*\("
)
_AUTH_KEYWORDS: tuple[str, ...] = (
    "flask_login",
    "fastapi.security",
    "jwt",
    "oauth",
    "bearer",
    "api_key_header",
    "security",
)

_S3_ENCRYPTION_REMEDIATION = (
    "Add ServerSideEncryption='AES256' or ServerSideEncryption='aws:kms' "
    "to all S3 put/upload calls."
)
_S3_VERSIONING_REMEDIATION = (
    "Call s3.put_bucket_versioning() after creating the bucket to enable "
    "versioning on model and data storage buckets."
)
_SAGEMAKER_ENCRYPTION_REMEDIATION = (
    "Add output_kms_key parameter to your SageMaker Estimator to encrypt "
    "training output."
)
_BIGQUERY_ACCESS_REMEDIATION = (
    "Set dataset.access_entries to restrict who can query your training data."
)
_AZURE_CONTAINER_PUBLIC_REMEDIATION = (
    "Set public_access=None or remove the public_access parameter to "
    "restrict container access to authenticated principals only."
)
_HTTP_DOWNLOAD_REMEDIATION = (
    "Use https:// URLs for all downloads. Additionally verify file "
    "integrity with a SHA256 checksum after downloading."
)
_MISSING_CHECKSUM_REMEDIATION = (
    "After downloading, verify the file's SHA256 hash against a "
    "known-good value: import hashlib; hashlib.sha256(data).hexdigest()"
)
_SERVING_AUTH_REMEDIATION = (
    "Add authentication to all model serving endpoints. For FastAPI use "
    "HTTPBearer or OAuth2PasswordBearer. For Flask use flask-login or "
    "flask-jwt-extended."
)


def _extract_call_args(text: str, start: int) -> str | None:
    """Return a call's arguments, given the index just after its opening
    `(`, handling nested brackets and string quotes so a nested call (or a
    multi-line argument list) doesn't terminate extraction early."""
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


def _check_s3_encryption(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    for match in _S3_UPLOAD_CALL_RE.finditer(text):
        args = _extract_call_args(text, match.end())
        if args is None or "ServerSideEncryption" in args:
            continue
        line, _ = _line_and_column(text, match.start())
        yield (
            "s3-upload-without-encryption",
            "MEDIUM",
            "S3 upload without server-side encryption — data stored in S3 "
            "will not be encrypted at rest",
            _S3_ENCRYPTION_REMEDIATION,
            line,
        )


def _check_s3_versioning(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    if "put_bucket_versioning" in text:
        return
    for match in _S3_CREATE_BUCKET_RE.finditer(text):
        line, _ = _line_and_column(text, match.start())
        yield (
            "s3-bucket-without-versioning",
            "LOW",
            "S3 bucket created without versioning — accidental deletion or "
            "overwrite of model artifacts cannot be recovered",
            _S3_VERSIONING_REMEDIATION,
            line,
        )


def _check_sagemaker_encryption(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    if "kms" in text.lower():
        return
    for match in _SAGEMAKER_OUTPUT_PATH_RE.finditer(text):
        line, _ = _line_and_column(text, match.start())
        yield (
            "sagemaker-output-without-encryption",
            "MEDIUM",
            "SageMaker training output path without explicit encryption — "
            "model artifacts may be stored unencrypted",
            _SAGEMAKER_ENCRYPTION_REMEDIATION,
            line,
        )


def _check_bigquery_access(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    if "access_entries" in text:
        return
    for match in _BIGQUERY_CREATE_DATASET_RE.finditer(text):
        line, _ = _line_and_column(text, match.start())
        yield (
            "bigquery-dataset-no-access-control",
            "MEDIUM",
            "BigQuery dataset created without explicit access controls",
            _BIGQUERY_ACCESS_REMEDIATION,
            line,
        )


def _check_azure_container_public_access(
    text: str,
) -> Iterator[tuple[str, Severity, str, str, int]]:
    for match in _AZURE_CLIENT_RE.finditer(text):
        args = _extract_call_args(text, match.end())
        if args is None:
            continue
        if "PublicAccessType" in args or re.search(r"public_access\s*=\s*(?!None\b)\S", args):
            line, _ = _line_and_column(text, match.start())
            yield (
                "azure-container-public-access",
                "HIGH",
                "Azure Blob Storage container configured with public "
                "access — blobs are readable without authentication",
                _AZURE_CONTAINER_PUBLIC_REMEDIATION,
                line,
            )


def _check_http_download_to_disk(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    saves_to_disk = bool(_DISK_SAVE_RE.search(text)) or "shutil." in text
    if not saves_to_disk:
        return
    for match in _HTTP_DOWNLOAD_RE.finditer(text):
        line, _ = _line_and_column(text, match.start())
        yield (
            "http-download-to-disk",
            "HIGH",
            "Training data or model downloaded over unencrypted HTTP — "
            "vulnerable to man-in-the-middle attacks and training data "
            "poisoning",
            _HTTP_DOWNLOAD_REMEDIATION,
            line,
        )


def _check_missing_checksum(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    if "hashlib" in text:
        return
    for match in _DOWNLOAD_CALL_RE.finditer(text):
        line, _ = _line_and_column(text, match.start())
        yield (
            "missing-checksum-verification",
            "MEDIUM",
            "File downloaded without checksum verification — integrity of "
            "downloaded model weights or dataset cannot be confirmed",
            _MISSING_CHECKSUM_REMEDIATION,
            line,
        )


def _check_serving_auth(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    lowered = text.lower()
    if any(keyword in lowered for keyword in _AUTH_KEYWORDS):
        return
    for match in _ROUTE_DECORATOR_RE.finditer(text):
        line, _ = _line_and_column(text, match.start())
        yield (
            "serving-endpoint-no-auth",
            "HIGH",
            "Model serving endpoint defined without apparent "
            "authentication — API may be publicly accessible without "
            "credentials",
            _SERVING_AUTH_REMEDIATION,
            line,
        )


def _scan_file_level(text: str) -> Iterator[tuple[str, Severity, str, str, int]]:
    """Run every whole-file-context check against `text` once."""
    yield from _check_s3_encryption(text)
    yield from _check_s3_versioning(text)
    yield from _check_sagemaker_encryption(text)
    yield from _check_bigquery_access(text)
    yield from _check_azure_container_public_access(text)
    yield from _check_http_download_to_disk(text)
    yield from _check_missing_checksum(text)
    yield from _check_serving_auth(text)


# ---------------------------------------------------------------------------
# Dockerfile- and shell-script-specific checks
# ---------------------------------------------------------------------------

_DOCKER_FROM_RE = re.compile(r"^FROM\s+(\S+)", re.IGNORECASE)
_DOCKER_USER_RE = re.compile(r"^USER\s+(\S+)", re.IGNORECASE)
_DOCKER_CMD_ENTRYPOINT_RE = re.compile(r"^(?:CMD|ENTRYPOINT)\b", re.IGNORECASE)
_PIP_INSTALL_RE = re.compile(r"\bpip3?\s+install\b", re.IGNORECASE)

_DOCKER_LATEST_TAG_MESSAGE = (
    "Dockerfile uses :latest tag or no tag — builds are non-reproducible "
    "and may pull different base images over time"
)
_DOCKER_LATEST_TAG_REMEDIATION = (
    "Pin the base image to a specific digest: FROM "
    "pytorch/pytorch@sha256:abc123... or a specific version tag like FROM "
    "pytorch/pytorch:2.1.0-cuda11.8-cudnn8-runtime"
)
_PIP_NO_PIN_MESSAGE = (
    "pip install without version pinning — non-reproducible environment, "
    "future installs may pull incompatible or vulnerable versions"
)
_PIP_NO_PIN_REMEDIATION = "Pin all dependencies: pip install torch==2.1.0 transformers==4.35.0"
_DOCKER_ROOT_USER_MESSAGE = (
    "Docker container runs as root — if the container is compromised the "
    "attacker has root access to the host via container escape"
)
_DOCKER_ROOT_USER_REMEDIATION = (
    "Add USER nonroot or create a dedicated user: RUN useradd -m appuser "
    "&& USER appuser before CMD/ENTRYPOINT."
)


def _is_unpinned_image(image_ref: str) -> bool:
    if "@sha256:" in image_ref:
        return False
    last_segment = image_ref.rsplit("/", 1)[-1]
    if ":" not in last_segment:
        return True
    return last_segment.rsplit(":", 1)[-1] == "latest"


def _scan_dockerfile(path: Path) -> list[Finding]:
    text = path.read_text(errors="ignore")
    if has_ignore_file_marker(text):
        return []

    findings: list[Finding] = []
    has_nonroot_user = False
    last_cmd_entrypoint_line = 1

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()

        if (match := _DOCKER_FROM_RE.match(stripped)) and _is_unpinned_image(match.group(1)):
            findings.append(
                _build_finding(
                    "docker-latest-tag",
                    "MEDIUM",
                    _DOCKER_LATEST_TAG_MESSAGE,
                    _DOCKER_LATEST_TAG_REMEDIATION,
                    path,
                    line_number,
                    1,
                )
            )

        if _PIP_INSTALL_RE.search(line) and "==" not in line:
            findings.append(
                _build_finding(
                    "pip-install-no-pin",
                    "MEDIUM",
                    _PIP_NO_PIN_MESSAGE,
                    _PIP_NO_PIN_REMEDIATION,
                    path,
                    line_number,
                    1,
                )
            )

        if user_match := _DOCKER_USER_RE.match(stripped):
            user = user_match.group(1).split(":")[0].strip().lower()
            if user and user != "root":
                has_nonroot_user = True

        if _DOCKER_CMD_ENTRYPOINT_RE.match(stripped):
            last_cmd_entrypoint_line = line_number

    if not has_nonroot_user:
        findings.append(
            _build_finding(
                "docker-root-user",
                "HIGH",
                _DOCKER_ROOT_USER_MESSAGE,
                _DOCKER_ROOT_USER_REMEDIATION,
                path,
                last_cmd_entrypoint_line,
                1,
            )
        )

    return filter_suppressed(findings, text)


def _scan_shell_script(path: Path) -> list[Finding]:
    text = path.read_text(errors="ignore")
    if has_ignore_file_marker(text):
        return []

    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if _PIP_INSTALL_RE.search(line) and "==" not in line:
            findings.append(
                _build_finding(
                    "pip-install-no-pin",
                    "MEDIUM",
                    _PIP_NO_PIN_MESSAGE,
                    _PIP_NO_PIN_REMEDIATION,
                    path,
                    line_number,
                    1,
                )
            )
    return filter_suppressed(findings, text)


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for cloud misconfigurations and infrastructure risks."""
    if "dockerfile" in path.name.lower():
        return _scan_dockerfile(path)
    if path.suffix in (".sh", ".bash", ".zsh"):
        return _scan_shell_script(path)
    if path.suffix == ".ipynb":
        return _scan_notebook(path)
    if path.suffix == ".py":
        return _scan_text_file(path)
    return []


def _scan_text_file(path: Path) -> list[Finding]:
    text = path.read_text(errors="ignore")
    if has_ignore_file_marker(text):
        return []

    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, severity, message, remediation, column in _scan_line(line):
            findings.append(
                _build_finding(rule, severity, message, remediation, path, line_number, column)
            )
    for rule, severity, message, remediation, fl_line in _scan_file_level(text):
        findings.append(_build_finding(rule, severity, message, remediation, path, fl_line, 1))
    return filter_suppressed(findings, text)


def _scan_notebook(path: Path) -> list[Finding]:
    try:
        notebook = json.loads(path.read_text(errors="ignore"))
    except json.JSONDecodeError:
        return []

    if notebook_has_ignore_file_marker(notebook):
        return []

    findings = []
    combined_lines: list[str] = []
    combined_line_cell: list[int] = []
    combined_line_number: list[int] = []

    for cell_number, cell in enumerate(notebook.get("cells", []), start=1):
        if cell.get("cell_type") != "code":
            continue

        source = cell.get("source", "")
        text = "".join(source) if isinstance(source, list) else source

        for line_number, line in enumerate(text.splitlines(), start=1):
            for rule, severity, message, remediation, column in _scan_line(line):
                findings.append(
                    _build_finding(
                        rule, severity, message, remediation, path, line_number, column,
                        cell=cell_number,
                    )
                )
            combined_lines.append(line)
            combined_line_cell.append(cell_number)
            combined_line_number.append(line_number)

    combined_text = "\n".join(combined_lines)
    for rule, severity, message, remediation, fl_line in _scan_file_level(combined_text):
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
        type="cloud",
        severity=severity,
        file=str(path),
        line=line,
        column=column,
        message=message,
        detail=message,
        remediation=remediation,
        cell=cell,
    )


_SCAN_EXTENSIONS = frozenset({".py", ".ipynb", ".sh", ".bash", ".zsh", ".dockerfile"})
_SCAN_FILENAMES = frozenset({"Dockerfile"})
_SCAN_NAME_SUBSTRINGS = frozenset({"dockerfile"})


def scan_path(root: Path) -> Iterator[Finding]:
    """Walk `root` and yield cloud misconfiguration findings."""
    for path in walk_files(
        root,
        include_extensions=_SCAN_EXTENSIONS,
        include_filenames=_SCAN_FILENAMES,
        include_name_substrings=_SCAN_NAME_SUBSTRINGS,
    ):
        yield from scan_file(path)


def count_files(root: Path) -> int:
    """Count how many files `scan_path(root)` would examine."""
    return sum(
        1
        for _ in walk_files(
            root,
            include_extensions=_SCAN_EXTENSIONS,
            include_filenames=_SCAN_FILENAMES,
            include_name_substrings=_SCAN_NAME_SUBSTRINGS,
        )
    )
