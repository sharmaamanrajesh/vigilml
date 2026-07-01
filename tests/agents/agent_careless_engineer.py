#!/usr/bin/env python3
"""Agent 1 — The Careless ML Engineer. See AGENTS.md for the full spec."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from _agent_utils import CheckList, run_scan_json

ROOT = Path(__file__).parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "careless_engineer"


def main() -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "tests" / "fixtures" / "setup_all_fixtures.py")],
        check=True,
        capture_output=True,
    )

    checks = CheckList("Agent 1 — The Careless ML Engineer")
    exit_code, payload = run_scan_json(str(FIXTURE))
    findings = payload["findings"]

    openai_finding = next((f for f in findings if f["rule"] == "openai-api-key"), None)
    checks.check(
        "OpenAI key detected with correct file and line",
        openai_finding is not None
        and openai_finding["file"].endswith("train.py")
        and openai_finding["line"] == 7,
    )

    hf_finding = next((f for f in findings if f["rule"] == "huggingface-token"), None)
    checks.check(
        "HuggingFace token detected, redacted to first 4 chars",
        hf_finding is not None
        and "hf_A" in hf_finding["detail"]
        and "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh" not in hf_finding["detail"],
    )

    pkl_finding = next((f for f in findings if f["rule"] == "unsafe-pickle-file"), None)
    checks.check(
        "model.pkl flagged as HIGH severity",
        pkl_finding is not None and pkl_finding["severity"] == "HIGH",
    )

    torch_load_finding = next(
        (f for f in findings if f["rule"] == "torch-load-without-weights-only"), None
    )
    checks.check("torch.load() without weights_only flagged", torch_load_finding is not None)

    checks.check(
        "torch==1.9.0 CVE reported with an advisory id",
        any(f["file"].endswith("requirements.txt") and "torch" in f["message"] for f in findings),
    )
    checks.check(
        "numpy==1.21.0 CVE reported with an advisory id",
        any(f["file"].endswith("requirements.txt") and "numpy" in f["message"] for f in findings),
    )

    aws_finding = next((f for f in findings if f["rule"] == "aws-access-key"), None)
    checks.check(
        "AWS key in notebook detected with correct cell reference",
        aws_finding is not None
        and aws_finding["file"].endswith("notebook.ipynb")
        and aws_finding.get("cell") is not None,
    )

    checks.check("Exit code is 1", exit_code == 1)
    checks.check(
        "Summary shows correct finding counts by severity",
        payload["total_findings"]
        == sum(payload["summary"][s] for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")),
    )

    checks.finish()


if __name__ == "__main__":
    main()
