#!/usr/bin/env python3
"""Agent 6 — The Notebook Specialist. See AGENTS.md for the full spec."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from _agent_utils import CheckList, run_scan_json

ROOT = Path(__file__).parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "notebook_specialist"


def _findings_for(payload: dict, filename: str) -> list[dict]:
    return [f for f in payload["findings"] if f["file"].endswith(filename)]


def main() -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "tests" / "fixtures" / "setup_all_fixtures.py")],
        check=True,
        capture_output=True,
    )

    checks = CheckList("Agent 6 — The Notebook Specialist")
    _, payload = run_scan_json(str(FIXTURE))

    key_findings = _findings_for(payload, "notebook_with_key.ipynb")
    checks.check(
        "notebook_with_key.ipynb: OpenAI key found, references cell 3",
        any(f["rule"] == "openai-api-key" and f.get("cell") == 3 for f in key_findings),
    )

    pickle_findings = _findings_for(payload, "notebook_with_pickle.ipynb")
    checks.check(
        "notebook_with_pickle.ipynb: pickle.load() found, references cell 7",
        any(f["rule"] == "pickle-load" and f.get("cell") == 7 for f in pickle_findings),
    )

    torch_findings = _findings_for(payload, "notebook_with_torch.ipynb")
    checks.check(
        "notebook_with_torch.ipynb: torch.load() found, references cell 2",
        any(
            f["rule"] == "torch-load-without-weights-only" and f.get("cell") == 2
            for f in torch_findings
        ),
    )

    multioutput_findings = _findings_for(payload, "notebook_multioutput.ipynb")
    checks.check(
        "notebook_multioutput.ipynb: credential in source found once (output not scanned)",
        len(multioutput_findings) == 1 and multioutput_findings[0]["rule"] == "aws-access-key",
    )

    checks.check(
        "notebook_clean.ipynb: zero findings",
        _findings_for(payload, "notebook_clean.ipynb") == [],
    )

    checks.check(
        "All findings reference a cell number (notebook scanning is cell-aware)",
        all(f.get("cell") is not None for f in payload["findings"]),
    )

    checks.finish()


if __name__ == "__main__":
    main()
