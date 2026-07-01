#!/usr/bin/env python3
"""Agent 5 — The Config Enforcer. See AGENTS.md for the full spec."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from _agent_utils import CheckList, run_scan_json

ROOT = Path(__file__).parent.parent.parent
FIXTURE = ROOT / "tests" / "fixtures" / "config_enforcer"
CONFIG = FIXTURE / ".vigilml.yml"


def main() -> None:
    subprocess.run(
        [sys.executable, str(ROOT / "tests" / "fixtures" / "setup_all_fixtures.py")],
        check=True,
        capture_output=True,
    )

    checks = CheckList("Agent 5 — The Config Enforcer")
    _, payload = run_scan_json(str(FIXTURE), "--config", str(CONFIG))
    findings = payload["findings"]

    checks.check(
        "Files in legacy/ are not scanned",
        not any("/legacy/" in f["file"] for f in findings),
    )
    checks.check(
        "Cloud misconfiguration findings are absent (rule disabled)",
        not any(f["type"] == "cloud" for f in findings),
    )

    credential_findings = [f for f in findings if f["type"] == "credential"]
    checks.check(
        "Credential findings show CRITICAL severity (overridden)",
        bool(credential_findings) and all(f["severity"] == "CRITICAL" for f in credential_findings),
    )

    dependency_findings = [f for f in findings if f["type"] == "dependency"]
    checks.check(
        "LOW and MEDIUM CVEs are not reported (min_severity: HIGH)",
        all(f["severity"] in ("HIGH", "CRITICAL") for f in dependency_findings),
    )

    checks.check(
        "scripts/generate_keys.py credential finding is suppressed",
        not any(f["file"].endswith("scripts/generate_keys.py") for f in findings),
    )

    checks.check(
        "Suppressed finding appears in summary as '1 ignored'",
        payload["summary"]["ignored"] == 1
        and payload["ignored_findings"][0]["file"].endswith("scripts/generate_keys.py"),
    )

    checks.finish()


if __name__ == "__main__":
    main()
