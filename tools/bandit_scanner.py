

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from typing import Any

from graph.state import SecurityIssue, Severity

logger = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "HIGH":   Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW":    Severity.LOW,
}

_OWASP_MAP: dict[str, str] = {
    "B101": "A05:2021", "B102": "A01:2021", "B105": "A07:2021",
    "B106": "A07:2021", "B107": "A07:2021", "B201": "A05:2021",
    "B301": "A08:2021", "B302": "A08:2021", "B303": "A02:2021",
    "B304": "A02:2021", "B307": "A03:2021", "B311": "A02:2021",
    "B324": "A02:2021", "B401": "A06:2021", "B403": "A08:2021",
    "B404": "A03:2021", "B501": "A02:2021", "B502": "A02:2021",
    "B505": "A02:2021", "B506": "A08:2021", "B602": "A03:2021",
    "B603": "A03:2021", "B605": "A03:2021", "B607": "A03:2021",
    "B608": "A03:2021", "B701": "A03:2021", "B702": "A03:2021",
}

_CWE_MAP: dict[str, str] = {
    "B105": "CWE-259", "B106": "CWE-259", "B107": "CWE-259",
    "B301": "CWE-502", "B302": "CWE-502", "B303": "CWE-327",
    "B307": "CWE-78",  "B311": "CWE-330", "B501": "CWE-295",
    "B502": "CWE-326", "B602": "CWE-78",  "B605": "CWE-78",
    "B608": "CWE-89",
}


def run_bandit(filename: str, source_code: str) -> list[dict[str, Any]]:
    """
    Runs Bandit on source_code and returns SecurityIssue-compatible dicts.
    """
    issues: list[dict] = []

    with tempfile.NamedTemporaryFile(
        suffix=".py", mode="w", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(source_code)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["bandit", "-f", "json", "-q", tmp_path],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode not in (0, 1):
            logger.warning("Bandit exited with code %d: %s", result.returncode, result.stderr)
            return issues

        raw = json.loads(result.stdout or "{}")
        for finding in raw.get("results", []):
            test_id = finding.get("test_id", "")
            sev_str = finding.get("issue_severity", "LOW").upper()
            issue = SecurityIssue(
                filename     = filename,
                line         = finding.get("line_number", 0),
                severity     = _SEVERITY_MAP.get(sev_str, Severity.LOW),
                category     = finding.get("test_name", "Unknown").replace("_", " ").title(),
                cwe_id       = _CWE_MAP.get(test_id),
                owasp        = _OWASP_MAP.get(test_id),
                description  = finding.get("issue_text", ""),
                source       = "bandit",
                code_snippet = finding.get("code", "").strip(),
            )
            issues.append(issue.model_dump())

    except subprocess.TimeoutExpired:
        logger.error("Bandit timed out on %s", filename)
    except json.JSONDecodeError as exc:
        logger.error("Bandit JSON parse error: %s", exc)
    except FileNotFoundError:
        logger.error("Bandit not installed. Run: pip install bandit")
    finally:
        os.unlink(tmp_path)

    logger.debug("Bandit found %d issue(s) in %s", len(issues), filename)
    return issues