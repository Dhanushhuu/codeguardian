

from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
from typing import Any

from graph.state import Language, SecurityIssue, Severity

logger = logging.getLogger(__name__)

_RULESET: dict[Language, str] = {
    Language.PYTHON:     "p/python",
    Language.JAVASCRIPT: "p/javascript",
    Language.TYPESCRIPT: "p/typescript",
    Language.JSX:        "p/javascript",
    Language.TSX:        "p/typescript",
}

_FILE_EXTENSION: dict[Language, str] = {
    Language.PYTHON:     ".py",
    Language.JAVASCRIPT: ".js",
    Language.TYPESCRIPT: ".ts",
    Language.JSX:        ".jsx",
    Language.TSX:        ".tsx",
}

_SEVERITY_MAP = {
    "ERROR":   Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO":    Severity.LOW,
}


def run_semgrep(filename: str, source_code: str, language: Language) -> list[dict[str, Any]]:
    """
    Runs Semgrep on source_code and returns SecurityIssue-compatible dicts.
    Falls back gracefully if Semgrep is not installed.
    """
    issues: list[dict] = []
    ruleset = _RULESET.get(language)
    ext     = _FILE_EXTENSION.get(language, ".py")

    if not ruleset:
        logger.debug("No Semgrep ruleset for language %s — skipping", language)
        return issues

    with tempfile.NamedTemporaryFile(
        suffix=ext, mode="w", delete=False, encoding="utf-8"
    ) as tmp:
        tmp.write(source_code)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["semgrep", "--config", ruleset, "--json", "--quiet", "--no-git-ignore", tmp_path],
            capture_output=True, text=True, timeout=60,
        )
        raw = json.loads(result.stdout or "{}")
        for finding in raw.get("results", []):
            check_id     = finding.get("check_id", "")
            severity_str = finding.get("extra", {}).get("severity", "WARNING").upper()
            message      = finding.get("extra", {}).get("message", "")
            lines        = finding.get("extra", {}).get("lines", "").strip()
            category     = check_id.split(".")[-1].replace("-", " ").replace("_", " ").title()

            issue = SecurityIssue(
                filename     = filename,
                line         = finding.get("start", {}).get("line", 0),
                severity     = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM),
                category     = category,
                description  = message,
                source       = "semgrep",
                code_snippet = lines,
            )
            issues.append(issue.model_dump())

    except subprocess.TimeoutExpired:
        logger.error("Semgrep timed out on %s", filename)
    except json.JSONDecodeError as exc:
        logger.error("Semgrep JSON parse error: %s", exc)
    except FileNotFoundError:
        logger.warning("Semgrep not installed. Run: pip install semgrep")
    finally:
        os.unlink(tmp_path)

    logger.debug("Semgrep found %d issue(s) in %s", len(issues), filename)
    return issues