from __future__ import annotations

import json
import logging
import os
from typing import Any

from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

from graph.state import Language, QualityIssue, Severity
from tools.quality_analyzer import analyse_quality

logger = logging.getLogger(__name__)


def _get_llm() -> ChatGroq:
    return ChatGroq(
        model="llama-3.3-70b-versatile",
        temperature=0.1,
        api_key=os.getenv("GROQ_API_KEY"),
    )


def _llm_quality_review(filename: str, content: str) -> list[dict]:
    """
    Asks the LLM for higher-level code quality observations.
    Returns a list of QualityIssue dicts.
    """
    prompt = f"""You are a senior software engineer doing a code quality review.

FILE: {filename}
```
{content[:3000]}
```

Identify code quality issues that static tools miss: poor naming, violations of
single-responsibility principle, obvious code duplication, missing error handling,
and unclear logic. Be concise — only flag real problems, not style preferences.

Respond ONLY as JSON (no markdown fences):
{{
  "issues": [
    {{
      "line": 10,
      "severity": "medium",
      "category": "Poor Naming",
      "description": "Variable `d` should have a descriptive name like `user_data`."
    }}
  ]
}}"""

    try:
        llm  = _get_llm()
        resp = llm.invoke([
            SystemMessage(content="You are a code quality expert. Respond only with valid JSON."),
            HumanMessage(content=prompt),
        ])
        raw = resp.content.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
        data = json.loads(raw)

    except Exception as exc:
        logger.warning("LLM quality review failed: %s", exc)
        return []

    sev_map = {
        "critical": Severity.CRITICAL, "high": Severity.HIGH,
        "medium": Severity.MEDIUM, "low": Severity.LOW, "info": Severity.INFO,
    }

    issues = []
    for item in data.get("issues", []):
        issue = QualityIssue(
            filename    = filename,
            line        = item.get("line", 1),
            severity    = sev_map.get(item.get("severity", "low"), Severity.LOW),
            category    = item.get("category", "Quality Issue"),
            description = item.get("description", ""),
        )
        issues.append(issue.model_dump())

    return issues


def run(state: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph node function.
    Input:  state["parsed_files"]
    Output: {"quality_issues": list[dict]}
    """
    parsed_files = state.get("parsed_files", [])
    all_issues: list[dict] = []

    for pf in parsed_files:
        filename = pf["filename"]
        content  = pf.get("content", "")
        language = Language(pf.get("language", "unknown"))

        # Static analysis (Python only)
        if language == Language.PYTHON and content:
            all_issues.extend(analyse_quality(filename, content))

        # LLM review (all supported languages)
        if content:
            all_issues.extend(_llm_quality_review(filename, content))

    logger.info("quality_agent: %d issue(s) found", len(all_issues))
    return {"quality_issues": all_issues}