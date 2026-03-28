from __future__ import annotations

import json
import logging
import os
from typing import Any

from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

from graph.state import GeneratedTest, Language

logger = logging.getLogger(__name__)


def _get_llm() -> ChatGroq:
    return ChatGroq(
        model="llama-3.3-70b-versatile",
        temperature=0.2,
        api_key=os.getenv("GROQ_API_KEY"),
    )


def _framework_for_language(lang: Language) -> str:
    if lang == Language.PYTHON:
        return "pytest"
    return "jest"


def _generate_tests(
    filename: str,
    language: Language,
    functions: list[dict],
    fixes: list[dict],
) -> dict | None:
    """
    Generates a test file covering the given functions.
    Returns a GeneratedTest dict or None on failure.
    """
    framework   = _framework_for_language(language)
    func_names  = [f["name"] for f in functions[:5]]
    fixed_funcs = [f["issue_id"] for f in fixes if f["filename"] == filename]
    func_sources = "\n\n".join(f.get("source", "") for f in functions[:5])

    prompt = f"""You are a senior test engineer writing {framework} tests.

FILE: {filename}
LANGUAGE: {language}
FUNCTIONS TO TEST: {", ".join(func_names)}
FIXED ISSUES: {len(fixed_funcs)} security fixes were applied to this file.

FUNCTION SOURCE:
```
{func_sources[:2500]}
```

Write a comprehensive {framework} test file that:
1. Tests the NORMAL (happy path) behavior of each function.
2. Tests EDGE CASES: empty input, None, very large input, special characters.
3. Tests SECURITY: ensure fixed vulnerabilities cannot be exploited
   (e.g. SQL injection strings, shell metacharacters, pickle payloads).
4. Uses mocking for external dependencies (DB, filesystem, HTTP).

Respond ONLY as JSON (no markdown fences):
{{
  "filename": "test_{filename.split('/')[-1]}",
  "content":  "# full test file source code as a string",
  "covers":   ["function_name_1", "function_name_2"]
}}"""

    try:
        llm  = _get_llm()
        resp = llm.invoke([
            SystemMessage(content="You are a test engineering expert. Respond only with valid JSON."),
            HumanMessage(content=prompt),
        ])
        raw = resp.content.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
        data = json.loads(raw)

    except Exception as exc:
        logger.warning("Test generation failed for %s: %s", filename, exc)
        return None

    test = GeneratedTest(
        filename  = data.get("filename", f"test_{filename.split('/')[-1]}"),
        framework = framework,
        content   = data.get("content", ""),
        covers    = data.get("covers", func_names),
    )
    return test.model_dump()


def run(state: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph node function.
    Input:  state["parsed_files"], state["fixes"]
    Output: {"tests": list[dict]}
    """
    parsed_files = state.get("parsed_files", [])
    fixes        = state.get("fixes", [])

    # Change to:
    eligible = [
        pf for pf in parsed_files
        if any(f["filename"] == pf["filename"] for f in fixes)
        or pf.get("functions")
        or pf.get("content")
    ]
    logger.info("test_writer_agent: generating tests for %d file(s)", len(eligible))

    tests: list[dict] = []
    for pf in eligible[:5]:
        lang  = Language(pf.get("language", "unknown"))
        funcs = pf.get("functions", [])
        if not funcs:
            continue
        test = _generate_tests(
            filename  = pf["filename"],
            language  = lang,
            functions = funcs,
            fixes     = fixes,
        )
        if test:
            tests.append(test)

    logger.info("test_writer_agent: generated %d test file(s)", len(tests))
    return {"tests": tests}