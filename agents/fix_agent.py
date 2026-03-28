from __future__ import annotations

import ast
import json
import logging
import os
from typing import Any

from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

from graph.state import CodeFix, Severity

logger = logging.getLogger(__name__)

# ─── Fix templates ────────────────────────────────────────────────────────────

_TEMPLATES: dict[str, str] = {
    "sql injection": (
        "Replace string-concatenated SQL with parameterized queries. "
        "Use `cursor.execute(query, params)` where params is a tuple."
    ),
    "shell injection": (
        "Replace shell=True subprocess calls with a list of arguments: "
        "`subprocess.run(['cmd', 'arg1', 'arg2'])`. Never pass user input to shell."
    ),
    "command injection": (
        "Use subprocess with a list of args (no shell=True). "
        "Validate and sanitize any user-controlled values before use."
    ),
    "hardcoded credential": (
        "Move secrets to environment variables: "
        "`import os; secret = os.getenv('SECRET_NAME')`. "
        "Never commit secrets to source control."
    ),
    "hardcoded password": (
        "Move passwords to environment variables using os.getenv(). "
        "Consider using a secrets manager (e.g. AWS Secrets Manager, Vault)."
    ),
    "weak cryptography": (
        "Replace MD5/SHA1 with SHA-256 or stronger: "
        "`hashlib.sha256(data).hexdigest()`. "
        "For passwords, use bcrypt or argon2 — never raw hashlib."
    ),
    "insecure deserialization": (
        "Replace pickle with json.loads() for untrusted data. "
        "If pickle is required, only unpickle data from trusted, signed sources."
    ),
    "arbitrary code execution": (
        "Replace eval() with ast.literal_eval() for safe expression parsing, "
        "or refactor to avoid dynamic code execution entirely."
    ),
    "tls verification disabled": (
        "Remove `verify=False` from requests calls. "
        "If using a custom CA, pass `verify='/path/to/ca-bundle.crt'` instead."
    ),
    "unsafe yaml deserialization": (
        "Replace yaml.load() with yaml.safe_load() which disallows arbitrary objects."
    ),
    "missing docstring": (
        "Add a Google-style docstring describing the function's purpose, "
        "arguments, and return value."
    ),
    "high complexity": (
        "Refactor by extracting sub-functions for each logical block. "
        "Aim for a cyclomatic complexity of 10 or less per function."
    ),
}


def _get_template(category: str) -> str:
    key = category.lower()
    for pattern, guidance in _TEMPLATES.items():
        if pattern in key:
            return guidance
    return "Apply the principle of least privilege and follow OWASP secure coding guidelines."


def _get_llm() -> ChatGroq:
    return ChatGroq(
        model="llama-3.3-70b-versatile",
        temperature=0.1,
        api_key=os.getenv("GROQ_API_KEY"),
    )


def _generate_fix(issue: dict, file_content: str) -> dict | None:
    """
    Asks the LLM to produce a minimal fix for one issue.
    Returns a CodeFix dict or None on failure.
    """
    template = _get_template(issue.get("category", ""))
    snippet  = issue.get("code_snippet") or ""

    prompt = f"""You are a security engineer fixing a code vulnerability.

ISSUE:
  File:        {issue['filename']}
  Line:        {issue['line']}
  Category:    {issue['category']}
  Severity:    {issue['severity']}
  Description: {issue['description']}

VULNERABLE SNIPPET:
```python
{snippet or file_content[max(0, issue['line']*40-200):issue['line']*40+200]}
```

FIX GUIDANCE: {template}

Produce a minimal, correct fix. Do NOT rewrite unrelated code.

Respond ONLY as JSON (no markdown fences):
{{
  "description": "One sentence describing the fix",
  "original": "the exact vulnerable code (5-15 lines max)",
  "fixed":    "the corrected replacement code",
  "explanation": "Why this fix eliminates the vulnerability"
}}"""

    try:
        llm  = _get_llm()
        resp = llm.invoke([
            SystemMessage(content="You are a security code-fix expert. Respond only with valid JSON."),
            HumanMessage(content=prompt),
        ])
        raw = resp.content.strip()
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
        data = json.loads(raw)

    except Exception as exc:
        logger.warning("Fix generation failed for issue %s: %s", issue.get("id"), exc)
        return None

    fixed_code = data.get("fixed", "")
    validated  = False
    try:
        ast.parse(fixed_code)
        validated = True
    except SyntaxError as syn:
        logger.warning("Generated fix has syntax error (%s) — including but flagged", syn)

    fix = CodeFix(
        issue_id    = issue.get("id", "unknown"),
        filename    = issue["filename"],
        description = data.get("description", "Fix applied"),
        original    = data.get("original", snippet),
        fixed       = fixed_code,
        explanation = data.get("explanation", ""),
        validated   = validated,
    )
    return fix.model_dump()


_FIX_SEVERITIES = {Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value}


def run(state: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph node function.
    Input:  state["security_issues"], state["parsed_files"]
    Output: {"fixes": list[dict]}
    """
    security_issues = state.get("security_issues", [])
    parsed_files    = state.get("parsed_files", [])

    content_map = {pf["filename"]: pf.get("content", "") for pf in parsed_files}

    fixable = [
        i for i in security_issues
        if (
            not i.get("false_positive")
            and i.get("severity") in _FIX_SEVERITIES
            and i.get("source") != "codebert"
        )
    ]

    logger.info("fix_agent: generating fixes for %d/%d issue(s)", len(fixable), len(security_issues))

    fixes: list[dict] = []
    for issue in fixable[:10]:
        content = content_map.get(issue["filename"], "")
        fix     = _generate_fix(issue, content)
        if fix:
            fixes.append(fix)

    logger.info("fix_agent: generated %d fix(es)", len(fixes))
    return {"fixes": fixes}