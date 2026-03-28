from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from langchain_groq import ChatGroq
from langchain_core.messages import SystemMessage, HumanMessage

from graph.state import Language, Severity
from tools.bandit_scanner      import run_bandit
from tools.semgrep_scanner     import run_semgrep
from tools.codebert_classifier import classify_functions

logger = logging.getLogger(__name__)

# ─── LLM setup ────────────────────────────────────────────────────────────────

def _get_llm() -> ChatGroq:
    return ChatGroq(
        model="llama-3.3-70b-versatile",
        temperature=0.1,
        api_key=os.getenv("GROQ_API_KEY"),
    )


# ─── Scanner dispatch ─────────────────────────────────────────────────────────

def _scan_file(parsed_file: dict) -> list[dict]:
    """Runs all 3 scanners on a single file and merges results."""
    filename  = parsed_file["filename"]
    content   = parsed_file.get("content", "")
    language  = Language(parsed_file.get("language", "unknown"))
    functions = parsed_file.get("functions", [])

    issues: list[dict] = []

    # Layer 1 — Bandit (Python only)
    if language == Language.PYTHON and content:
        issues.extend(run_bandit(filename, content))

    # Layer 2 — Semgrep (multi-language)
    if content:
        issues.extend(run_semgrep(filename, content, language))

    # Layer 3 — CodeBERT (Python functions)
    if language == Language.PYTHON and functions:
        issues.extend(classify_functions(filename, functions))

    return issues


# ─── LLM enrichment ───────────────────────────────────────────────────────────

def _build_enrichment_prompt(issues: list[dict], file_content: str) -> str:
    issues_text = ""
    for i, issue in enumerate(issues, 1):
        issues_text += (
            f"\n[{i}] File: {issue['filename']} | Line: {issue['line']}\n"
            f"    Category: {issue['category']} | Severity: {issue['severity']}\n"
            f"    Source: {issue['source']} | Description: {issue['description']}\n"
            f"    Snippet: {(issue.get('code_snippet') or '')[:200]}\n"
        )

    return f"""You are a senior application security engineer reviewing static analysis findings.

SOURCE CODE (truncated to 3000 chars):
```
{file_content[:3000]}
```

SCANNER FINDINGS:
{issues_text}

Your tasks:
1. For each finding, decide if it is a TRUE POSITIVE or FALSE POSITIVE.
2. For false positives, explain why (e.g. controlled input, unreachable code, test-only context).
3. Identify any ADDITIONAL vulnerabilities the scanners missed that you can see in the code.
4. Add exploitation context for true positives (how could an attacker exploit this?).

Respond ONLY as JSON (no markdown fences) with this exact structure:
{{
  "reviewed": [
    {{
      "index": 1,
      "false_positive": false,
      "fp_reason": null,
      "exploitation_context": "An attacker could ..."
    }}
  ],
  "additional_issues": [
    {{
      "filename": "app.py",
      "line": 42,
      "severity": "high",
      "category": "Broken Access Control",
      "description": "...",
      "exploitation_context": "..."
    }}
  ]
}}"""


def _llm_enrich(issues: list[dict], file_content: str) -> list[dict]:
    """
    Sends all scanner findings to the LLM for FP filtering and enrichment.
    Returns the final deduplicated issue list.
    """
    if not issues:
        return []

    try:
        llm    = _get_llm()
        prompt = _build_enrichment_prompt(issues, file_content)
        resp   = llm.invoke([
            SystemMessage(content="You are a code security expert. Respond only with valid JSON."),
            HumanMessage(content=prompt),
        ])

        import json
        raw = resp.content.strip()
        # Strip accidental markdown code fences
        if raw.startswith("```"):
            raw = raw.split("\n", 1)[1].rsplit("```", 1)[0]
        data = json.loads(raw)

    except Exception as exc:
        logger.warning("LLM enrichment failed: %s — returning raw scanner results", exc)
        return issues

    # Apply FP verdicts
    reviewed_map: dict[int, dict] = {
        r["index"]: r for r in data.get("reviewed", [])
    }
    enriched: list[dict] = []

    for idx, issue in enumerate(issues, 1):
        review = reviewed_map.get(idx, {})
        issue  = dict(issue)
        if review.get("false_positive"):
            issue["false_positive"] = True
            issue["fp_reason"]      = review.get("fp_reason", "Dismissed by LLM reviewer")
        else:
            ctx = review.get("exploitation_context")
            if ctx:
                issue["description"] = issue["description"] + f"\n\nExploitation: {ctx}"
        enriched.append(issue)

    # Append LLM-only additional issues
    from graph.state import SecurityIssue
    for extra in data.get("additional_issues", []):
        sev_str = extra.get("severity", "medium").upper()
        sev_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
                   "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
        issue = SecurityIssue(
            filename    = extra.get("filename", "unknown"),
            line        = extra.get("line", 0),
            severity    = sev_map.get(sev_str, Severity.MEDIUM),
            category    = extra.get("category", "Security Issue"),
            description = extra.get("description", ""),
            source      = "llm",
        )
        enriched.append(issue.model_dump())

    logger.debug("LLM enrichment: %d raw → %d final issues", len(issues), len(enriched))
    return enriched


# ─── Main agent ───────────────────────────────────────────────────────────────

def run(state: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph node function.
    Input:  state["parsed_files"]
    Output: {"security_issues": list[dict]}
    """
    parsed_files   = state.get("parsed_files", [])
    all_raw_issues: list[dict] = []

    # Run scanners in parallel (one thread per file)
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = {executor.submit(_scan_file, pf): pf for pf in parsed_files}
        for future in as_completed(futures):
            pf = futures[future]
            try:
                issues = future.result()
                all_raw_issues.extend(issues)
            except Exception as exc:
                logger.error("Scanner failed on %s: %s", pf.get("filename"), exc)

    logger.info("security_agent: %d raw issues from scanners", len(all_raw_issues))

    # Enrich with LLM (per-file to keep prompt sizes manageable)
    final_issues: list[dict] = []
    for pf in parsed_files:
        file_issues = [i for i in all_raw_issues if i["filename"] == pf["filename"]]
        if not file_issues:
            continue
        enriched = _llm_enrich(file_issues, pf.get("content", ""))
        final_issues.extend(enriched)

    # Files with no issues from any scanner (add empty pass)
    scanned_files = {i["filename"] for i in all_raw_issues}
    for pf in parsed_files:
        if pf["filename"] not in scanned_files:
            final_issues.extend([])   # No issues — no action needed

    logger.info("security_agent: %d final issues after LLM enrichment", len(final_issues))
    return {"security_issues": final_issues}