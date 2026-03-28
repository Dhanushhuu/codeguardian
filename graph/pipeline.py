

from __future__ import annotations

import time
import uuid
import logging
from typing import Any

from langgraph.graph import StateGraph, END

from graph.state import ReviewState

logger = logging.getLogger(__name__)


# ─── Event helper ─────────────────────────────────────────────────────────────
# Returns a NEW list with just this one event.
# LangGraph merges it into the accumulated events list via operator.add.

def _evt(agent: str, message: str) -> list[dict]:
    return [{"agent": agent, "message": message, "ts": time.time()}]


# ─── Node wrappers ────────────────────────────────────────────────────────────

def node_parser(state: ReviewState) -> dict[str, Any]:
    from agents.parser_agent import run as run_parser
    logger.info("[pipeline] parser_agent starting")
    result = run_parser(state)
    n = len(result.get("parsed_files", []))
    return {
        "parsed_files": result["parsed_files"],
        "events":       _evt("parser", f"Parsed {n} file(s)"),
    }


def node_security(state: ReviewState) -> dict[str, Any]:
    from agents.security_agent import run as run_security
    logger.info("[pipeline] security_agent starting")
    result = run_security(state)
    n = len(result.get("security_issues", []))
    return {
        "security_issues": result["security_issues"],
        "events":          _evt("security", f"Found {n} security issue(s)"),
    }


def node_quality(state: ReviewState) -> dict[str, Any]:
    from agents.quality_agent import run as run_quality
    logger.info("[pipeline] quality_agent starting")
    result = run_quality(state)
    n = len(result.get("quality_issues", []))
    return {
        "quality_issues": result["quality_issues"],
        "events":         _evt("quality", f"Found {n} quality issue(s)"),
    }


def node_fix(state: ReviewState) -> dict[str, Any]:
    from agents.fix_agent import run as run_fix
    logger.info("[pipeline] fix_agent starting")
    result = run_fix(state)
    n = len(result.get("fixes", []))
    return {
        "fixes":  result["fixes"],
        "events": _evt("fix", f"Generated {n} fix(es)"),
    }


def node_test_writer(state: ReviewState) -> dict[str, Any]:
    from agents.test_writer_agent import run as run_tests
    logger.info("[pipeline] test_writer_agent starting")
    result = run_tests(state)
    n = len(result.get("tests", []))
    return {
        "tests":  result["tests"],
        "events": _evt("test_writer", f"Generated {n} test file(s)"),
    }


def node_reviewer(state: ReviewState) -> dict[str, Any]:
    from agents.reviewer_agent import run as run_reviewer
    logger.info("[pipeline] reviewer_agent starting")
    result = run_reviewer(state)
    verdict = (result.get("report") or {}).get("verdict", "unknown")
    return {
        "report": result["report"],
        "events": _evt("reviewer", f"Review complete — verdict: {verdict}"),
    }


# ─── Graph construction ───────────────────────────────────────────────────────

def build_graph() -> StateGraph:
    g = StateGraph(ReviewState)

    g.add_node("parser",      node_parser)
    g.add_node("security",    node_security)
    g.add_node("quality",     node_quality)
    g.add_node("fix",         node_fix)
    g.add_node("test_writer", node_test_writer)
    g.add_node("reviewer",    node_reviewer)

    g.set_entry_point("parser")

    # Fan-out: parser -> security AND quality in parallel
    g.add_edge("parser",   "security")
    g.add_edge("parser",   "quality")

    # Fan-in: both must finish before fix runs
    g.add_edge("security", "fix")
    g.add_edge("quality",  "fix")

    # Sequential tail
    g.add_edge("fix",         "test_writer")
    g.add_edge("test_writer", "reviewer")
    g.add_edge("reviewer",    END)

    return g.compile()


# ─── Public entry point ───────────────────────────────────────────────────────

def run_review(pr_files: list[dict], pr_url: str = "") -> dict[str, Any]:
    """
    Runs the full review pipeline.

    Args:
        pr_files: List of PRFile-compatible dicts.
        pr_url:   Optional GitHub PR URL for posting comments.

    Returns:
        Final ReviewState dict.
    """
    graph = build_graph()

    initial_state: ReviewState = {
        "review_id":       str(uuid.uuid4()),
        "pr_files":        pr_files,
        "pr_url":          pr_url,
        "parsed_files":    [],
        "security_issues": [],
        "quality_issues":  [],
        "fixes":           [],
        "tests":           [],
        "report":          None,
        "error":           None,
        "events":          [],
    }

    try:
        final_state = graph.invoke(initial_state)
        return final_state
    except Exception as exc:
        logger.exception("[pipeline] Review failed: %s", exc)
        initial_state["error"] = str(exc)
        return initial_state