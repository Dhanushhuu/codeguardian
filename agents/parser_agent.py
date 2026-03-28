from __future__ import annotations

import logging
from typing import Any

from tools.pr_parser import parse_pr_files

logger = logging.getLogger(__name__)


def run(state: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph node function.
    Input:  state["pr_files"] — list of raw PRFile-compatible dicts
    Output: {"parsed_files": list[dict]}
    """
    raw_files = state.get("pr_files", [])
    logger.info("parser_agent: received %d file(s)", len(raw_files))

    parsed = parse_pr_files(raw_files)
    parsed_dicts = [p.model_dump() for p in parsed]

    logger.info("parser_agent: accepted %d/%d file(s)", len(parsed_dicts), len(raw_files))
    return {"parsed_files": parsed_dicts}