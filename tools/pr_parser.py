

from __future__ import annotations

import ast
import logging
from typing import Any

from graph.state import Language, ParsedFile, PRFile

logger = logging.getLogger(__name__)

_EXT_MAP: dict[str, Language] = {
    ".py":  Language.PYTHON,
    ".js":  Language.JAVASCRIPT,
    ".ts":  Language.TYPESCRIPT,
    ".jsx": Language.JSX,
    ".tsx": Language.TSX,
}

_IGNORE_PATTERNS = {
    "package-lock.json", "yarn.lock", "poetry.lock",
    ".min.js", ".min.css", ".map",
}


def detect_language(filename: str) -> Language:
    for pattern in _IGNORE_PATTERNS:
        if filename.endswith(pattern):
            return Language.UNKNOWN
    suffix = "." + filename.rsplit(".", 1)[-1] if "." in filename else ""
    return _EXT_MAP.get(suffix.lower(), Language.UNKNOWN)


def extract_python_functions(source: str) -> list[dict[str, Any]]:
    """
    Returns list of {name, start_line, end_line, source} dicts.
    Falls back to empty list on any parse error.
    """
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []

    lines     = source.splitlines()
    functions: list[dict[str, Any]] = []

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start      = node.lineno - 1
            end        = node.end_lineno or start
            func_lines = lines[start:end]
            functions.append({
                "name":       node.name,
                "start_line": node.lineno,
                "end_line":   end,
                "source":     "\n".join(func_lines),
            })

    return functions


def parse_pr_files(raw_files: list[dict]) -> list[ParsedFile]:
    """
    Converts raw PR file dicts into enriched ParsedFile objects.
    Skips unsupported / ignored files.
    """
    parsed: list[ParsedFile] = []

    for raw in raw_files:
        try:
            pf = PRFile(**raw)
        except Exception as exc:
            logger.warning("Skipping malformed PR file entry: %s", exc)
            continue

        lang = detect_language(pf.filename)
        if lang == Language.UNKNOWN:
            logger.debug("Skipping unsupported file: %s", pf.filename)
            continue

        functions: list[dict] = []
        ast_available = False

        if lang == Language.PYTHON and pf.content:
            functions     = extract_python_functions(pf.content)
            ast_available = True

        parsed.append(ParsedFile(
            filename      = pf.filename,
            language      = lang,
            content       = pf.content,
            patch         = pf.patch,
            additions     = pf.additions,
            deletions     = pf.deletions,
            functions     = functions,
            ast_available = ast_available,
        ))
        logger.debug("Parsed %s (%s) — %d function(s)", pf.filename, lang, len(functions))

    logger.info("parse_pr_files: %d/%d files accepted", len(parsed), len(raw_files))
    return parsed