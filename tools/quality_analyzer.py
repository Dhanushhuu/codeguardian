

from __future__ import annotations

import ast
import logging
from typing import Any

from graph.state import QualityIssue, Severity

logger = logging.getLogger(__name__)

CC_HIGH          = 10
CC_VERY_HIGH     = 15
MI_LOW           = 20
MI_POOR          = 10
MAX_FUNCTION_LINES = 50
MAX_PARAMETERS   = 7
MAX_NESTING_DEPTH = 4


def _run_radon_cc(source: str, filename: str) -> list[dict[str, Any]]:
    issues: list[dict] = []
    try:
        from radon.complexity import cc_visit
        for block in cc_visit(source):
            cc = block.complexity
            if cc < CC_HIGH:
                continue
            issue = QualityIssue(
                filename    = filename,
                line        = block.lineno,
                severity    = Severity.HIGH if cc >= CC_VERY_HIGH else Severity.MEDIUM,
                category    = "High Complexity",
                description = (
                    f"`{block.name}` has cyclomatic complexity {cc} "
                    f"({'very high' if cc >= CC_VERY_HIGH else 'high'} — aim for ≤ {CC_HIGH})."
                ),
                metric      = f"cyclomatic_complexity={cc}",
            )
            issues.append(issue.model_dump())
    except ImportError:
        logger.warning("radon not installed — skipping complexity analysis")
    except Exception as exc:
        logger.debug("radon CC failed on %s: %s", filename, exc)
    return issues


def _run_radon_mi(source: str, filename: str) -> list[dict[str, Any]]:
    issues: list[dict] = []
    try:
        from radon.metrics import mi_visit
        mi = mi_visit(source, multi=True)
        if mi > MI_LOW:
            return issues
        issue = QualityIssue(
            filename    = filename,
            line        = 1,
            severity    = Severity.HIGH if mi <= MI_POOR else Severity.MEDIUM,
            category    = "Low Maintainability",
            description = (
                f"File maintainability index is {mi:.1f}/100 "
                f"({'very low' if mi <= MI_POOR else 'low'} — aim for > {MI_LOW})."
            ),
            metric      = f"maintainability_index={mi:.1f}",
        )
        issues.append(issue.model_dump())
    except ImportError:
        pass
    except Exception as exc:
        logger.debug("radon MI failed on %s: %s", filename, exc)
    return issues


class _NestingVisitor(ast.NodeVisitor):
    def __init__(self):
        self.max_depth  = 0
        self._depth     = 0
        self.worst_line = 0

    def _visit_nested(self, node):
        self._depth += 1
        if self._depth > self.max_depth:
            self.max_depth  = self._depth
            self.worst_line = node.lineno
        self.generic_visit(node)
        self._depth -= 1

    visit_If    = _visit_nested
    visit_For   = _visit_nested
    visit_While = _visit_nested
    visit_With  = _visit_nested
    visit_Try   = _visit_nested


def _ast_checks(source: str, filename: str) -> list[dict[str, Any]]:
    issues: list[dict] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return issues

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        name  = node.name
        start = node.lineno
        end   = node.end_lineno or start
        lines = end - start + 1

        if lines > MAX_FUNCTION_LINES:
            issues.append(QualityIssue(
                filename    = filename,
                line        = start,
                severity    = Severity.MEDIUM,
                category    = "Long Function",
                description = (
                    f"`{name}` is {lines} lines long — "
                    f"consider splitting (aim for ≤ {MAX_FUNCTION_LINES} lines)."
                ),
                metric = f"lines={lines}",
            ).model_dump())

        has_docstring = (
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        )
        if not has_docstring and not name.startswith("_"):
            issues.append(QualityIssue(
                filename    = filename,
                line        = start,
                severity    = Severity.LOW,
                category    = "Missing Docstring",
                description = f"Public function `{name}` has no docstring.",
            ).model_dump())

        args   = node.args
        n_args = (
            len(args.args) + len(args.posonlyargs) + len(args.kwonlyargs)
            + (1 if args.vararg else 0) + (1 if args.kwarg else 0)
        )
        if n_args > MAX_PARAMETERS:
            issues.append(QualityIssue(
                filename    = filename,
                line        = start,
                severity    = Severity.MEDIUM,
                category    = "Too Many Parameters",
                description = (
                    f"`{name}` has {n_args} parameters — "
                    f"consider a config object (aim for ≤ {MAX_PARAMETERS})."
                ),
                metric = f"params={n_args}",
            ).model_dump())

        visitor = _NestingVisitor()
        visitor.visit(node)
        if visitor.max_depth > MAX_NESTING_DEPTH:
            issues.append(QualityIssue(
                filename    = filename,
                line        = visitor.worst_line,
                severity    = Severity.MEDIUM,
                category    = "Deep Nesting",
                description = (
                    f"`{name}` has nesting depth {visitor.max_depth} — "
                    f"consider early returns (aim for ≤ {MAX_NESTING_DEPTH})."
                ),
                metric = f"nesting_depth={visitor.max_depth}",
            ).model_dump())

    return issues


def analyse_quality(filename: str, source: str) -> list[dict[str, Any]]:
    """Runs all quality checks. Returns list of QualityIssue-compatible dicts."""
    issues: list[dict] = []
    issues.extend(_run_radon_cc(source, filename))
    issues.extend(_run_radon_mi(source, filename))
    issues.extend(_ast_checks(source, filename))
    logger.debug("quality_analyzer found %d issue(s) in %s", len(issues), filename)
    return issues