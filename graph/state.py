
from __future__ import annotations

import operator
import uuid
from enum import Enum
from typing import Annotated, Any, Optional
from typing_extensions import TypedDict

from pydantic import BaseModel, Field


# ─── Enums ────────────────────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class Verdict(str, Enum):
    APPROVE          = "approve"
    REQUEST_CHANGES  = "request_changes"
    COMMENT          = "comment"


class Language(str, Enum):
    PYTHON     = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JSX        = "jsx"
    TSX        = "tsx"
    UNKNOWN    = "unknown"


# ─── File models ──────────────────────────────────────────────────────────────

class PRFile(BaseModel):
    filename:  str
    language:  Language = Language.UNKNOWN
    content:   str
    patch:     str = ""
    additions: int = 0
    deletions: int = 0


class ParsedFile(BaseModel):
    """PRFile enriched with AST data by the Parser agent."""
    filename:      str
    language:      Language
    content:       str
    patch:         str
    additions:     int
    deletions:     int
    functions:     list[dict[str, Any]] = Field(default_factory=list)
    ast_available: bool = False


# ─── Issue models ─────────────────────────────────────────────────────────────

class SecurityIssue(BaseModel):
    id:             str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    filename:       str
    line:           int
    severity:       Severity
    category:       str
    cwe_id:         Optional[str] = None
    owasp:          Optional[str] = None
    description:    str
    source:         str
    code_snippet:   Optional[str] = None
    false_positive: bool = False
    fp_reason:      Optional[str] = None


class QualityIssue(BaseModel):
    id:          str = Field(default_factory=lambda: str(uuid.uuid4())[:8])
    filename:    str
    line:        int
    severity:    Severity
    category:    str
    description: str
    metric:      Optional[str] = None


# ─── Fix & Test models ────────────────────────────────────────────────────────

class CodeFix(BaseModel):
    issue_id:    str
    filename:    str
    description: str
    original:    str
    fixed:       str
    explanation: str
    validated:   bool = False


class GeneratedTest(BaseModel):
    filename:  str
    framework: str
    content:   str
    covers:    list[str]


# ─── Report models ────────────────────────────────────────────────────────────

class SeverityBreakdown(BaseModel):
    critical: int = 0
    high:     int = 0
    medium:   int = 0
    low:      int = 0
    info:     int = 0


class ReviewReport(BaseModel):
    review_id:          str
    verdict:            Verdict
    summary:            str
    security_issues:    list[SecurityIssue]
    quality_issues:     list[QualityIssue]
    fixes:              list[CodeFix]
    tests:              list[GeneratedTest]
    severity_breakdown: SeverityBreakdown
    files_reviewed:     int
    github_comment_url: Optional[str] = None
    pdf_path:           Optional[str] = None


# ─── LangGraph shared state ───────────────────────────────────────────────────
#
# Rule: any key that TWO parallel nodes both write must be declared as
#   Annotated[list[X], operator.add]
# so LangGraph concatenates the two lists instead of crashing.
#
# In our pipeline, security_agent and quality_agent run in parallel.
# Both write to `events`. security_agent writes `security_issues`,
# quality_agent writes `quality_issues`. Those are separate keys so they
# are fine as plain lists — but events is shared, so it needs Annotated.

class ReviewState(TypedDict):
    # Input
    review_id:   str
    pr_files:    list[dict]
    pr_url:      Optional[str]

    # Parser output (written by parser node only — plain list is fine)
    parsed_files: list[dict]

    # Parallel agent outputs
    # security_issues written only by security node → plain list fine
    security_issues: list[dict]
    # quality_issues written only by quality node → plain list fine
    quality_issues:  list[dict]

    # Fix & test outputs (sequential nodes — plain lists fine)
    fixes: list[dict]
    tests: list[dict]

    # Final output
    report: Optional[dict]
    error:  Optional[str]

    # Events — written by EVERY node including parallel ones → must use
    # Annotated so LangGraph merges instead of overwriting/crashing
    events: Annotated[list[dict], operator.add]