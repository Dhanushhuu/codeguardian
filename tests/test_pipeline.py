from __future__ import annotations
import io
import os
import sys

# Windows UTF-8 console fix
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import argparse
import json
import logging
import time
from pathlib import Path

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger(__name__)

# Load sample file using absolute path so it works from any cwd
SAMPLE_PATH     = Path(PROJECT_ROOT) / "data" / "samples" / "vulnerable_example.py"
VULNERABLE_CODE = SAMPLE_PATH.read_text(encoding="utf-8")

SAMPLE_FILES = [
    {
        "filename":  "app.py",
        "language":  "python",
        "content":   VULNERABLE_CODE,
        "patch":     "",
        "additions": 80,
        "deletions": 0,
    }
]

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"


def ok(msg):
    logger.info("%s+ PASS%s  %s", GREEN, RESET, msg)


def fail(msg, err=None):
    logger.error("%sx FAIL%s  %s", RED, RESET, msg)
    if err:
        logger.error("       %s", err)


def section(title):
    print(f"\n{BOLD}{CYAN}{'-'*60}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'-'*60}{RESET}\n")


def test_pr_parser():
    section("Tool: pr_parser")
    from tools.pr_parser import parse_pr_files, detect_language, extract_python_functions
    from graph.state import Language

    assert detect_language("app.py") == Language.PYTHON,    "Python detection failed"
    assert detect_language("app.js") == Language.JAVASCRIPT, "JS detection failed"
    assert detect_language("app.ts") == Language.TYPESCRIPT, "TS detection failed"
    assert detect_language("app.rb") == Language.UNKNOWN,    "Unknown should be UNKNOWN"
    ok("Language detection")

    # Test AST extraction directly first
    funcs = extract_python_functions(VULNERABLE_CODE)
    logger.info("  extract_python_functions: %d function(s)", len(funcs))
    for f in funcs:
        logger.info("    - %s (line %d)", f["name"], f["start_line"])

    assert len(funcs) > 0, (
        "extract_python_functions returned 0 functions.\n"
        "  First 300 chars of code: " + repr(VULNERABLE_CODE[:300])
    )
    ok(f"AST extracted {len(funcs)} function(s)")

    parsed = parse_pr_files(SAMPLE_FILES)
    assert len(parsed) == 1, f"Expected 1 parsed file, got {len(parsed)}"
    pf = parsed[0]
    assert pf.language == Language.PYTHON
    assert len(pf.functions) > 0, "parse_pr_files returned 0 functions"
    ok(f"Parsed 1 file -- {len(pf.functions)} function(s) extracted")

    func_names = [f["name"] for f in pf.functions]
    logger.info("  Functions: %s", func_names)
    for expected in ["get_user_by_id", "ping_host", "load_user_session"]:
        assert expected in func_names, f"Expected '{expected}' not found in {func_names}"
    ok("All expected functions found")


def test_bandit():
    section("Tool: bandit_scanner")
    from tools.bandit_scanner import run_bandit

    assert "pickle.loads" in VULNERABLE_CODE, "Sample missing pickle.loads"
    assert "shell=True"   in VULNERABLE_CODE, "Sample missing shell=True"
    assert "eval("        in VULNERABLE_CODE, "Sample missing eval()"

    issues = run_bandit("app.py", VULNERABLE_CODE)
    logger.info("  Bandit found %d issue(s)", len(issues))
    for i in issues:
        logger.info("    [%s] %s (line %d)", i["severity"], i["category"], i["line"])

    assert len(issues) > 0, (
        "Bandit found 0 issues.\n"
        "  Verify bandit is installed: pip install bandit\n"
        "  Test manually: bandit -f json data/samples/vulnerable_example.py"
    )
    ok(f"Bandit found {len(issues)} issue(s)")
    assert "bandit" in {i["source"] for i in issues}
    ok("Issues attributed to bandit")


def test_semgrep():
    section("Tool: semgrep_scanner")
    from tools.semgrep_scanner import run_semgrep
    from graph.state import Language

    issues = run_semgrep("app.py", VULNERABLE_CODE, Language.PYTHON)
    logger.info("  Semgrep found %d issue(s)", len(issues))
    if issues:
        ok(f"Semgrep found {len(issues)} issue(s)")
    else:
        logger.warning("%s~ SKIP%s  Semgrep not installed or no rules matched", YELLOW, RESET)


def test_codebert():
    section("Tool: codebert_classifier")
    from tools.pr_parser import extract_python_functions
    from tools.codebert_classifier import classify_functions, _heuristic_score

    # Test heuristic scorer directly on the full code
    score, categories = _heuristic_score(VULNERABLE_CODE)
    logger.info("  Heuristic score: %.2f  categories: %s", score, categories)
    assert score >= 0.5, f"Heuristic score too low ({score}) -- check _VULN_PATTERNS"
    ok(f"Heuristic scorer working (score={score:.2f})")

    funcs = extract_python_functions(VULNERABLE_CODE)
    assert len(funcs) > 0, "No functions extracted -- fix pr_parser first"
    logger.info("  Classifying %d function(s)...", len(funcs))

    issues = classify_functions("app.py", funcs)
    logger.info("  CodeBERT found %d issue(s)", len(issues))
    for i in issues:
        logger.info("    [%s] %s (line %d)", i["severity"], i["category"], i["line"])

    assert len(issues) > 0, (
        f"CodeBERT heuristics found 0 issues across {len(funcs)} functions.\n"
        f"  Functions: {[f['name'] for f in funcs]}"
    )
    ok(f"CodeBERT found {len(issues)} issue(s)")


def test_quality_analyzer():
    section("Tool: quality_analyzer")
    from tools.quality_analyzer import analyse_quality, _ast_checks

    ast_issues = _ast_checks(VULNERABLE_CODE, "app.py")
    logger.info("  AST checks: %d issue(s)", len(ast_issues))
    for i in ast_issues:
        logger.info("    [%s] %s (line %d)", i["severity"], i["category"], i["line"])

    issues = analyse_quality("app.py", VULNERABLE_CODE)
    logger.info("  Total quality issues: %d", len(issues))

    if issues:
        ok(f"quality_analyzer found {len(issues)} issue(s)")
    else:
        logger.warning(
            "%s~ SKIP%s  0 quality issues -- run: pip install radon",
            YELLOW, RESET,
        )


def test_full_pipeline():
    section("Full Pipeline Test")
    if not os.getenv("GROQ_API_KEY"):
        logger.warning("%s~ SKIP%s  GROQ_API_KEY not set", YELLOW, RESET)
        return

    from graph.pipeline import run_review

    start   = time.time()
    state   = run_review(SAMPLE_FILES)
    elapsed = time.time() - start
    ok(f"Pipeline completed in {elapsed:.1f}s")

    assert "report" in state and state["report"], "No report in state"
    report = state["report"]

    logger.info("  Verdict:  %s", report.get("verdict"))
    logger.info("  Summary:  %s", report.get("summary"))
    for sev in ("critical", "high", "medium", "low"):
        logger.info("    %-10s %d", sev, report.get("severity_breakdown", {}).get(sev, 0))

    assert report["verdict"] in ("approve", "comment", "request_changes")
    ok("Verdict is valid")

    real = [i for i in state.get("security_issues", []) if not i.get("false_positive")]
    assert len(real) >= 3, f"Expected >= 3 real issues, got {len(real)}"
    ok(f"Found {len(real)} real security issues")
    print(json.dumps(report, indent=2, default=str))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tools-only", action="store_true")
    args = parser.parse_args()

    print(f"\n{BOLD}CodeGuardian -- Test Suite{RESET}")
    print(f"Project root : {PROJECT_ROOT}")
    print(f"Sample file  : {SAMPLE_PATH}")
    print(f"File size    : {len(VULNERABLE_CODE)} chars, {len(VULNERABLE_CODE.splitlines())} lines")

    # Pre-check: count functions in sample file
    import ast as _ast
    try:
        _tree = _ast.parse(VULNERABLE_CODE)
        _fns  = [n for n in _ast.walk(_tree) if isinstance(n, (_ast.FunctionDef, _ast.AsyncFunctionDef))]
        print(f"AST functions: {len(_fns)} ({[n.name for n in _fns]})")
    except Exception as e:
        print(f"AST pre-check failed: {e}")

    passed, failed = 0, 0

    for name, fn in [
        ("pr_parser",        test_pr_parser),
        ("bandit_scanner",   test_bandit),
        ("semgrep_scanner",  test_semgrep),
        ("codebert",         test_codebert),
        ("quality_analyzer", test_quality_analyzer),
    ]:
        try:
            fn()
            passed += 1
        except (AssertionError, Exception) as exc:
            fail(name, exc)
            failed += 1

    if not args.tools_only:
        try:
            test_full_pipeline()
            passed += 1
        except Exception as exc:
            fail("full_pipeline", exc)
            failed += 1

    print(f"\n{'─'*60}")
    print(f"{BOLD}Results: {GREEN}{passed} passed{RESET}, {RED}{failed} failed{RESET}")
    print(f"{'─'*60}\n")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()