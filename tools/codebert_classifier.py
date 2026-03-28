

from __future__ import annotations

import logging
import os
import re
from typing import Any

logger = logging.getLogger(__name__)

_VULN_PATTERNS: list[tuple[re.Pattern, str, float]] = [
    (re.compile(r"pickle\.loads?\("),             "Insecure Deserialization",   0.9),
    (re.compile(r"subprocess.*shell\s*=\s*True"), "Shell Injection",             0.9),
    (re.compile(r"exec\s*\("),                    "Arbitrary Code Execution",    0.85),
    (re.compile(r"eval\s*\("),                    "Arbitrary Code Execution",    0.85),
    (re.compile(r"os\.system\s*\("),              "OS Command Injection",        0.8),
    (re.compile(r"cursor\.execute\s*\([^,)]*%"),  "SQL Injection",               0.9),
    (re.compile(r"cursor\.execute\s*\([^,)]*\+"), "SQL Injection",               0.85),
    (re.compile(r'password\s*=\s*["\'][^"\']+'),  "Hardcoded Credential",        0.8),
    (re.compile(r'secret\s*=\s*["\'][^"\']+'),    "Hardcoded Credential",        0.8),
    (re.compile(r'api_key\s*=\s*["\'][^"\']+'),   "Hardcoded Credential",        0.8),
    (re.compile(r"hashlib\.md5\("),               "Weak Cryptography",           0.7),
    (re.compile(r"hashlib\.sha1\("),              "Weak Cryptography",           0.65),
    (re.compile(r"random\.random\(\)"),           "Insecure Randomness",         0.6),
    (re.compile(r"verify\s*=\s*False"),           "TLS Verification Disabled",   0.85),
    (re.compile(r"yaml\.load\("),                 "Unsafe YAML Deserialization", 0.8),
    (re.compile(r"__import__\s*\("),              "Dynamic Import",              0.65),
    (re.compile(r"deserialize\s*\("),             "Possible Deserialization",    0.55),
    (re.compile(r"input\s*\("),                   "Unvalidated Input",           0.4),
]

_VULN_THRESHOLD = 0.5

_model     = None
_tokenizer = None
_finetuned = False


def _heuristic_score(source: str) -> tuple[float, list[str]]:
    score: float      = 0.0
    categories: list[str] = []
    for pattern, category, contribution in _VULN_PATTERNS:
        if pattern.search(source):
            score = max(score, contribution)
            categories.append(category)
    return score, categories


def _load_model():
    global _model, _tokenizer, _finetuned

    if _model is not None:
        return _model, _tokenizer, _finetuned

    use_finetuned = os.getenv("USE_FINETUNED_MODEL", "false").lower() == "true"
    model_path    = os.getenv(
        "CODEBERT_MODEL_PATH", "data/models/codebert-vulnerability-detector"
    )

    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification

        if use_finetuned and os.path.isdir(model_path):
            logger.info("Loading fine-tuned CodeBERT from %s", model_path)
            _tokenizer = AutoTokenizer.from_pretrained(model_path)
            _model     = AutoModelForSequenceClassification.from_pretrained(model_path)
            _finetuned = True
        else:
            logger.info("Base mode — using heuristic classifier")
            _tokenizer = None
            _model     = None
            _finetuned = False

    except ImportError:
        logger.warning("transformers not installed — CodeBERT classifier disabled")
        _model = _tokenizer = None

    return _model, _tokenizer, _finetuned


def _append_heuristic_issues(
    issues: list[dict],
    filename: str,
    start_line: int,
    func_name: str,
    score: float,
    categories: list[str],
    source: str,
) -> None:
    from graph.state import SecurityIssue, Severity

    if score < _VULN_THRESHOLD:
        return

    for category in categories:
        issue = SecurityIssue(
            filename     = filename,
            line         = start_line,
            severity     = Severity.HIGH if score >= 0.8 else Severity.MEDIUM,
            category     = category,
            description  = (
                f"CodeBERT heuristic flagged `{func_name}` for `{category}` "
                f"(confidence {score:.0%})."
            ),
            source       = "codebert",
            code_snippet = source[:300],
        )
        issues.append(issue.model_dump())


def classify_functions(
    filename: str,
    functions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Classifies each function and returns SecurityIssue dicts for vulnerable ones.
    """
    from graph.state import SecurityIssue, Severity

    model, tokenizer, finetuned = _load_model()
    issues: list[dict] = []

    for func in functions:
        source     = func.get("source", "")
        start_line = func.get("start_line", 0)
        func_name  = func.get("name", "unknown")

        if not source.strip():
            continue

        if finetuned and model is not None:
            try:
                import torch
                inputs = tokenizer(
                    source, return_tensors="pt",
                    max_length=512, truncation=True, padding=True,
                )
                with torch.no_grad():
                    logits    = model(**inputs).logits
                    probs     = torch.softmax(logits, dim=-1)
                    vuln_prob = probs[0][1].item()

                if vuln_prob >= _VULN_THRESHOLD:
                    issue = SecurityIssue(
                        filename     = filename,
                        line         = start_line,
                        severity     = Severity.HIGH if vuln_prob > 0.8 else Severity.MEDIUM,
                        category     = "ML-Detected Vulnerability",
                        description  = (
                            f"CodeBERT (fine-tuned) flagged `{func_name}` as potentially "
                            f"vulnerable with {vuln_prob:.0%} confidence."
                        ),
                        source       = "codebert",
                        code_snippet = source[:300],
                    )
                    issues.append(issue.model_dump())

            except Exception as exc:
                logger.warning("Fine-tuned inference failed for %s: %s — using heuristics", func_name, exc)
                score, categories = _heuristic_score(source)
                _append_heuristic_issues(issues, filename, start_line, func_name, score, categories, source)
        else:
            score, categories = _heuristic_score(source)
            _append_heuristic_issues(issues, filename, start_line, func_name, score, categories, source)

    logger.debug("CodeBERT: %d function(s) in %s → %d issue(s)", len(functions), filename, len(issues))
    return issues