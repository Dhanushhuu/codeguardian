

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from graph.state import Severity, SeverityBreakdown, Verdict

logger = logging.getLogger(__name__)


# ─── Verdict logic ────────────────────────────────────────────────────────────

def _compute_verdict(security_issues: list[dict]) -> Verdict:
    real = [i for i in security_issues if not i.get("false_positive")]
    sevs = {i.get("severity") for i in real}
    if Severity.CRITICAL.value in sevs:
        return Verdict.REQUEST_CHANGES
    if Severity.HIGH.value in sevs:
        return Verdict.REQUEST_CHANGES
    if Severity.MEDIUM.value in sevs:
        return Verdict.COMMENT
    return Verdict.APPROVE


def _compute_breakdown(security_issues: list[dict]) -> dict:
    b = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for issue in security_issues:
        if issue.get("false_positive"):
            continue
        sev = issue.get("severity", "info")
        if sev in b:
            b[sev] += 1
    return b


# ─── GitHub comment ───────────────────────────────────────────────────────────

def _build_github_comment(
    verdict: Verdict,
    summary: str,
    security_issues: list[dict],
    fixes: list[dict],
    tests: list[dict],
    files_reviewed: int,
    review_id: str,
    breakdown: dict,
) -> str:
    verdict_icon = {
        Verdict.APPROVE:         "OK",
        Verdict.COMMENT:         "WARNING",
        Verdict.REQUEST_CHANGES: "BLOCKED",
    }[verdict]

    lines = [
        f"## [{verdict_icon}] CodeGuardian Review -- {verdict.value.replace('_', ' ').title()}",
        "",
        f"> {summary}",
        "",
        "### Security Issues",
        "| Severity | Count |",
        "|----------|-------|",
        f"| Critical | {breakdown.get('critical', 0)} |",
        f"| High     | {breakdown.get('high', 0)} |",
        f"| Medium   | {breakdown.get('medium', 0)} |",
        f"| Low      | {breakdown.get('low', 0)} |",
        "",
    ]

    real_issues = [i for i in security_issues if not i.get("false_positive")]
    if real_issues:
        lines.append("### Findings")
        by_file: dict[str, list[dict]] = {}
        for i in real_issues:
            by_file.setdefault(i.get("filename", "unknown"), []).append(i)

        for filename, issues in by_file.items():
            lines.append(f"\n**{filename}** -- {len(issues)} issue(s)\n")
            for issue in issues:
                sev   = issue.get("severity", "info").upper()
                cat   = issue.get("category", "Unknown")
                line  = issue.get("line", 0)
                desc  = issue.get("description", "")
                lines.append(f"- [{sev}] {cat} (line {line}): {desc}")
                if issue.get("cwe_id"):
                    lines.append(f"  - {issue['cwe_id']}")
            lines.append("")

    if fixes:
        lines.append(f"\n### Fixes Generated -- {len(fixes)} patch(es)")
        for fix in fixes:
            v = "syntax validated" if fix.get("validated") else "needs review"
            lines.append(f"- {fix.get('filename', '')}: {fix.get('description', '')} ({v})")

    if tests:
        lines.append(f"\n### Tests Generated -- {len(tests)} file(s)")
        for test in tests:
            covers = ", ".join(test.get("covers", []))
            lines.append(f"- {test.get('filename', '')} ({test.get('framework', '')}) covers: {covers}")

    lines.append(
        f"\n---\nReviewed {files_reviewed} file(s) -- "
        f"CodeGuardian v1.0 -- Review ID: {review_id}"
    )
    return "\n".join(lines)


def _post_github_comment(pr_url: str, body: str) -> str | None:
    try:
        from github import Github
        token = os.getenv("GITHUB_TOKEN")
        if not token or not pr_url:
            return None
        parts     = pr_url.rstrip("/").split("/")
        pr_number = int(parts[-1])
        repo_name = f"{parts[-4]}/{parts[-3]}"
        gh      = Github(token)
        repo    = gh.get_repo(repo_name)
        pr      = repo.get_pull(pr_number)
        comment = pr.create_issue_comment(body)
        return comment.html_url
    except Exception as exc:
        logger.warning("GitHub comment failed: %s", exc)
        return None


# ─── PDF report ───────────────────────────────────────────────────────────────

def _generate_pdf(
    review_id: str,
    verdict: str,
    summary: str,
    breakdown: dict,
    security_issues: list[dict],
) -> str | None:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles    import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units     import inch
        from reportlab.platypus      import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib            import colors

        output_dir = Path(os.getenv("REPORT_OUTPUT_DIR", "data/reports"))
        output_dir.mkdir(parents=True, exist_ok=True)
        pdf_path = output_dir / f"codeguardian_{review_id[:8]}.pdf"

        doc    = SimpleDocTemplate(str(pdf_path), pagesize=letter)
        styles = getSampleStyleSheet()
        story  = []

        title_style = ParagraphStyle(
            "title", parent=styles["Heading1"], fontSize=18, spaceAfter=12
        )
        story.append(Paragraph("CodeGuardian Security Review", title_style))
        story.append(Paragraph(f"Review ID: {review_id}", styles["Normal"]))
        story.append(Paragraph(f"Verdict: {verdict.upper()}", styles["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Summary", styles["Heading2"]))
        story.append(Paragraph(summary, styles["Normal"]))
        story.append(Spacer(1, 0.2 * inch))

        story.append(Paragraph("Severity Breakdown", styles["Heading2"]))
        table_data = [
            ["Severity", "Count"],
            ["Critical", str(breakdown.get("critical", 0))],
            ["High",     str(breakdown.get("high", 0))],
            ["Medium",   str(breakdown.get("medium", 0))],
            ["Low",      str(breakdown.get("low", 0))],
        ]
        t = Table(table_data, colWidths=[2 * inch, 1 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2C2C2A")),
            ("TEXTCOLOR",  (0, 0), (-1, 0), colors.white),
            ("GRID",       (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE",   (0, 0), (-1, -1), 10),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.2 * inch))

        real_issues = [i for i in security_issues if not i.get("false_positive")]
        if real_issues:
            story.append(Paragraph("Security Issues", styles["Heading2"]))
            for issue in real_issues[:20]:
                sev  = issue.get("severity", "info").upper()
                cat  = issue.get("category", "Unknown")
                fn   = issue.get("filename", "")
                ln   = issue.get("line", 0)
                desc = issue.get("description", "")
                story.append(Paragraph(
                    f"[{sev}] {cat} -- {fn}:{ln}",
                    styles["Heading3"],
                ))
                story.append(Paragraph(desc, styles["Normal"]))
                story.append(Spacer(1, 0.1 * inch))

        doc.build(story)
        logger.info("PDF report saved to %s", pdf_path)
        return str(pdf_path)

    except ImportError:
        logger.warning("reportlab not installed -- skipping PDF generation")
        return None
    except Exception as exc:
        logger.error("PDF generation failed: %s", exc)
        return None


# ─── Main agent ───────────────────────────────────────────────────────────────

def run(state: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph node function.
    Input:  full state (all keys are plain dicts/lists — no Pydantic objects)
    Output: {"report": dict}
    """
    security_issues = state.get("security_issues", []) or []
    quality_issues  = state.get("quality_issues",  []) or []
    fixes           = state.get("fixes",           []) or []
    tests           = state.get("tests",           []) or []
    parsed_files    = state.get("parsed_files",    []) or []
    review_id       = state.get("review_id",       "unknown")
    pr_url          = state.get("pr_url",          "") or ""

    # Ensure all items are plain dicts (defensive — should already be)
    def to_dict(item: Any) -> dict:
        if isinstance(item, dict):
            return item
        if hasattr(item, "model_dump"):
            return item.model_dump()
        return dict(item)

    security_issues = [to_dict(i) for i in security_issues]
    quality_issues  = [to_dict(i) for i in quality_issues]
    fixes           = [to_dict(i) for i in fixes]
    tests           = [to_dict(i) for i in tests]

    verdict   = _compute_verdict(security_issues)
    breakdown = _compute_breakdown(security_issues)

    real_count = sum(1 for i in security_issues if not i.get("false_positive"))
    fp_count   = sum(1 for i in security_issues if i.get("false_positive"))

    summary = (
        f"Found {real_count} security issue(s) and {len(quality_issues)} "
        f"quality issue(s) across {len(parsed_files)} file(s). "
        f"{fp_count} false positive(s) dismissed. "
        f"{len(fixes)} fix(es) and {len(tests)} test file(s) generated."
    )

    # Build comment
    comment_body = _build_github_comment(
        verdict         = verdict,
        summary         = summary,
        security_issues = security_issues,
        fixes           = fixes,
        tests           = tests,
        files_reviewed  = len(parsed_files),
        review_id       = review_id,
        breakdown       = breakdown,
    )
    comment_url = _post_github_comment(pr_url, comment_body) if pr_url else None

    # Generate PDF
    pdf_path = _generate_pdf(
        review_id       = review_id,
        verdict         = verdict.value,
        summary         = summary,
        breakdown       = breakdown,
        security_issues = security_issues,
    )

    # Build final report as a plain dict — NOT a Pydantic object
    report = {
        "review_id":          review_id,
        "verdict":            verdict.value,
        "summary":            summary,
        "security_issues":    security_issues,
        "quality_issues":     quality_issues,
        "fixes":              fixes,
        "tests":              tests,
        "severity_breakdown": breakdown,
        "files_reviewed":     len(parsed_files),
        "github_comment_url": comment_url,
        "pdf_path":           pdf_path,
    }

    logger.info(
        "reviewer_agent: verdict=%s security=%d quality=%d fixes=%d tests=%d",
        verdict.value, real_count, len(quality_issues), len(fixes), len(tests),
    )

    return {"report": report}