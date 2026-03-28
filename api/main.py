

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import uuid
from pathlib import Path
from typing import Any, AsyncGenerator

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

load_dotenv()

logging.basicConfig(
    level=getattr(logging, os.getenv("LOG_LEVEL", "INFO")),
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="CodeGuardian",
    description="Autonomous Code Security & Quality Review Agent",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── In-memory job store (replace with Redis for production) ──────────────────

_jobs: dict[str, dict[str, Any]] = {}   # review_id → state dict


# ─── Request / response models ────────────────────────────────────────────────

class PRFileRequest(BaseModel):
    filename:  str
    language:  str = "python"
    content:   str
    patch:     str = ""
    additions: int = 0
    deletions: int = 0


class ReviewRequest(BaseModel):
    files:  list[PRFileRequest]
    pr_url: str = ""   # optional — if provided, posts GitHub comment


class ReviewResponse(BaseModel):
    review_id: str
    status:    str = "queued"


# ─── Background review runner ─────────────────────────────────────────────────

def _run_review_sync(review_id: str, files: list[dict], pr_url: str = "") -> None:
    """Runs the full pipeline synchronously in a background thread."""
    from graph.pipeline import run_review

    _jobs[review_id]["status"] = "running"
    try:
        state = run_review(files, pr_url=pr_url)
        _jobs[review_id].update({
            "status": "complete",
            "state":  state,
        })
        logger.info("Review %s complete", review_id)
    except Exception as exc:
        logger.exception("Review %s failed: %s", review_id, exc)
        _jobs[review_id].update({
            "status": "failed",
            "error":  str(exc),
        })


async def _run_review_async(review_id: str, files: list[dict], pr_url: str = "") -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _run_review_sync, review_id, files, pr_url)


# ─── Webhook signature verification ──────────────────────────────────────────

def _verify_github_signature(payload: bytes, signature_header: str | None) -> bool:
    secret = os.getenv("GITHUB_WEBHOOK_SECRET", "")
    if not secret:
        logger.warning("GITHUB_WEBHOOK_SECRET not set — skipping signature verification")
        return True
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        secret.encode(), payload, digestmod=hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.get("/", tags=["Health"])
async def root():
    return {"service": "CodeGuardian", "status": "ok", "version": "1.0.0"}


@app.post("/webhook/github", tags=["Webhook"])
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Receives GitHub PR webhook events.
    Triggers a review on PR opened / synchronize / reopened.
    """
    payload_bytes = await request.body()
    sig           = request.headers.get("X-Hub-Signature-256")

    if not _verify_github_signature(payload_bytes, sig):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    event = request.headers.get("X-GitHub-Event", "")
    if event != "pull_request":
        return {"message": f"Ignored event: {event}"}

    payload = json.loads(payload_bytes)
    action  = payload.get("action", "")

    if action not in ("opened", "synchronize", "reopened"):
        return {"message": f"Ignored PR action: {action}"}

    pr      = payload.get("pull_request", {})
    pr_url  = pr.get("html_url", "")

    # Fetch changed files from the PR diff
    files_raw: list[dict] = []
    for f in payload.get("pull_request", {}).get("files", []):
        files_raw.append({
            "filename":  f.get("filename", ""),
            "language":  "python",     # parser will detect properly
            "content":   f.get("contents_url", ""),  # fetched below
            "patch":     f.get("patch", ""),
            "additions": f.get("additions", 0),
            "deletions": f.get("deletions", 0),
        })

    if not files_raw:
        # GitHub webhook doesn't include file content — fetch via API
        files_raw = await _fetch_pr_files(pr, payload.get("repository", {}))

    review_id = str(uuid.uuid4())
    _jobs[review_id] = {"status": "queued", "pr_url": pr_url}

    background_tasks.add_task(_run_review_async, review_id, files_raw, pr_url)
    logger.info("Queued review %s for PR %s", review_id, pr_url)

    return ReviewResponse(review_id=review_id, status="queued")


async def _fetch_pr_files(pr: dict, repo: dict) -> list[dict]:
    """Fetches actual file contents from GitHub API for a PR."""
    import httpx

    token   = os.getenv("GITHUB_TOKEN", "")
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github.v3+json"}

    repo_full  = repo.get("full_name", "")
    pr_number  = pr.get("number", 0)
    files_url  = f"https://api.github.com/repos/{repo_full}/pulls/{pr_number}/files"

    files: list[dict] = []
    try:
        async with httpx.AsyncClient() as client:
            resp       = await client.get(files_url, headers=headers, timeout=15)
            resp.raise_for_status()
            pr_files   = resp.json()

            for f in pr_files:
                raw_url = f.get("raw_url", "")
                content = ""
                if raw_url:
                    cr = await client.get(raw_url, headers=headers, timeout=15)
                    if cr.status_code == 200:
                        content = cr.text

                files.append({
                    "filename":  f.get("filename", ""),
                    "language":  "python",
                    "content":   content,
                    "patch":     f.get("patch", ""),
                    "additions": f.get("additions", 0),
                    "deletions": f.get("deletions", 0),
                })
    except Exception as exc:
        logger.error("Failed to fetch PR files: %s", exc)

    return files


@app.post("/review", response_model=ReviewResponse, tags=["Review"])
async def manual_review(body: ReviewRequest, background_tasks: BackgroundTasks):
    """
    Manual review trigger — useful for testing without a GitHub webhook.
    Accepts file content directly in the request body.
    """
    review_id = str(uuid.uuid4())
    files     = [f.model_dump() for f in body.files]
    _jobs[review_id] = {"status": "queued", "pr_url": body.pr_url}

    background_tasks.add_task(_run_review_async, review_id, files, body.pr_url)
    logger.info("Manual review queued: %s", review_id)

    return ReviewResponse(review_id=review_id, status="queued")


@app.get("/status/{review_id}", tags=["Review"])
async def get_status(review_id: str):
    """Returns the current status, event log, and full state for a review job."""
    job = _jobs.get(review_id)
    if not job:
        raise HTTPException(status_code=404, detail="Review not found")

    state  = job.get("state") or {}
    events = state.get("events", []) if state else []

    return {
        "review_id": review_id,
        "status":    job["status"],
        "events":    events,
        "error":     job.get("error") or (state.get("error") if state else None),
        "state":     state,
    }


@app.get("/stream/{review_id}", tags=["Review"])
async def stream_events(review_id: str):
    """
    Server-Sent Events stream — pushes agent progress events in real time.
    Connect from the frontend with EventSource('/stream/{review_id}').
    """
    async def event_generator() -> AsyncGenerator[str, None]:
        last_sent = 0
        while True:
            job = _jobs.get(review_id)
            if not job:
                yield "data: {\"error\": \"not found\"}\n\n"
                break

            state  = job.get("state", {})
            events = state.get("events", [])

            # Push any new events
            for event in events[last_sent:]:
                data = json.dumps(event)
                yield f"data: {data}\n\n"
                last_sent += 1

            if job["status"] in ("complete", "failed"):
                yield f"data: {{\"done\": true, \"status\": \"{job['status']}\"}}\n\n"
                break

            await asyncio.sleep(0.5)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":               "no-cache",
            "X-Accel-Buffering":           "no",
            "Access-Control-Allow-Origin": "*",
        },
    )


@app.get("/results/{review_id}", tags=["Review"])
async def get_results(review_id: str):
    """Returns the full review results as JSON once the review is complete."""
    job = _jobs.get(review_id)
    if not job:
        raise HTTPException(status_code=404, detail="Review not found")
    if job["status"] != "complete":
        raise HTTPException(status_code=202, detail=f"Review status: {job['status']}")

    state  = job.get("state") or {}
    report = state.get("report") if state else None
    if not report:
        raise HTTPException(status_code=500, detail="Report is empty — check server logs for pipeline errors")
    return report


@app.get("/results/{review_id}/pdf", tags=["Review"])
async def download_pdf(review_id: str):
    """Downloads the PDF report for a completed review."""
    job = _jobs.get(review_id)
    if not job:
        raise HTTPException(status_code=404, detail="Review not found")
    if job["status"] != "complete":
        raise HTTPException(status_code=202, detail="Review not complete yet")

    report   = job.get("state", {}).get("report", {})
    pdf_path = report.get("pdf_path")

    if not pdf_path or not Path(pdf_path).exists():
        raise HTTPException(status_code=404, detail="PDF not found — reportlab may not be installed")

    return FileResponse(
        path         = pdf_path,
        media_type   = "application/pdf",
        filename     = f"codeguardian_{review_id[:8]}.pdf",
    )