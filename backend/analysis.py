"""Endpoints: start analysis, poll progress, fetch the final report."""
import json
import os
import shutil
import threading
import uuid
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

import store
from ingest import _validate
from llm import LLMClient, OllamaClient
from pipeline import run_job

router = APIRouter(prefix="/api/analysis")

# One analysis at a time: the model is the bottleneck and RAM is limited.
_RUN_LOCK = threading.Lock()


def get_llm_client() -> LLMClient:
    """FastAPI dependency; tests override it with a fake client."""
    return OllamaClient.from_env()


def _worker(job_id: str, path: str, client: LLMClient) -> None:
    try:
        with _RUN_LOCK:
            run_job(job_id, path, client)
    finally:
        # Only the API owns (and may delete) its uploaded copies; run_job never deletes input.
        if os.getenv("KEEP_UPLOADS", "0") != "1":
            Path(path).unlink(missing_ok=True)


@router.post("", status_code=202)
def start_analysis(file: UploadFile = File(...), client: LLMClient = Depends(get_llm_client)):
    size = _validate(file)
    job_id = uuid.uuid4().hex
    upload_dir = store.data_dir() / "uploads"
    upload_dir.mkdir(exist_ok=True)
    path = upload_dir / f"{job_id}.log"
    with open(path, "wb") as out:
        shutil.copyfileobj(file.file, out, 1024 * 1024)  # streamed, never fully in memory
    store.create_job(job_id, file.filename or "upload", size)
    threading.Thread(target=_worker, args=(job_id, str(path), client), daemon=True).start()
    return {"job_id": job_id, "status": "queued"}


def _job_or_404(job_id: str) -> dict:
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(404, "Unknown job")
    return job


@router.get("/{job_id}")
def progress(job_id: str):
    j = _job_or_404(job_id)
    size = j["size_bytes"] or 1
    finished = j["status"] in ("completed", "completed_with_errors", "failed")
    return {
        "job_id": job_id,
        "filename": j["filename"],
        "status": j["status"],
        "log_format": j["log_format"],
        "progress_percent": 100.0 if j["status"].startswith("completed") else round(100 * j["bytes_done"] / size, 1),
        "chunks_done": j["chunks_done"],
        "chunks_failed": j["chunks_failed"],
        "finished": finished,
        "error": j["error"],
    }


@router.get("/{job_id}/report")
def report(job_id: str):
    j = _job_or_404(job_id)
    if j["status"] == "failed":
        raise HTTPException(500, f"Analysis failed: {j['error']}")
    if not j["report_json"]:
        raise HTTPException(409, f"Report not ready (status: {j['status']})")
    return {"status": j["status"], **json.loads(j["report_json"])}
