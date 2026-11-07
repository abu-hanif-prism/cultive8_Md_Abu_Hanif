"""Endpoints: start analysis, poll progress, fetch the final report."""
import json
import os
import shutil
import threading
import time
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


RESUMABLE = {"aborted", "failed", "completed_with_errors"}
_ACTIVE: set[str] = set()  # jobs with a live worker thread in this process


def _worker(job_id: str, path: str, client: LLMClient, resume: bool = False) -> None:
    try:
        with _RUN_LOCK:
            run_job(job_id, path, client, resume=resume)
    finally:
        _ACTIVE.discard(job_id)
        # The API owns its uploaded copies (run_job never deletes input). Keep the file
        # unless the job fully succeeded, so an aborted/failed job can be resumed.
        job = store.get_job(job_id)
        if os.getenv("KEEP_UPLOADS", "0") != "1" and job and job["status"] == "completed":
            Path(path).unlink(missing_ok=True)


def _upload_path(job_id: str) -> Path:
    return store.data_dir() / "uploads" / f"{job_id}.log"


def _is_resumable(j: dict) -> bool:
    # "running"/"queued" with no live worker means the server restarted mid-job.
    stale = j["status"] in ("queued", "running") and j["id"] not in _ACTIVE
    return (j["status"] in RESUMABLE or stale) and _upload_path(j["id"]).exists()


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
    _ACTIVE.add(job_id)
    threading.Thread(target=_worker, args=(job_id, str(path), client), daemon=True).start()
    return {"job_id": job_id, "status": "queued"}


@router.post("/{job_id}/resume", status_code=202)
def resume_analysis(job_id: str, client: LLMClient = Depends(get_llm_client)):
    """Continue an aborted/failed job: saved chunks are reused, failed ones retried."""
    j = _job_or_404(job_id)
    if j["status"] == "completed":
        raise HTTPException(409, "Job already completed")
    if j["id"] in _ACTIVE:
        raise HTTPException(409, "Job is already running")
    if not _upload_path(job_id).exists():
        raise HTTPException(410, "The uploaded file is no longer available; upload it again")
    if not _is_resumable(j):
        raise HTTPException(409, f"Job cannot be resumed (status: {j['status']})")
    _ACTIVE.add(job_id)
    threading.Thread(
        target=_worker, args=(job_id, str(_upload_path(job_id)), client, True), daemon=True
    ).start()
    return {"job_id": job_id, "status": "queued"}


def _job_or_404(job_id: str) -> dict:
    job = store.get_job(job_id)
    if not job:
        raise HTTPException(404, "Unknown job")
    return job


def _timing(j: dict) -> dict:
    start = j.get("started_at")
    end = j.get("finished_at") or time.time()
    elapsed = round(end - start, 1) if start else 0.0
    pct = j["bytes_done"] / (j["size_bytes"] or 1)
    live = not j["status"].startswith("completed") and j["status"] not in ("failed", "aborted")
    return {
        "elapsed_s": elapsed,
        "model_seconds": round(j.get("model_seconds") or 0, 1),
        "avg_chunk_s": round((j.get("model_seconds") or 0) / j["chunks_done"], 1) if j["chunks_done"] else None,
        "eta_s": round(elapsed * (1 - pct) / pct) if live and pct > 0.02 else None,
    }


@router.get("/{job_id}")
def progress(job_id: str):
    j = _job_or_404(job_id)
    size = j["size_bytes"] or 1
    finished = j["status"] in ("completed", "completed_with_errors", "failed", "aborted")
    return {
        "resumable": _is_resumable(j),
        "job_id": job_id,
        "filename": j["filename"],
        "status": j["status"],
        "log_format": j["log_format"],
        "progress_percent": 100.0 if j["status"].startswith("completed") else round(100 * j["bytes_done"] / size, 1),
        "chunks_done": j["chunks_done"],
        "chunks_failed": j["chunks_failed"],
        "finished": finished,
        "error": j["error"],
        **_timing(j),
    }


@router.get("/{job_id}/report")
def report(job_id: str):
    j = _job_or_404(job_id)
    if j["status"] in ("failed", "aborted"):
        raise HTTPException(
            500 if j["status"] == "failed" else 409, f"Analysis {j['status']}: {j['error']}"
        )
    if not j["report_json"]:
        raise HTTPException(409, f"Report not ready (status: {j['status']})")
    return {"status": j["status"], **json.loads(j["report_json"])}


system_router = APIRouter(prefix="/api")


@system_router.get("/system")
def system_info():
    """RAM use of this backend and of the local model (the brief limits both to 4 GB total)."""
    import httpx
    import psutil

    backend_mb = round(psutil.Process().memory_info().rss / 1e6)
    model = None
    try:
        host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
        models = httpx.get(f"{host}/api/ps", timeout=2).json().get("models", [])
        if models:
            m = models[0]
            model = {
                "name": m["name"], "size_mb": round(m["size"] / 1e6),
                "on_gpu_mb": round(m.get("size_vram", 0) / 1e6),
            }
    except Exception:
        pass  # Ollama not running or idle
    return {
        "backend_rss_mb": backend_mb,
        "model": model,
        "total_mb": backend_mb + (model["size_mb"] if model else 0),
        "limit_mb": 4096,
    }
