"""Upload validation and ingestion endpoint."""
import os
from pathlib import PurePath

from fastapi import APIRouter, File, HTTPException, Query, UploadFile

from chunking import TokenBudget, chunk_lines, iter_lines
from tokenizer import get_tokenizer

router = APIRouter(prefix="/api")

ALLOWED_EXTENSIONS = {".log", ".txt"}
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_MB", "50")) * 1024 * 1024


def _validate(file: UploadFile) -> int:
    """Return file size in bytes or raise HTTPException."""
    ext = PurePath(file.filename or "").suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(415, f"Unsupported file type '{ext}'. Allowed: .log, .txt")
    f = file.file
    size = f.seek(0, os.SEEK_END)
    f.seek(0)
    if size == 0:
        raise HTTPException(400, "File is empty")
    if size > MAX_UPLOAD_BYTES:
        raise HTTPException(413, f"File exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB limit")
    if b"\x00" in f.read(8192):
        raise HTTPException(415, "File appears to be binary, not text")
    f.seek(0)
    return size


@router.post("/logs/upload")
def upload_log(
    file: UploadFile = File(...),
    include_text: bool = Query(False, description="Include rendered chunk text"),
):
    size = _validate(file)
    try:
        budget = TokenBudget.from_env()
        limit = budget.chunk_tokens
    except ValueError as e:
        raise HTTPException(500, str(e))

    tok = get_tokenizer()
    chunks, total_lines = [], 0
    # Streams straight from the upload's spooled file; the whole log is never
    # held in memory, only the current chunk.

    def counted():
        nonlocal total_lines
        for item in iter_lines(file.file):
            total_lines = item[0]
            yield item

    for c in chunk_lines(counted(), tok, limit):
        meta = {
            "index": c.index,
            "start_line": c.start_line,
            "end_line": c.end_line,
            "line_count": len(c.lines),
            "token_count": c.token_count,
            "progress_percent": round(100 * c.end_byte / size, 1),
        }
        if include_text:
            meta["text"] = c.render()
        chunks.append(meta)

    return {
        "filename": file.filename,
        "status": "complete",
        "size_bytes": size,
        "total_lines": total_lines,
        "total_chunks": len(chunks),
        "progress_percent": 100.0,
        "budget": {
            "context_window": budget.context_window,
            "system_prompt_reserve": budget.system_prompt,
            "context_reserve": budget.context,
            "output_reserve": budget.output,
            "chunk_tokens": limit,
        },
        "chunks": chunks,
    }

