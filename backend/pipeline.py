"""Sequential analysis pipeline: ledger -> summary -> model -> save -> merge."""
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import store
from chunking import Chunk, TokenBudget, chunk_lines, iter_lines
from ledger import Ledger, Thresholds, detect_format, sample_file
from llm import (
    FINDINGS_SCHEMA, SYSTEM_PROMPT, LLMClient, ParseError, build_user_prompt,
    clean_finding, parse_findings,
)
from merge import SEV_RANK, merge_findings
from summary import build_summary
from tokenizer import Tokenizer, get_tokenizer


@dataclass
class PipelineConfig:
    budget: TokenBudget = field(default_factory=TokenBudget.from_env)
    thresholds: Thresholds = field(default_factory=Thresholds.from_env)
    summary_cap_tokens: int = field(default_factory=lambda: int(os.getenv("SUMMARY_CAP_TOKENS", "230")))
    max_retries: int = field(default_factory=lambda: int(os.getenv("CHUNK_MAX_RETRIES", "2")))
    timeout_s: float = field(default_factory=lambda: float(os.getenv("OLLAMA_TIMEOUT_S", "120")))
    backoff_s: float = 1.0
    sleep: Callable[[float], None] = time.sleep  # injectable so tests do not wait


def analyze_chunk(chunk: Chunk, summary: str, client: LLMClient, cfg: PipelineConfig):
    """Return (status, attempts, error, findings). Never raises for model problems."""
    user = build_user_prompt(chunk, summary)
    last_err = ""
    attempts = 0
    for attempt in range(cfg.max_retries + 1):
        attempts = attempt + 1
        try:
            raw = client.generate(SYSTEM_PROMPT, user, FINDINGS_SCHEMA, cfg.timeout_s)
            items, partial = parse_findings(raw)
            findings = [
                f for f in (clean_finding(i, chunk.start_line, chunk.end_line) for i in items) if f
            ]
            note = "partial output salvaged" if partial else None
            return "done", attempts, note, findings
        except (TimeoutError, ConnectionError, ParseError, RuntimeError, OSError, KeyError, ValueError) as e:
            last_err = f"{type(e).__name__}: {e}"[:300]
            if attempt < cfg.max_retries:
                cfg.sleep(cfg.backoff_s * (attempt + 1))
    return "failed", attempts, last_err, []


def run_job(
    job_id: str,
    path: str | Path,
    client: LLMClient,
    cfg: PipelineConfig | None = None,
    tok: Tokenizer | None = None,
) -> None:
    cfg = cfg or PipelineConfig()
    tok = tok or get_tokenizer()
    try:
        store.update_job(job_id, status="running")
        fmt = detect_format(sample_file(str(path)))
        store.update_job(job_id, log_format=fmt)
        ledger = Ledger(fmt, cfg.thresholds)
        done = failed = 0
        with open(path, "rb") as f:
            for chunk in chunk_lines(iter_lines(f), tok, cfg.budget.chunk_tokens):
                summary = build_summary(ledger, tok, cfg.summary_cap_tokens)  # earlier chunks only
                ledger.scan(chunk.lines)
                status, attempts, err, findings = analyze_chunk(chunk, summary, client, cfg)
                # Persist immediately: finished chunks survive a later failure.
                store.save_chunk(
                    job_id, chunk.index, chunk.start_line, chunk.end_line, status, attempts, err, findings
                )
                done += 1
                failed += status == "failed"
                store.update_job(job_id, bytes_done=chunk.end_byte, chunks_done=done, chunks_failed=failed)
        report = build_report(job_id, ledger)
        store.update_job(
            job_id,
            status="completed_with_errors" if failed else "completed",
            report_json=json.dumps(report),
            finished_at=time.time(),
        )
    except Exception as e:  # unexpected (I/O, bug): mark the job, keep chunk results
        store.update_job(job_id, status="failed", error=f"{type(e).__name__}: {e}"[:300], finished_at=time.time())


def build_report(job_id: str, ledger: Ledger) -> dict:
    chunks = store.load_chunks(job_id)
    model_findings = [f for c in chunks for f in c["findings"]]
    merged = merge_findings(ledger.to_findings() + model_findings, ledger)
    by_sev = {s: 0 for s in SEV_RANK}
    for f in merged:
        by_sev[f["severity"]] += 1
    return {
        "job_id": job_id,
        "summary": {
            "total_findings": len(merged),
            "by_severity": by_sev,
            "chunks_total": len(chunks),
            "chunks_failed": sum(c["status"] == "failed" for c in chunks),
            "complete": all(c["status"] == "done" for c in chunks),
        },
        "findings": merged,
        "failed_chunks": [
            {"index": c["idx"], "start_line": c["start_line"], "end_line": c["end_line"],
             "attempts": c["attempts"], "error": c["error"]}
            for c in chunks if c["status"] == "failed"
        ],
        "ledger": ledger.stats(),
        "note": (
            "Ledger findings are deterministic; model findings are best-effort. "
            "Failed chunks were analysed by the ledger only."
        ),
    }
