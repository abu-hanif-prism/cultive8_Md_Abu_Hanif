"""Sequential analysis pipeline: ledger -> summary -> model -> save -> merge."""
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import store
from chunking import Chunk, TokenBudget, chunk_lines, iter_lines
from ledger import Ledger, Thresholds, compact_line, detect_format, sample_file
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
    breaker_failures: int = field(default_factory=lambda: int(os.getenv("CIRCUIT_BREAKER_FAILURES", "3")))
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
            texts = dict(chunk.lines)
            findings = [
                f
                for f in (clean_finding(i, chunk.start_line, chunk.end_line, texts) for i in items)
                if f
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
    resume: bool = False,
) -> None:
    """Run (or resume) a job.

    Resume re-scans every chunk with the deterministic ledger (cheap, and needed
    to rebuild its state) but skips the model call for chunks already saved as
    "done". Failed chunks are retried. A circuit breaker aborts the job after
    `cfg.breaker_failures` consecutive failed chunks (e.g. Ollama is down).
    """
    cfg = cfg or PipelineConfig()
    tok = tok or get_tokenizer()
    try:
        prior = store.get_job(job_id) or {}
        model_seconds = float(prior.get("model_seconds") or 0) if resume else 0.0
        store.update_job(
            job_id, status="running", error=None, bytes_done=0, chunks_done=0, chunks_failed=0, report_json=None,
            started_at=(prior.get("started_at") if resume and prior.get("started_at") else time.time()),
            model_seconds=model_seconds,
        )
        fmt = detect_format(sample_file(str(path)))
        store.update_job(job_id, log_format=fmt)
        ledger = Ledger(fmt, cfg.thresholds)
        saved = {c["idx"]: c for c in store.load_chunks(job_id) if c["status"] == "done"} if resume else {}
        done = failed = consecutive = 0
        # The model sees a compact view of each line (JSON noise fields dropped); the ledger
        # scans the original. `raw` holds originals only for lines not yet scanned.
        raw: dict[int, str] = {}

        def prepared(fh):
            for n, text, off in iter_lines(fh):
                if fmt == "json_lines":
                    raw[n] = text
                    text = compact_line(text, fmt)
                yield n, text, off

        with open(path, "rb") as f:
            for chunk in chunk_lines(prepared(f), tok, cfg.budget.chunk_tokens):
                summary = build_summary(ledger, tok, cfg.summary_cap_tokens)  # earlier chunks only
                if fmt == "json_lines":
                    ledger.scan([(n, raw[n]) for n in dict.fromkeys(n for n, _ in chunk.lines)])
                    for n in [k for k in raw if k <= chunk.end_line]:
                        del raw[n]
                else:
                    ledger.scan(chunk.lines)
                prev = saved.get(chunk.index)
                if prev is not None:
                    if (prev["start_line"], prev["end_line"]) != (chunk.start_line, chunk.end_line):
                        raise ValueError(
                            f"Chunk {chunk.index} layout changed since the saved run "
                            "(token budget or tokenizer differs); cannot resume"
                        )
                    status = "done"  # reuse the saved findings, no model call
                else:
                    t_call = time.time()
                    status, attempts, err, findings = analyze_chunk(chunk, summary, client, cfg)
                    model_seconds += time.time() - t_call
                    # Persist immediately: finished chunks survive a later failure.
                    store.save_chunk(
                        job_id, chunk.index, chunk.start_line, chunk.end_line, status, attempts, err, findings
                    )
                    consecutive = consecutive + 1 if status == "failed" else 0
                done += 1
                failed += status == "failed"
                store.update_job(
                    job_id, bytes_done=chunk.end_byte, chunks_done=done, chunks_failed=failed,
                    model_seconds=model_seconds,
                )
                if consecutive >= cfg.breaker_failures:
                    store.update_job(
                        job_id,
                        status="aborted",
                        error=(
                            f"Stopped after {consecutive} consecutive chunk failures "
                            f"(last: {err}). Completed chunks are saved; resume once the model is available."
                        )[:400],
                        finished_at=time.time(),
                    )
                    return
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
        if f["corroborated"]:  # unverified model leads are counted separately
            by_sev[f["severity"]] += 1
    return {
        "job_id": job_id,
        "summary": {
            "total_findings": sum(f["corroborated"] for f in merged),
            "by_severity": by_sev,
            "chunks_total": len(chunks),
            "chunks_failed": sum(c["status"] == "failed" for c in chunks),
            "complete": all(c["status"] == "done" for c in chunks),
            "unverified_findings": sum(not f["corroborated"] for f in merged),
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
