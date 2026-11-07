# Local AI Security Log Analyzer

A web app that finds possible attacks in server logs using a **local** language model (no cloud AI). The log is larger than the model's 2,048-token window, so the backend splits it, analyzes each part, carries facts between parts, and combines everything into one report.

- **Frontend:** Next.js (App Router, TypeScript, Tailwind) at `http://localhost:3000`
- **Backend:** Python, FastAPI, SQLite at `http://localhost:8000`
- **Model:** `qwen3.5:0.8b` served by [Ollama](https://ollama.com), 2,048-token context, temperature 0, thinking off, JSON-schema constrained replies
- Works **offline** after setup (no CDN fonts, no external calls).

## Setup

Prerequisites: Python 3.11+, Node 20+, Ollama.

```bash
# 1. Model (needs internet once)
ollama pull qwen3.5:0.8b

# 2. Backend
cd backend
python -m venv .venv
.venv\Scripts\activate            # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
copy .env.example .env            # optional; defaults work
uvicorn main:app --port 8000

# 3. Frontend (second terminal)
cd frontend
npm install
npm run dev
```

Open http://localhost:3000, choose a `.log`/`.txt` file, press **Analyze**. Tests: `pip install -r requirements-dev.txt && pytest` in `backend/` (no Ollama needed; the model is faked).

To mimic the 2 vCPU / no-GPU target set `OLLAMA_NUM_GPU=0` and `OLLAMA_NUM_THREAD=2` in `backend/.env`. All settings are listed in `backend/.env.example`.

## How it works

```
upload ─▶ validate ─▶ stream line by line ─▶ chunker (token budget, whole entries)
                                   │                       │
                          deterministic ledger        for each chunk, one at a time:
                          (per-IP counts + lines)       carry-over summary + log text ─▶ local model
                                   │                       │ JSON (tolerant parser, retries, timeout)
                                   ▼                       ▼
                               SQLite ◀── findings saved after every chunk
                                   │
                                   ▼
                       merge in code ─▶ one final report ─▶ dashboard
```

### Log splitting

- The file is read as a stream (never fully in memory); each line keeps its **original line number**, shown to the model as `N: text`.
- Chunks are built from whole **log entries**: indented lines, `Caused by:` and stack-trace lines stay with their entry. An entry bigger than a chunk is split by line; a single over-long line is split into pieces that share its number.
- JSON-lines logs are sent in a **compact view** (user agent, host, byte counts, request ids dropped): about 4.7x fewer tokens for the same events, so fewer model calls. The full line is still what the deterministic scan reads.
- Token counting uses `LogAwareTokenizer` (digits/punctuation count one token each), calibrated against Ollama's `prompt_eval_count`. A flat "3 characters per token" guess was wrong by 2.2x for logs and made Ollama silently truncate prompts (see AI_USAGE.md).

| Budget (tokens) | |
|---|---|
| Context window | 2,048 |
| System prompt reserve | 450 |
| Carry-over context reserve | 250 (summary capped at 230) |
| Model output (`num_predict`) | 512 |
| **Log text per chunk** | **836** |

### Linking events across the file

1. **Ledger** (plain code, no AI): per-IP counts and line numbers for failed/successful logins, 401/403, SQL injection, path traversal, request rate, scanning of sensitive paths and text that tries to instruct the analyzer. It reads every line of every chunk, so a brute-force run spread across the whole file is counted as one.
2. **Carry-over summary:** before each model call, the top suspicious entities so far (counts + line ranges, about 230 tokens) are put in the prompt.
3. **Merge step** (plain code): findings are grouped by (entity, attack type), evidence lines unioned, and **failed logins followed by a success from the same IP are escalated to "brute force with possible account compromise"** (critical), including privileged use afterwards.

### Keeping the model honest

A 0.8B model hallucinates, so its output is checked in code:

- A finding is dropped if its cited lines are outside the chunk or do not mention the entity it names.
- Findings backed by the ledger are **Corroborated** and keep the ledger's severity and wording.
- Model-only findings are **capped at Low**, labelled **Unverified**, listed separately and not counted in the headline.
- Log text is treated as data: wrapped in per-chunk random delimiters, the system prompt says never to follow it, and text like "Ignore previous instructions" is reported as a low-severity finding instead of obeyed. Nothing in a log is ever executed.

### Reliability

Invalid uploads (type, empty, binary, too large) get clear 4xx errors. Model calls have a timeout and up to 2 retries; broken or truncated JSON is salvaged finding by finding. A failed chunk is marked failed and the rest continue; findings are saved to SQLite after each chunk. After 3 consecutive failures (for example Ollama stopped) the job aborts instead of burning through the file, and **Resume** continues from the saved chunks.

## API

| | |
|---|---|
| `POST /api/analysis` | upload a file, returns `job_id` (202) |
| `GET /api/analysis/{id}` | progress, elapsed time, time per model call, ETA |
| `GET /api/analysis/{id}/report` | final report (409 until ready) |
| `POST /api/analysis/{id}/resume` | continue an aborted/failed job |
| `GET /api/system` | backend RAM, model RAM, 4 GB limit |
| `GET /api/health` | liveness |

Each finding: attack type, severity (low/medium/high/critical), entity (IP), evidence line numbers, reason, suggested action, sources, corroborated flag.

## Results on the supplied log (`Cultive8_Workspace_Agrigen_Server.log`, 258 lines)

Confirmed findings: possible account compromise by 203.0.113.44 (12 failed logins from line 5 to 189, success at 196, then admin and export requests, **critical**); SQL injection by 203.0.113.72 (the duplicate event on lines 222/223 counts once); scanning and path traversal by 203.0.113.90; rate burst by 203.0.113.155; prompt-injection text from 203.0.113.201 (low). Not flagged: a single typo followed by a successful login, DB timeouts, 502s, 422 validation errors, health checks.

| Run | Calls | Time | Notes |
|---|---|---|---|
| GPU machine | 15 to 18 | about 50 s | |
| **CPU only, 2 threads** (`OLLAMA_NUM_GPU=0`) | 18 | **280 s** (15.5 s per call, max 23 s) | model about 568 MB; all calls succeeded; largest prompt 1,305 + 512 output = 1,817 tokens |

## Known limits

- The 0.8B model is weak: it misses attacks and invents others. Real detection comes from the ledger; the model adds extra leads (shown as Unverified) and explanations.
- The ledger understands JSON lines, Apache/nginx access logs and sshd-style text. Other formats fall back to "any line with an IPv4 address plus keywords". Login success/failure is inferred from `auth_result`, or from POSTs to login-like paths, so apps that return 200 on a wrong password are miscounted.
- Thresholds (5 failed logins, 10 requests per minute, 3 probed paths) are heuristics, tunable in `.env`.
- Large files are slow: about 15 s per model call on CPU, so a 20,000-token log is minutes, but a 50 MB log would be many hours. Only one job runs at a time.
- No authentication on the API; intended for local use.
- Resume reuses saved chunks only if the token budget and tokenizer are unchanged; otherwise it refuses.
- Only the backend and model RAM are measured; the frontend dev server is not included in the 4 GB figure.

## Not done / ideas

Switching models from the UI (set `OLLAMA_MODEL` instead), a persistent job history list, deleting finished jobs, and a real model tokenizer instead of the calibrated estimator.
