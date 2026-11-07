# AI usage log

Claude Code (Sonnet 5.5) wrote most of the code in this repo at my direction. This file records where its
output was wrong, how that was found, and what changed. Edit anything here that does not match what you remember.

## 1. Token estimator was wrong by 2.2x (largest mistake)

**What the AI built.** A placeholder `ApproxTokenizer` assuming 3 characters per token. Chunks were sized to a
986-token budget so that system prompt + context + chunk + output fit in the 2,048-token window.

**The wrong claim.** After the first real run of `scripts/stress_test.py` on the 32-line sample log, Ollama reported
`prompt_eval_count: 1026` and the AI's estimate for the same text was 1,009. The AI reported the estimator was
"within 2%". That agreement was a coincidence.

**The tell.** In later runs on a generated log, `prompt_eval_count` was exactly **1026 for 40, 80 and 120 lines**.
A prompt that triples in size cannot keep the same token count. The model had also missed attacks at the *start*
of every chunk (e.g. the 7 failed logins on lines 5-11 of the sample) and returned malformed JSON on clean traffic.

**Diagnosis (measured, not guessed).**

| Probe | Result |
|---|---|
| Same 120-line prompt, `num_ctx` 2048 vs 4096 | 1026 vs 2050 tokens. Both are about `num_ctx / 2`, so Ollama was **truncating** the prompt |
| 30 log lines (2,447 chars), `num_ctx` 2048 | 1828 tokens, about 1.34 chars/token |
| Log text with `num_ctx` 16384 (no truncation) | 1.33-1.35 chars/token for every log slice tested |
| English system prompt, same method | about 5 chars/token |

**Cause.** Qwen-style tokenizers emit one token per digit and roughly one per punctuation mark. Access logs
are mostly IPs, timestamps and status codes, so they cost far more tokens per character than prose. "986 tokens"
of chunk was really about 2,200, and Ollama silently dropped the front of every prompt.

**Fix.** `LogAwareTokenizer` in `backend/tokenizer.py` counts digits and punctuation individually and words at
4 chars/token, with a 10% safety margin. Calibration against real Ollama counts (before the margin): access
log 0.96-0.97, sshd log 0.96, prose 1.49 (over-estimates, the safe direction). Regression tests pin it to measured
counts. Verified end to end: 28 chunks of a 375-line log, real prompts 513-1266 tokens, worst case plus
512 output = 1778 < 2048, no truncation.

**Lesson.** A number that agrees with your estimate once proves nothing. Look for values that *don't move* when
the input changes.

## 2. Other mistakes caught

- **Parser dropped findings.** The tolerant JSON parser, on truncated output, decoded the first inner finding as
  if it were the whole response and lost the rest while reporting it complete. A unit test caught it; the parser now
  anchors on the `{"findings"` wrapper.
- **Tests that would have deleted the real sample log.** The pipeline deleted its input file when finished and the
  tests passed it `sample-security.log`. The tool permission check blocked the test run before any such test
  executed (file verified intact). Deletion moved to the API worker, which owns its uploaded copies, and a test
  now asserts `run_job` never deletes its input.
- **Vacuous assertions.** The AI twice left `or True` assertions in tests; found on review and replaced with real checks.

## 3. Limits of the model itself

`qwen3.5:0.8b` misses real attacks (it did not report the brute-force-then-success or the SQL injection in the
32-line sample) and once flagged a user with a single typo'd password as high-severity brute force. The design
therefore treats the model as a second opinion: a deterministic regex ledger produces the core findings, and each
finding is shown as **Corroborated** (backed by the ledger) or **Unverified** (model only).

Model output is also not fully reproducible between runs, because each chunk's prompt carries a random delimiter.
