"use client";

import { useEffect, useState } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type Severity = "low" | "medium" | "high" | "critical";

interface Progress {
  job_id: string;
  filename: string;
  status: string;
  log_format: string | null;
  progress_percent: number;
  chunks_done: number;
  chunks_failed: number;
  finished: boolean;
  resumable: boolean;
  error: string | null;
  elapsed_s: number;
  avg_chunk_s: number | null;
  eta_s: number | null;
}

interface Finding {
  attack_type: string;
  severity: Severity;
  model_severity: Severity | null;
  entity: string;
  evidence_lines: number[];
  evidence_truncated: boolean;
  reason: string;
  suggested_action: string;
  sources: string[];
  corroborated: boolean;
}

interface Report {
  status: string;
  summary: {
    total_findings: number;
    by_severity: Record<Severity, number>;
    chunks_total: number;
    chunks_failed: number;
    complete: boolean;
    unverified_findings: number;
  };
  findings: Finding[];
  failed_chunks: { index: number; start_line: number; end_line: number; error: string }[];
  ledger: { format: string; lines_scanned: number; duplicate_events_ignored?: number };
}

interface SystemInfo {
  backend_rss_mb: number;
  model: { name: string; size_mb: number } | null;
  total_mb: number;
  limit_mb: number;
}

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-amber-300 text-amber-950",
  low: "bg-sky-200 text-sky-950",
};

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_URL}${path}`, init);
  const body = await res.json().catch(() => ({}));
  if (!res.ok) {
    const d = body?.detail;
    throw new Error(typeof d === "string" ? d : `Request failed (${res.status})`);
  }
  return body as T;
}

/** [253,254,255,260] -> "253–255, 260" */
function lineRanges(lines: number[]): string {
  const out: string[] = [];
  let i = 0;
  while (i < lines.length) {
    let j = i;
    while (j + 1 < lines.length && lines[j + 1] === lines[j] + 1) j++;
    out.push(j > i ? `${lines[i]}–${lines[j]}` : `${lines[i]}`);
    i = j + 1;
  }
  return out.join(", ");
}

const label = (s: string) => s.replace(/_/g, " ");

function fmtTime(s: number | null): string {
  if (s === null || s === undefined) return "–";
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m ${Math.round(s % 60)}s` : `${Math.round(s)}s`;
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`rounded px-2 py-0.5 text-xs font-semibold uppercase ${SEVERITY_STYLE[severity]}`}>
      {severity}
    </span>
  );
}

function VerifiedBadge({ corroborated }: { corroborated: boolean }) {
  return corroborated ? (
    <span
      title="Backed by the deterministic log scan, not just the AI model"
      className="rounded border border-emerald-600 px-2 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-400"
    >
      ✓ Corroborated
    </span>
  ) : (
    <span
      title="Reported only by the AI model; the deterministic scan found no matching evidence. Review manually."
      className="rounded border border-amber-500 px-2 py-0.5 text-xs font-medium text-amber-700 dark:text-amber-400"
    >
      ? Unverified
    </span>
  );
}

function FindingsTable({ findings, empty }: { findings: Finding[]; empty: string }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-zinc-300 dark:border-zinc-700">
      <table className="w-full min-w-[56rem] text-left text-sm">
        <thead className="bg-zinc-100 text-xs uppercase text-zinc-600 dark:bg-zinc-900 dark:text-zinc-400">
          <tr>
            <th className="p-3">Severity</th>
            <th className="p-3">Entity</th>
            <th className="p-3">Attack type</th>
            <th className="p-3">Evidence lines</th>
            <th className="p-3">Reason / suggested action</th>
            <th className="p-3">Verification</th>
          </tr>
        </thead>
        <tbody>
          {findings.length === 0 && (
            <tr>
              <td colSpan={6} className="p-4 text-center text-zinc-500">
                {empty}
              </td>
            </tr>
          )}
          {findings.map((f) => (
            <tr key={`${f.entity}|${f.attack_type}`} className="border-t border-zinc-200 align-top dark:border-zinc-800">
              <td className="p-3">
                <SeverityBadge severity={f.severity} />
                {f.model_severity && f.model_severity !== f.severity && (
                  <div className="mt-1 text-xs text-zinc-500">model said {f.model_severity}</div>
                )}
              </td>
              <td className="p-3 font-mono">{f.entity}</td>
              <td className="p-3 capitalize">{label(f.attack_type)}</td>
              <td className="p-3 font-mono text-xs">
                {lineRanges(f.evidence_lines)}
                {f.evidence_truncated && " …"}
              </td>
              <td className="p-3">
                <p>{f.reason}</p>
                <p className="mt-1 text-zinc-500">→ {f.suggested_action}</p>
              </td>
              <td className="p-3">
                <VerifiedBadge corroborated={f.corroborated} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function Home() {
  const [health, setHealth] = useState("checking…");
  const [system, setSystem] = useState<SystemInfo | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const [runId, setRunId] = useState(0); // bumped on resume to restart polling
  const [progress, setProgress] = useState<Progress | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    api<{ status: string }>("/api/health")
      .then((d) => setHealth(d.status))
      .catch(() => setHealth("unreachable"));
  }, []);

  // RAM / model readout, refreshed every few seconds.
  useEffect(() => {
    let stopped = false;
    const load = () =>
      api<SystemInfo>("/api/system")
        .then((s) => !stopped && setSystem(s))
        .catch(() => undefined);
    load();
    const t = setInterval(load, 4000);
    return () => {
      stopped = true;
      clearInterval(t);
    };
  }, []);

  // Poll progress; fetch the report once the job has finished.
  useEffect(() => {
    if (!jobId) return;
    let stopped = false;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      try {
        const p = await api<Progress>(`/api/analysis/${jobId}`);
        if (stopped) return;
        setProgress(p);
        if (p.finished) {
          if (p.status.startsWith("completed")) {
            const r = await api<Report>(`/api/analysis/${jobId}/report`);
            if (!stopped) setReport(r);
          }
          return;
        }
      } catch (e) {
        if (!stopped) setError(e instanceof Error ? e.message : "Polling failed");
        return;
      }
      timer = setTimeout(tick, 1000);
    };
    timer = setTimeout(tick, 0);
    return () => {
      stopped = true;
      clearTimeout(timer);
    };
  }, [jobId, runId]);

  async function start() {
    if (!file) return;
    setBusy(true);
    setError(null);
    setReport(null);
    setProgress(null);
    try {
      const form = new FormData();
      form.append("file", file);
      const r = await api<{ job_id: string }>("/api/analysis", { method: "POST", body: form });
      setJobId(r.job_id);
      setRunId((n) => n + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Upload failed");
    } finally {
      setBusy(false);
    }
  }

  async function resume() {
    if (!jobId) return;
    setError(null);
    setReport(null);
    try {
      await api(`/api/analysis/${jobId}/resume`, { method: "POST" });
      setProgress((p) => (p ? { ...p, finished: false, resumable: false, status: "queued" } : p));
      setRunId((n) => n + 1);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Resume failed");
    }
  }

  const running = !!progress && !progress.finished;
  const pct = progress ? Math.min(100, progress.progress_percent) : 0;
  const confirmed = report?.findings.filter((f) => f.corroborated) ?? [];
  const unverified = report?.findings.filter((f) => !f.corroborated) ?? [];

  return (
    <main className="mx-auto flex w-full max-w-6xl flex-col gap-6 p-6">
      <header className="flex flex-wrap items-baseline justify-between gap-4">
        <h1 className="text-2xl font-bold sm:text-3xl">Local AI Security Log Analyzer</h1>
        <div className="text-right text-xs text-zinc-500">
          <div>Backend: {health}</div>
          {system && (
            <div title="Backend process + loaded model, against the 4 GB limit">
              RAM: {system.backend_rss_mb} MB backend
              {system.model ? ` + ${system.model.size_mb} MB model (${system.model.name})` : " · model idle"} ={" "}
              {system.total_mb} / {system.limit_mb} MB
            </div>
          )}
        </div>
      </header>

      <section className="flex flex-wrap items-center gap-3 rounded-lg border border-zinc-300 p-4 dark:border-zinc-700">
        <input
          type="file"
          accept=".log,.txt"
          onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          className="text-sm"
        />
        <button
          onClick={start}
          disabled={!file || busy || running}
          className="rounded bg-zinc-900 px-4 py-2 text-sm font-medium text-white disabled:opacity-40 dark:bg-zinc-100 dark:text-zinc-900"
        >
          {busy ? "Uploading…" : "Analyze"}
        </button>
        <span className="text-xs text-zinc-500">.log or .txt, processed locally</span>
      </section>

      {error && (
        <div role="alert" className="rounded border border-red-500 bg-red-50 p-3 text-sm text-red-800 dark:bg-red-950 dark:text-red-200">
          {error}
        </div>
      )}

      {progress && (
        <section className="rounded-lg border border-zinc-300 p-4 dark:border-zinc-700" aria-live="polite">
          <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2 text-sm">
            <span className="font-medium">
              {progress.filename} <span className="text-zinc-500">· {label(progress.status)}</span>
            </span>
            <span className="text-zinc-500">
              {progress.chunks_done} chunks done
              {progress.chunks_failed > 0 && `, ${progress.chunks_failed} failed`}
              {progress.log_format && ` · ${label(progress.log_format)}`}
            </span>
          </div>
          <div className="h-3 w-full overflow-hidden rounded bg-zinc-200 dark:bg-zinc-800" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
            <div
              className={`h-full transition-all ${
                progress.status === "aborted" || progress.status === "failed" ? "bg-red-500" : "bg-emerald-500"
              }`}
              style={{ width: `${pct}%` }}
            />
          </div>
          <div className="mt-1 flex justify-between text-xs text-zinc-500">
            <span>
              elapsed {fmtTime(progress.elapsed_s)}
              {progress.avg_chunk_s !== null && ` · ${progress.avg_chunk_s}s per model call`}
              {progress.eta_s !== null && ` · about ${fmtTime(progress.eta_s)} left`}
            </span>
            <span>{pct.toFixed(1)}%</span>
          </div>
          {progress.error && <p className="mt-2 text-sm text-red-700 dark:text-red-300">{progress.error}</p>}
          {progress.resumable && (
            <button onClick={resume} className="mt-3 rounded border border-zinc-500 px-3 py-1.5 text-sm font-medium">
              Resume analysis
            </button>
          )}
        </section>
      )}

      {report && (
        <section className="flex flex-col gap-4">
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-xl font-semibold">{report.summary.total_findings} confirmed findings</h2>
            {(Object.keys(SEVERITY_STYLE) as Severity[]).reverse().map((s) => (
              <span key={s} className="flex items-center gap-1 text-sm">
                <SeverityBadge severity={s} /> {report.summary.by_severity[s]}
              </span>
            ))}
          </div>

          {!report.summary.complete && (
            <p className="rounded border border-amber-500 p-3 text-sm">
              {report.summary.chunks_failed} chunk(s) failed AI analysis (lines{" "}
              {report.failed_chunks.map((c) => `${c.start_line}–${c.end_line}`).join(", ")}); those lines were checked by
              the deterministic scan only.
            </p>
          )}

          <FindingsTable findings={confirmed} empty="No confirmed suspicious activity found." />

          {unverified.length > 0 && (
            <details className="rounded-lg border border-amber-500 p-3">
              <summary className="cursor-pointer text-sm font-medium">
                {unverified.length} unverified AI suggestion{unverified.length > 1 ? "s" : ""} (not counted above — review
                manually)
              </summary>
              <p className="my-2 text-xs text-zinc-500">
                The local model reported these, but the deterministic scan found no matching evidence, so their severity
                is capped at low. They are leads, not confirmed attacks.
              </p>
              <FindingsTable findings={unverified} empty="" />
            </details>
          )}
        </section>
      )}
    </main>
  );
}
