"""Deterministic per-IP ledger: regex/field scan of log lines, no model involved.

Counts and original line numbers are recorded for failed/successful logins,
401/403 responses, SQLi, path traversal, request rate, scanning/probing and
text that tries to instruct the analyzer. Memory is bounded: line lists, probed
path sets, username sets, seen event ids and tracked IPs are all capped.

Supported formats (auto-detected from the first lines):
  json_lines  one JSON object per line (client_ip, path, status, auth_result, ...)
  access_log  Apache/nginx common + combined
  auth_log    sshd-style text ("Failed password for ... from 1.2.3.4")
  generic     any text containing an IPv4 address
"""
import json
import os
import re
from dataclasses import dataclass, field
from itertools import islice
from urllib.parse import unquote_plus

MAX_LINES = 40  # evidence line numbers kept per category per IP
MAX_PATHS = 50  # distinct probed paths kept per IP
MAX_IPS = 20000  # tracked IPs; further new IPs are only counted
MAX_EVENT_IDS = 20000  # remembered event ids (duplicate suppression)

# --- patterns -----------------------------------------------------------------
# Apache/nginx common + combined log format.
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<target>\S+)(?: [^"]*)?" '
    r"(?P<status>\d{3}) (?P<size>\S+)"
)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FROM_IP_RE = re.compile(r"\bfrom\s+((?:\d{1,3}\.){3}\d{1,3})\b")
AUTH_FAIL_RE = re.compile(
    r"failed password|authentication failure|invalid user|failed login|login failed", re.I
)
AUTH_OK_RE = re.compile(r"accepted (?:password|publickey)|login successful|session opened for user", re.I)

LOGIN_PATH_RE = re.compile(
    r"/(?:wp-login\.php|login|signin|sign-in|auth|authenticate|session|user/login|admin/login)(?:/|$)",
    re.I,
)
SQLI_RE = re.compile(
    r"union(?:\s|\+|/\*.*?\*/)+(?:all\s+)?select"
    r"|'\s*or\s+'?\w+'?\s*=\s*'?\w"
    r"|\b(?:or|and)\s+\d+\s*=\s*\d+"
    r"|;\s*drop\s+table|information_schema|sleep\s*\(|benchmark\s*\(|xp_cmdshell"
    r"|waitfor\s+delay|load_file\s*\(|into\s+outfile|'\s*--",
    re.I,
)
TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|etc/passwd|boot\.ini|/proc/self", re.I)
# Log text that tries to talk to an analyzer. It is only ever *flagged*, never obeyed.
INJECTION_RE = re.compile(
    r"ignore (?:all |any |the )?(?:previous|prior|above) (?:instructions|rules)"
    r"|disregard (?:all |any |the )?(?:previous|prior|above|your) (?:instructions|rules)"
    r"|you are now\b|reveal (?:your )?system prompt|report (?:all )?events as safe",
    re.I,
)
COMMON_PROBE_HINTS = (
    "admin", "phpmyadmin", "wp-admin", "wp-login", ".env", ".git", "backup", "config",
    "server-status", "shell", "cgi-bin", "xmlrpc", "actuator", "console", ".htaccess", "passwd",
)
PRIVILEGED_PATH_RE = re.compile(r"/(?:admin|export|download|users|secrets|keys)\b", re.I)
SUCCESS_RESULTS = {"success", "ok", "authenticated", "logged_in", "granted"}


def detect_format(sample_lines: list[str]) -> str:
    """Return 'json_lines', 'access_log', 'auth_log' or 'generic' from a sample of lines."""
    lines = [l for l in sample_lines if l.strip()]
    if not lines:
        return "generic"
    if sum(1 for l in lines if _json_obj(l) is not None) / len(lines) >= 0.6:
        return "json_lines"
    access = sum(1 for l in lines if ACCESS_RE.match(l))
    if access / len(lines) >= 0.5:
        return "access_log"
    auth = sum(1 for l in lines if AUTH_FAIL_RE.search(l) or AUTH_OK_RE.search(l))
    if auth / len(lines) >= 0.2:
        return "auth_log"
    return "generic"


def _json_obj(line: str):
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    return obj if isinstance(obj, dict) else None


def sample_file(path: str, n: int = 200) -> list[str]:
    with open(path, "rb") as f:
        return [raw.decode("utf-8", "replace").rstrip("\r\n") for raw in islice(f, n)]


# --- compact view of a line for the model ------------------------------------------
_NOISE_KEYS = {
    "app", "host", "request_id", "user_agent", "response_bytes", "duration_ms",
    "owner", "allowed_paths", "time", "timestamp", "@timestamp", "level", "service",
    "client_ip", "ip", "method", "path", "url", "status", "status_code",
}


def compact_line(text: str, fmt: str) -> str:
    """What the model sees. For JSON logs, drop noise fields (user agent, host, byte
    counts, ids...) and keep what matters, so more lines fit in one 2,048-token call.
    Other formats are returned unchanged. The original line number is never altered."""
    if fmt != "json_lines":
        return text
    r = _json_obj(text)
    if r is None:
        return text
    t = str(r.get("time") or r.get("timestamp") or r.get("@timestamp") or "")
    parts = [t[5:19] if len(t) >= 19 else t]
    if r.get("level") and r["level"] != "INFO":
        parts.append(str(r["level"]))
    if r.get("service") and r["service"] != "gateway":
        parts.append(str(r["service"]))
    for k in ("client_ip", "ip", "method", "path", "url", "status", "status_code"):
        if r.get(k) is not None:
            parts.append(str(r[k])[:160])
    for k, v in r.items():
        if k in _NOISE_KEYS or v is None:
            continue
        parts.append(f"{k}={str(v)[:100]}")
    return " ".join(p for p in parts if p)


# --- thresholds ----------------------------------------------------------------
@dataclass(frozen=True)
class Thresholds:
    failed_logins: int = 5  # -> brute_force
    denied: int = 3  # 401/403 -> unauthorized_access
    rate_per_minute: int = 10  # peak requests/minute -> rate_abuse
    probe_paths: int = 3  # distinct probed paths -> path_probing
    escalate_min_fails: int = 3  # failures before a success -> possible compromise

    @classmethod
    def from_env(cls) -> "Thresholds":
        d = cls()
        g = lambda k, v: int(os.getenv(k, v))
        return cls(
            g("TH_FAILED_LOGINS", d.failed_logins),
            g("TH_DENIED", d.denied),
            g("TH_RATE_PER_MINUTE", d.rate_per_minute),
            g("TH_PROBE_PATHS", d.probe_paths),
            g("TH_ESCALATE_MIN_FAILS", d.escalate_min_fails),
        )


# --- ledger ---------------------------------------------------------------------
CATEGORIES = ("failed", "success", "denied", "sqli", "notfound", "probe", "traversal", "injection", "rate")


@dataclass
class IPStats:
    requests: int = 0
    first_line: int = 0
    last_line: int = 0
    counts: dict = field(default_factory=lambda: dict.fromkeys(CATEGORIES, 0))
    lines: dict = field(default_factory=lambda: {c: [] for c in CATEGORIES})
    probed: set = field(default_factory=set)  # distinct 404 paths + denied scanner paths
    common_probe_hits: int = 0
    usernames: set = field(default_factory=set)  # accounts targeted by failed logins
    reported_peak: int = 0  # server-reported requests_in_window (JSON logs)
    reported_window: int = 0
    # request-rate bucket (one open minute bucket, plus the peak seen)
    bucket: str = ""
    b_count: int = 0
    b_first: int = 0
    b_last: int = 0
    peak: int = 0
    peak_first: int = 0
    peak_last: int = 0
    # failures followed by a success
    fails_since_success: int = 0
    run_first_fail: int = 0
    compromises: list = field(default_factory=list)  # (fails, first_fail_line, success_line)
    post_compromise: list = field(default_factory=list)  # (line, path): privileged use afterwards

    def peak_rate(self) -> tuple[int, int, int]:
        if self.b_count > self.peak:
            return self.b_count, self.b_first, self.b_last
        return self.peak, self.peak_first, self.peak_last


@dataclass
class Flag:
    attack_type: str
    severity: str
    count: int
    evidence_lines: list
    reason: str
    action: str


class Ledger:
    def __init__(self, fmt: str, thresholds: Thresholds | None = None):
        self.fmt = fmt
        self.th = thresholds or Thresholds()
        self.ips: dict[str, IPStats] = {}
        self.event_ids: set[str] = set()
        self.dropped_ips = 0
        self.lines_scanned = 0
        self.unparsed = 0
        self.no_ip = 0
        self.duplicates = 0

    # -- scanning
    def scan(self, lines) -> None:
        for number, text in lines:
            self.lines_scanned += 1
            self._scan_line(number, text)

    def _stat(self, ip: str) -> IPStats | None:
        st = self.ips.get(ip)
        if st is None:
            if len(self.ips) >= MAX_IPS:
                self.dropped_ips += 1
                return None
            st = self.ips[ip] = IPStats()
        return st

    @staticmethod
    def _hit(st: IPStats, cat: str, n: int) -> None:
        st.counts[cat] += 1
        if len(st.lines[cat]) < MAX_LINES:
            st.lines[cat].append(n)

    def _scan_line(self, n: int, text: str) -> None:
        if self.fmt == "json_lines":
            r = _json_obj(text)
            if r is None:
                self.unparsed += 1
                return
            ip = str(r.get("client_ip") or r.get("ip") or r.get("remote_addr") or r.get("src_ip") or "")
            if not ip:
                self.no_ip += 1  # service/app event with no client: nothing to attribute
                return
            eid = r.get("event_id")
            if eid is not None:
                if eid in self.event_ids:
                    self.duplicates += 1  # same event logged twice: count it once
                    return
                if len(self.event_ids) < MAX_EVENT_IDS:
                    self.event_ids.add(eid)
            st = self._stat(ip)
            if st is None:
                return
            t = str(r.get("time") or r.get("timestamp") or r.get("@timestamp") or "")
            self._touch(st, n, t[:16])  # minute resolution
            self._http(
                st, n,
                method=str(r.get("method") or "").upper(),
                target=str(r.get("path") or r.get("url") or ""),
                status=_int(r.get("status") or r.get("status_code")),
                auth_result=r.get("auth_result"),
                username=r.get("username"),
                reported=(_int(r.get("requests_in_window")), _int(r.get("window_seconds"))),
            )
            if INJECTION_RE.search(text):
                self._hit(st, "injection", n)
            return

        if self.fmt == "access_log":
            m = ACCESS_RE.match(text)
            if not m:
                self.unparsed += 1
                return
            st = self._stat(m["ip"])
            if st is None:
                return
            self._touch(st, n, m["ts"][:17])  # minute resolution, e.g. 07/Nov/2026:10:00
            self._http(st, n, method=m["method"], target=m["target"], status=int(m["status"]))
            return

        # auth_log / generic: keyword based
        m = FROM_IP_RE.search(text) or IP_RE.search(text)
        if not m:
            self.unparsed += 1
            return
        ip = m.group(1) if m.re is FROM_IP_RE else m.group(0)
        st = self._stat(ip)
        if st is None:
            return
        self._touch(st, n, text[:6])  # no reliable timestamp: coarse bucket
        if AUTH_FAIL_RE.search(text):
            self._login(st, n, ok=False)
        elif AUTH_OK_RE.search(text):
            self._login(st, n, ok=True)
        decoded = unquote_plus(unquote_plus(text))
        if SQLI_RE.search(decoded):
            self._hit(st, "sqli", n)
        if TRAVERSAL_RE.search(decoded):
            self._hit(st, "traversal", n)
        if INJECTION_RE.search(text):
            self._hit(st, "injection", n)

    def _http(self, st, n, method, target, status, auth_result=None, username=None, reported=(0, 0)):
        decoded = unquote_plus(unquote_plus(target))  # twice: catches %252e%252e style evasion
        path = decoded.split("?", 1)[0]
        hint = any(h in path.lower() for h in COMMON_PROBE_HINTS)
        if status in (401, 403):
            self._hit(st, "denied", n)
        # login outcome: an explicit auth_result wins, otherwise infer from POST to a login path
        if auth_result is not None:
            ok = str(auth_result).lower() in SUCCESS_RESULTS
            self._login(st, n, ok=ok, username=None if ok else username)
        elif method == "POST" and LOGIN_PATH_RE.search(path):
            if status in (401, 403):
                self._login(st, n, ok=False)
            elif status in (200, 204, 301, 302, 303):
                self._login(st, n, ok=True)
        # privileged use after a login that followed a failure streak (account takeover)
        if st.compromises and status and 200 <= status < 300 and PRIVILEGED_PATH_RE.search(path):
            if len(st.post_compromise) < 10 and n > st.compromises[-1][2]:
                st.post_compromise.append((n, path))
        # scanning: 404s, plus denied requests for well-known sensitive paths
        if status == 404 or (status in (401, 403) and hint):
            if status == 404:
                self._hit(st, "notfound", n)
            self._hit(st, "probe", n)
            if len(st.probed) < MAX_PATHS and path not in st.probed:
                st.probed.add(path)
                if hint:
                    st.common_probe_hits += 1
        if SQLI_RE.search(decoded):
            self._hit(st, "sqli", n)
        if TRAVERSAL_RE.search(decoded):
            self._hit(st, "traversal", n)
        if status == 429 or reported[0]:
            self._hit(st, "rate", n)
        if reported[0] > st.reported_peak:
            st.reported_peak, st.reported_window = reported

    def _touch(self, st: IPStats, n: int, minute: str) -> None:
        st.requests += 1
        st.first_line = st.first_line or n
        st.last_line = n
        if st.bucket != minute:
            if st.b_count > st.peak:
                st.peak, st.peak_first, st.peak_last = st.b_count, st.b_first, st.b_last
            st.bucket, st.b_count, st.b_first = minute, 0, n
        st.b_count += 1
        st.b_last = n

    def _login(self, st: IPStats, n: int, ok: bool, username=None) -> None:
        if ok:
            self._hit(st, "success", n)
            if st.fails_since_success >= self.th.escalate_min_fails and len(st.compromises) < 5:
                st.compromises.append((st.fails_since_success, st.run_first_fail, n))
            st.fails_since_success = 0
        else:
            self._hit(st, "failed", n)
            if username and len(st.usernames) < 5:
                st.usernames.add(str(username)[:40])
            if st.fails_since_success == 0:
                st.run_first_fail = n
            st.fails_since_success += 1

    # -- results
    def flags(self, st: IPStats) -> list[Flag]:
        th, c, ln = self.th, st.counts, st.lines
        out: list[Flag] = []
        if c["failed"] >= th.failed_logins:
            who = f" targeting {', '.join(sorted(st.usernames))}" if st.usernames else ""
            out.append(Flag(
                "brute_force", "high", c["failed"], ln["failed"],
                f"{c['failed']} failed login attempts from one source{who}.",
                "Block or rate-limit the IP and enforce account lockout or MFA.",
            ))
        if c["denied"] >= th.denied and c["failed"] < th.failed_logins:
            out.append(Flag(
                "unauthorized_access", "medium", c["denied"], ln["denied"],
                f"{c['denied']} requests were denied with 401/403.",
                "Review the targeted resources and block the IP if the attempts continue.",
            ))
        if c["sqli"] >= 1:
            out.append(Flag(
                "sql_injection", "high", c["sqli"], ln["sqli"],
                f"{c['sqli']} requests contain SQL injection patterns.",
                "Block the IP, use parameterised queries and check for data exposure.",
            ))
        if c["traversal"] >= 1:
            out.append(Flag(
                "path_traversal", "high", c["traversal"], ln["traversal"],
                f"{c['traversal']} requests try to read files outside the web root (../ or encoded variants).",
                "Block the IP and verify file-access endpoints validate and canonicalise paths.",
            ))
        peak, pf, pl = st.peak_rate()
        if peak >= th.rate_per_minute or st.reported_peak >= th.rate_per_minute:
            ev = ln["rate"] or list(range(pf, pl + 1))[:MAX_LINES]
            detail = f"Peak of {peak} requests in one minute"
            if st.reported_peak:
                detail += f"; server reported {st.reported_peak} requests in a {st.reported_window}s window"
            out.append(Flag(
                "rate_abuse", "medium", max(peak, st.reported_peak), ev,
                detail + ".",
                "Apply rate limiting and check whether the traffic is automated.",
            ))
        if len(st.probed) >= th.probe_paths:
            sev = "high" if len(st.probed) >= 10 else "medium"
            out.append(Flag(
                "path_probing", sev, len(st.probed), ln["probe"],
                f"{len(st.probed)} distinct missing or denied paths ({st.common_probe_hits} are commonly "
                "scanned admin/config paths).",
                "Block the IP and make sure admin, config and backup paths are not exposed.",
            ))
        if c["injection"] >= 1:
            out.append(Flag(
                "prompt_injection", "low", c["injection"], ln["injection"],
                "Log content tries to give instructions to an automated analyzer. It was treated as data and ignored.",
                "Review the submitting client; no change to the analysis is needed.",
            ))
        return out

    def suspicious(self) -> list[tuple[str, IPStats, list[Flag]]]:
        res = []
        for ip, st in self.ips.items():
            fl = self.flags(st)
            if fl or st.compromises:
                res.append((ip, st, fl))
        return res

    def to_findings(self) -> list[dict]:
        out = []
        for ip, _st, fl in self.suspicious():
            for f in fl:
                out.append({
                    "attack_type": f.attack_type, "severity": f.severity, "entity": ip,
                    "evidence_lines": list(f.evidence_lines), "reason": f.reason,
                    "suggested_action": f.action, "source": "ledger",
                })
        return out

    def stats(self) -> dict:
        return {
            "format": self.fmt, "lines_scanned": self.lines_scanned, "unparsed_lines": self.unparsed,
            "lines_without_ip": self.no_ip, "duplicate_events_ignored": self.duplicates,
            "tracked_ips": len(self.ips), "dropped_ips": self.dropped_ips,
        }


def _int(v) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0
