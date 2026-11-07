"""Deterministic per-IP ledger: regex scan of log lines, no model involved.

Counts and original line numbers are recorded for failed/successful logins,
401/403 responses, SQLi patterns, request rate and path probing.
Memory is bounded: line lists, probed-path sets and the number of tracked IPs
are all capped.
"""
import os
import re
from dataclasses import dataclass, field
from itertools import islice
from urllib.parse import unquote_plus

MAX_LINES = 40  # evidence line numbers kept per category per IP
MAX_PATHS = 50  # distinct 404 paths kept per IP
MAX_IPS = 20000  # tracked IPs; further new IPs are only counted

# --- formats -----------------------------------------------------------------
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
COMMON_PROBE_HINTS = (
    "admin", "phpmyadmin", "wp-admin", "wp-login", ".env", ".git", "backup", "config",
    "server-status", "shell", "cgi-bin", "xmlrpc", "actuator", "console", ".htaccess", "passwd",
)


def detect_format(sample_lines: list[str]) -> str:
    """Return 'access_log', 'auth_log' or 'generic' from a sample of lines."""
    lines = [l for l in sample_lines if l.strip()]
    if not lines:
        return "generic"
    access = sum(1 for l in lines if ACCESS_RE.match(l))
    if access / len(lines) >= 0.5:
        return "access_log"
    auth = sum(1 for l in lines if AUTH_FAIL_RE.search(l) or AUTH_OK_RE.search(l))
    if auth / len(lines) >= 0.2:
        return "auth_log"
    return "generic"


def sample_file(path: str, n: int = 200) -> list[str]:
    with open(path, "rb") as f:
        return [raw.decode("utf-8", "replace").rstrip("\r\n") for raw in islice(f, n)]


# --- thresholds ----------------------------------------------------------------
@dataclass(frozen=True)
class Thresholds:
    failed_logins: int = 5  # -> brute_force
    denied: int = 3  # 401/403 -> unauthorized_access
    rate_per_minute: int = 10  # peak requests/minute -> rate_abuse
    probe_paths: int = 3  # distinct 404 paths -> path_probing
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
CATEGORIES = ("failed", "success", "denied", "sqli", "notfound")


@dataclass
class IPStats:
    requests: int = 0
    first_line: int = 0
    last_line: int = 0
    counts: dict = field(default_factory=lambda: dict.fromkeys(CATEGORIES, 0))
    lines: dict = field(default_factory=lambda: {c: [] for c in CATEGORIES})
    paths_404: set = field(default_factory=set)
    common_probe_hits: int = 0
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
        self.dropped_ips = 0
        self.lines_scanned = 0
        self.unparsed = 0

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
        if self.fmt == "access_log":
            m = ACCESS_RE.match(text)
            if not m:
                self.unparsed += 1
                return
            st = self._stat(m["ip"])
            if st is None:
                return
            self._touch(st, n, m["ts"][:17])  # minute resolution, e.g. 07/Nov/2026:10:00
            target = unquote_plus(unquote_plus(m["target"]))
            path = target.split("?", 1)[0]
            status = int(m["status"])
            if status in (401, 403):
                self._hit(st, "denied", n)
            if m["method"] == "POST" and LOGIN_PATH_RE.search(path):
                if status in (401, 403):
                    self._login(st, n, ok=False)
                elif status in (200, 204, 301, 302, 303):
                    self._login(st, n, ok=True)
            if status == 404:
                self._hit(st, "notfound", n)
                if len(st.paths_404) < MAX_PATHS and path not in st.paths_404:
                    st.paths_404.add(path)
                    if any(h in path.lower() for h in COMMON_PROBE_HINTS):
                        st.common_probe_hits += 1
            if SQLI_RE.search(target):
                self._hit(st, "sqli", n)
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
        if SQLI_RE.search(unquote_plus(text)):
            self._hit(st, "sqli", n)

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

    def _login(self, st: IPStats, n: int, ok: bool) -> None:
        if ok:
            self._hit(st, "success", n)
            if st.fails_since_success >= self.th.escalate_min_fails and len(st.compromises) < 5:
                st.compromises.append((st.fails_since_success, st.run_first_fail, n))
            st.fails_since_success = 0
        else:
            self._hit(st, "failed", n)
            if st.fails_since_success == 0:
                st.run_first_fail = n
            st.fails_since_success += 1

    # -- results
    def flags(self, st: IPStats) -> list[Flag]:
        th, c, ln = self.th, st.counts, st.lines
        out: list[Flag] = []
        if c["failed"] >= th.failed_logins:
            out.append(Flag(
                "brute_force", "high", c["failed"], ln["failed"],
                f"{c['failed']} failed login attempts from one source.",
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
        peak, pf, pl = st.peak_rate()
        if peak >= th.rate_per_minute:
            out.append(Flag(
                "rate_abuse", "medium", peak, list(range(pf, pl + 1))[:MAX_LINES],
                f"Peak of {peak} requests in one minute.",
                "Apply rate limiting and check whether the traffic is automated.",
            ))
        if len(st.paths_404) >= th.probe_paths:
            sev = "high" if len(st.paths_404) >= 10 else "medium"
            out.append(Flag(
                "path_probing", sev, len(st.paths_404), ln["notfound"],
                f"{len(st.paths_404)} distinct paths returned 404 "
                f"({st.common_probe_hits} are commonly probed paths).",
                "Block the IP and make sure admin and backup paths are not exposed.",
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
            "tracked_ips": len(self.ips), "dropped_ips": self.dropped_ips,
        }
