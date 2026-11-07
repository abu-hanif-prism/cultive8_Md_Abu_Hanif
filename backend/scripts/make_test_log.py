"""Generate a deterministic access log: clean traffic first, then known attacks.

Usage: python scripts/make_test_log.py [out_path]   (default: data/test-traffic.log)
Prints the line ranges of each planted attack so results can be checked.
"""
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

rnd = random.Random(42)
out = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent.parent / "data" / "test-traffic.log")
out.parent.mkdir(parents=True, exist_ok=True)

NORMAL_IPS = [f"10.0.{rnd.randint(0, 3)}.{rnd.randint(2, 250)}" for _ in range(25)]
PATHS = ["/", "/products", "/products/12", "/about", "/contact", "/cart", "/static/app.js",
         "/static/style.css", "/api/items", "/api/status", "/search?q=shoes", "/blog/post-1"]
rows: list[tuple[str, str, str, str, int, int]] = []  # ip, method, path, ts, status, size
clock = datetime(2026, 11, 7, 10, 0, 0)
marks: dict[str, list[int]] = {}


def add(ip, method, path, status, size=None, step=None):
    global clock
    clock += timedelta(seconds=step if step is not None else rnd.randint(1, 3))
    rows.append((ip, method, path, clock.strftime("%d/%b/%Y:%H:%M:%S +0600"), status, size or rnd.randint(200, 5000)))


def mark(name, start):
    marks[name] = [start + 1, len(rows)]  # 1-based line range


# 1. clean traffic (~250 lines)
for _ in range(250):
    p = rnd.choice(PATHS)
    add(rnd.choice(NORMAL_IPS), rnd.choice(["GET"] * 9 + ["POST"]) if p.startswith("/api") else "GET", p,
        rnd.choices([200, 304, 404], [90, 7, 3])[0])
# a couple of ordinary users logging in (one typo) -> must NOT be flagged
add("10.0.1.77", "POST", "/login", 401); add("10.0.1.77", "POST", "/login", 200)

# 2. attacks
s = len(rows); atk = "203.0.113.50"
for _ in range(9):
    add(atk, "POST", "/login", 401, 450, 1)
add(atk, "POST", "/login", 200, 1200, 1)
mark("brute_force_then_success 203.0.113.50", s)

s = len(rows); atk = "198.51.100.23"
for q in ["%27%20OR%201=1--", "1%20UNION%20SELECT%20username,password%20FROM%20users",
          "1%27%20OR%20%271%27=%271", "1;%20DROP%20TABLE%20users--", "1%20AND%20SLEEP(5)"]:
    add(atk, "GET", f"/products?id={q}", rnd.choice([400, 403, 500]), 300)
mark("sql_injection 198.51.100.23", s)

s = len(rows); atk = "192.0.2.77"
for p in ["/admin", "/phpmyadmin", "/wp-admin", "/.env", "/.git/config", "/backup.zip", "/server-status", "/config.php"]:
    add(atk, "GET", p, 404 if p != "/server-status" else 403, 200, 1)
mark("path_probing 192.0.2.77", s)

s = len(rows); atk = "198.51.100.99"
for _ in range(40):
    add(atk, "GET", "/api/items", 200, 800, 0)
mark("rate_abuse 198.51.100.99", s)

# 3. clean tail
for _ in range(60):
    add(rnd.choice(NORMAL_IPS), "GET", rnd.choice(PATHS), rnd.choices([200, 304, 404], [90, 7, 3])[0])

with open(out, "w", encoding="utf-8", newline="\n") as f:
    for ip, m, p, ts, st, sz in rows:
        f.write(f'{ip} - - [{ts}] "{m} {p} HTTP/1.1" {st} {sz}\n')

print(f"wrote {len(rows)} lines to {out}")
print("clean traffic: lines 1-252 and the last 60 lines")
for k, (a, b) in marks.items():
    print(f"  {k}: lines {a}-{b}")
