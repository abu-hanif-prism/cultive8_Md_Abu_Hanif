"""Carry-over summary: the top suspicious entities seen so far, token-capped."""
from ledger import Ledger
from tokenizer import Tokenizer

HEADER = "Suspicious so far (earlier chunks):"
NONE_LINE = "none"

_LABEL = {
    "brute_force": "failed logins",
    "unauthorized_access": "401/403",
    "sql_injection": "SQLi",
    "rate_abuse": "peak req/min",
    "path_probing": "404 paths",
}


def _score(st, flags) -> int:
    s = 100 * len(st.compromises)
    for f in flags:
        s += {"high": 10, "medium": 5, "low": 1}[f.severity] * 10 + f.count
    return s


def build_summary(ledger: Ledger, tok: Tokenizer, cap_tokens: int = 230) -> str:
    """Return a summary that fits in cap_tokens (header included)."""
    ranked = sorted(
        ((_score(st, fl), ip, st, fl) for ip, st, fl in ledger.suspicious()),
        key=lambda x: (-x[0], x[1]),
    )
    if not ranked:
        return f"{HEADER} {NONE_LINE}"
    lines = [HEADER]
    for _score_, ip, st, fl in ranked:
        parts = []
        if st.compromises:
            fails, first, success = st.compromises[0]
            parts.append(f"{fails} failed logins then success (L{first}-{success})")
        for f in fl:
            if f.attack_type == "brute_force" and st.compromises:
                continue
            lo, hi = min(f.evidence_lines), max(f.evidence_lines)
            parts.append(f"{f.count} {_LABEL[f.attack_type]} (L{lo}-{hi})")
        line = f"- {ip}: " + "; ".join(parts)
        if tok.count("\n".join(lines + [line])) > cap_tokens:
            break
        lines.append(line)
    if len(lines) == 1:  # even the top entity did not fit: truncate it
        top = f"- {ranked[0][1]}: suspicious (see ledger)"
        lines.append(top)
    return "\n".join(lines)
