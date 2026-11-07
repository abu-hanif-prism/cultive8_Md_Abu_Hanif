"""Merge model + ledger findings in code (no model involved)."""
from ledger import Ledger

SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
COMPROMISE = "brute_force_possible_compromise"
MAX_EVIDENCE = 200


def _new_group(entity: str, attack_type: str) -> dict:
    return {
        "entity": entity, "attack_type": attack_type, "severity": "low",
        "evidence_lines": set(), "reason": "", "suggested_action": "", "sources": set(),
        "_rank": (0, 0),
    }


def _absorb(g: dict, f: dict) -> None:
    g["evidence_lines"].update(f["evidence_lines"])
    g["sources"].add(f.get("source", "model"))
    # Ledger facts outrank model opinion: a model can add evidence lines to a ledger-backed
    # finding but cannot raise its severity or replace its explanation. Within a source, the
    # highest severity wins.
    rank = (1 if f.get("source") == "ledger" else 0, SEV_RANK.get(f["severity"], 1))
    if rank > g["_rank"]:
        g["_rank"], g["severity"] = rank, f["severity"]
        g["reason"], g["suggested_action"] = f["reason"], f["suggested_action"]


def merge_findings(findings: list[dict], ledger: Ledger | None = None) -> list[dict]:
    groups: dict[tuple[str, str], dict] = {}
    for f in findings:
        key = (f["entity"], f["attack_type"])
        _absorb(groups.setdefault(key, _new_group(*key)), f)

    # Failures followed by a success from the same IP -> escalate.
    if ledger is not None:
        for ip, st in ledger.ips.items():
            if not st.compromises:
                continue
            fails, first_fail, success = max(st.compromises)
            esc = _new_group(ip, COMPROMISE)
            old = groups.pop((ip, "brute_force"), None)
            if old:
                esc["evidence_lines"] |= old["evidence_lines"]
                esc["sources"] |= old["sources"]
            esc["evidence_lines"] |= {n for n in st.lines["failed"] if first_fail <= n < success}
            esc["evidence_lines"].add(success)
            after = [(n, p) for n, p in st.post_compromise if n > success]
            esc["evidence_lines"] |= {n for n, _ in after}
            follow = (
                f" Afterwards the same IP used privileged endpoints ({', '.join(sorted({p for _, p in after})[:3])})."
                if after else ""
            )
            who = f" against {', '.join(sorted(st.usernames))}" if st.usernames else ""
            esc["sources"].add("ledger")
            esc.update(
                severity="critical",
                reason=(
                    f"{fails} failed logins{who} from {ip} (first at line {first_fail}) were followed by "
                    f"a successful login at line {success}: the account may be compromised.{follow}"
                ),
                suggested_action=(
                    "Treat the account as compromised: force a password reset, revoke sessions, "
                    "enable MFA, and investigate or block the IP."
                ),
            )
            groups[(ip, COMPROMISE)] = esc

    out = []
    for g in groups.values():
        ev = sorted(g["evidence_lines"])
        corroborated = "ledger" in g["sources"]
        # The deterministic scan is the evidence. A model-only claim is a lead to review,
        # not a confirmed attack, so its severity is capped (the model's own value is kept).
        severity = g["severity"] if corroborated else "low"
        out.append({
            "attack_type": g["attack_type"], "severity": severity, "entity": g["entity"],
            "model_severity": None if corroborated else g["severity"],
            "evidence_lines": ev[:MAX_EVIDENCE], "evidence_truncated": len(ev) > MAX_EVIDENCE,
            "reason": g["reason"], "suggested_action": g["suggested_action"],
            "sources": sorted(g["sources"]),
            # Backed by the deterministic ledger (not just the model's opinion).
            "corroborated": corroborated,
        })
    out.sort(key=lambda f: (-SEV_RANK.get(f["severity"], 1), f["entity"], f["attack_type"]))
    return out
