import json

POLICY_NAME = "dbt_quality"


def nodes(rows) -> list[dict]:
    # rows: (seq, signed_at, entry_hash_b64, verdict, reasons, input_text, signals) in seq order
    out, seq_of = [], {}
    for seq, signed_at, entry_hash, verdict, reasons, text, signals in rows:
        try:
            rec = json.loads(text or "")
        except ValueError:
            continue
        seq_of[entry_hash] = seq
        reasons = reasons or {}
        out.append(
            {
                "seq": seq,
                "signed_at": signed_at,
                "invocation_id": rec.get("invocation_id"),
                "unique_id": rec.get("unique_id"),
                "resource_type": rec.get("resource_type"),
                "status": rec.get("status"),
                "rows": rec.get("rows"),
                "sql_sha256": rec.get("sql_sha256"),
                "columns_sha256": rec.get("columns_sha256"),
                "verdict": verdict,
                "matched_rule_id": reasons.get("matched_rule_id"),
                "reason": reasons.get("reason"),
                "signals": signals,
                # upstream nodes always land on the chain first, so their seq is known by now
                "refs": [
                    {"unique_id": name, "seq": seq_of.get(h)}
                    for name, h in (rec.get("refs") or {}).items()
                ],
            }
        )
    return out


def group_runs(nodes: list[dict]) -> list[dict]:
    runs = {}
    for n in nodes:
        run = runs.setdefault(
            n["invocation_id"],
            {
                "invocation_id": n["invocation_id"],
                "started_at": n["signed_at"],
                "first_seq": n["seq"],
                "total": 0,
                "counts": {},
            },
        )
        run["total"] += 1
        run["counts"][n["verdict"]] = run["counts"].get(n["verdict"], 0) + 1
    return sorted(runs.values(), key=lambda r: r["first_seq"], reverse=True)
