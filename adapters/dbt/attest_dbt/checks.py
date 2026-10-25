from collections import defaultdict
from statistics import median

ROW_WINDOW = 7
ROW_FLOOR = 0.7


def rows_signal(rec: dict, history: list[dict]) -> str | None:
    rows = rec["rows"]
    if rows is None or rows < 0:
        return None
    # incremental runs only add new rows, so only compare like with like
    same = [
        h["rows"]
        for h in history
        if h["run_kind"] == rec["run_kind"] and h["rows"] is not None and h["rows"] >= 0
    ][-ROW_WINDOW:]
    if not same or rows >= ROW_FLOOR * median(same):
        return None
    if history and history[-1]["sql_sha256"] != rec["sql_sha256"]:
        return "code_change"
    return "drop"


def schema_changed(rec: dict, history: list[dict]) -> bool:
    if rec["columns_sha256"] is None:
        return False
    prev = [h["columns_sha256"] for h in history if h["columns_sha256"]]
    return bool(prev) and prev[-1] != rec["columns_sha256"]


def signals(rec: dict, history: list[dict], has_catalog: bool) -> str:
    out = [f"status={rec['status']}"]
    if rec["resource_type"] == "test":
        if rec["status"] in ("fail", "error"):
            out.append("test=fail")
        elif rec["status"] == "warn":
            out.append("test=warn")
    rows = rows_signal(rec, history)
    if rows:
        out.append(f"rows={rows}")
    if not has_catalog:
        out.append("schema=skipped")
    elif schema_changed(rec, history):
        out.append("schema=changed")
    return " ".join(out)


class History:
    """what's already on the chain, per node. history only ever looks at a node's
    own past records, so partial runs and missing nodes need no special case."""

    def __init__(self, past: list[tuple[dict, str]] = ()):
        self.by_node = defaultdict(list)
        self.latest = {}
        self.seen = set()
        for rec, entry_hash in past:
            self.add(rec, entry_hash)

    def add(self, rec: dict, entry_hash: str) -> None:
        self.by_node[rec["unique_id"]].append(rec)
        self.latest[rec["unique_id"]] = entry_hash
        self.seen.add((rec["invocation_id"], rec["unique_id"]))

    def prepare(self, rec: dict, has_catalog: bool) -> tuple[dict, str] | None:
        if (rec["invocation_id"], rec["unique_id"]) in self.seen:
            return None
        rec = dict(rec)
        rec["refs"] = {n: self.latest.get(n) for n in rec.pop("depends_on")}
        return rec, signals(rec, self.by_node[rec["unique_id"]], has_catalog)
