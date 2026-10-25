import hashlib
import json
from pathlib import Path

# docs generate also writes run_results.json, but it's a compile, not a run
RUN_COMMANDS = {"build", "run", "test", "seed", "snapshot"}


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _read(path: Path) -> dict | None:
    return json.loads(path.read_text()) if path.exists() else None


def columns_hash(catalog_node: dict | None) -> str | None:
    if not catalog_node:
        return None
    cols = sorted((c["name"], c["type"]) for c in catalog_node["columns"].values())
    return sha256_hex(json.dumps(cols, separators=(",", ":")))


def run_kind(materialization: str | None, full_refresh: bool) -> str:
    if materialization == "incremental" and not full_refresh:
        return "incremental"
    return "full"


def parse(target_dir: str | Path) -> tuple[list[dict], bool]:
    target = Path(target_dir)
    run_results = _read(target / "run_results.json")
    manifest = _read(target / "manifest.json")
    if run_results is None or manifest is None:
        raise FileNotFoundError(f"need run_results.json and manifest.json in {target}")
    catalog = _read(target / "catalog.json")

    args = run_results.get("args") or {}
    which = args.get("which")
    if which and which not in RUN_COMMANDS:
        raise ValueError(f"run_results.json is from `dbt {which}`, not a run. ingest before docs generate")

    invocation_id = run_results["metadata"]["invocation_id"]
    full_refresh = bool(args.get("full_refresh"))
    cat_nodes = (catalog or {}).get("nodes", {})

    records = []
    for res in run_results["results"]:
        uid = res["unique_id"]
        node = manifest["nodes"].get(uid, {})
        mat = (node.get("config") or {}).get("materialized")
        sql = res.get("compiled_code") or node.get("compiled_code")
        records.append(
            {
                "invocation_id": invocation_id,
                "unique_id": uid,
                "resource_type": node.get("resource_type") or uid.split(".")[0],
                "status": res["status"],
                "execution_time": res.get("execution_time"),
                "materialization": mat,
                "run_kind": run_kind(mat, full_refresh),
                "rows": (res.get("adapter_response") or {}).get("rows_affected"),
                "sql_sha256": sha256_hex(sql) if sql else None,
                "columns_sha256": columns_hash(cat_nodes.get(uid)),
                "depends_on": (node.get("depends_on") or {}).get("nodes", []),
            }
        )
    return records, catalog is not None
