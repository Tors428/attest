import json

import pytest

from attest_dbt.artifacts import columns_hash, parse, sha256_hex


def write_target(tmp_path, results, nodes, catalog=None, which="build", full_refresh=None):
    run_results = {
        "metadata": {"invocation_id": "inv-1"},
        "args": {"which": which, "full_refresh": full_refresh},
        "results": results,
    }
    (tmp_path / "run_results.json").write_text(json.dumps(run_results))
    (tmp_path / "manifest.json").write_text(json.dumps({"nodes": nodes}))
    if catalog is not None:
        (tmp_path / "catalog.json").write_text(json.dumps({"nodes": catalog}))
    return tmp_path


def result(uid, status="success", rows=None, sql="select 1"):
    resp = {"_message": "OK"} if rows is None else {"rows_affected": rows}
    return {
        "unique_id": uid,
        "status": status,
        "execution_time": 0.5,
        "adapter_response": resp,
        "compiled_code": sql,
    }


def node(rtype, mat="table", deps=()):
    return {"resource_type": rtype, "config": {"materialized": mat}, "depends_on": {"nodes": list(deps)}}


def cols(*pairs):
    return {"columns": {n: {"name": n, "type": t, "index": i} for i, (n, t) in enumerate(pairs)}}


def test_parses_one_record_per_node(tmp_path):
    target = write_target(
        tmp_path,
        [result("seed.p.raw", rows=99, sql=None), result("model.p.orders", sql="select * from raw")],
        {"seed.p.raw": node("seed", "seed"), "model.p.orders": node("model", deps=["seed.p.raw"])},
        catalog={"model.p.orders": cols(("id", "INTEGER"), ("amount", "DOUBLE"))},
    )
    records, has_catalog = parse(target)
    assert has_catalog
    seed, model = records
    assert seed["rows"] == 99
    assert seed["sql_sha256"] is None
    assert seed["columns_sha256"] is None
    assert model["invocation_id"] == "inv-1"
    assert model["resource_type"] == "model"
    assert model["materialization"] == "table"
    assert model["execution_time"] == 0.5
    assert model["sql_sha256"] == sha256_hex("select * from raw")
    assert model["depends_on"] == ["seed.p.raw"]


def test_missing_rows_affected_stays_null(tmp_path):
    target = write_target(tmp_path, [result("model.p.a")], {"model.p.a": node("model")})
    (rec,), _ = parse(target)
    assert rec["rows"] is None


def test_column_hash_ignores_catalog_order():
    a = cols(("id", "INTEGER"), ("name", "VARCHAR"))
    b = cols(("name", "VARCHAR"), ("id", "INTEGER"))
    assert columns_hash(a) == columns_hash(b)
    assert columns_hash(a) != columns_hash(cols(("id", "BIGINT"), ("name", "VARCHAR")))


def test_missing_catalog(tmp_path):
    target = write_target(tmp_path, [result("model.p.a")], {"model.p.a": node("model")})
    (rec,), has_catalog = parse(target)
    assert has_catalog is False
    assert rec["columns_sha256"] is None


def test_incremental_run_kind(tmp_path):
    nodes = {"model.p.inc": node("model", "incremental"), "model.p.t": node("model")}
    res = [result("model.p.inc"), result("model.p.t")]
    inc, table = parse(write_target(tmp_path, res, nodes))[0]
    assert inc["run_kind"] == "incremental"
    assert table["run_kind"] == "full"
    inc, _ = parse(write_target(tmp_path, res, nodes, full_refresh=True))[0]
    assert inc["run_kind"] == "full"


def test_refuses_docs_generate_results(tmp_path):
    target = write_target(tmp_path, [result("model.p.a")], {"model.p.a": node("model")}, which="generate")
    with pytest.raises(ValueError, match="docs generate"):
        parse(target)
