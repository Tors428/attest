from pathlib import Path

import pytest

from attest.loader import load_from_file
from attest.matcher import enforce
from attest_dbt.checks import History

POLICY = load_from_file(Path(__file__).resolve().parent.parent / "policies" / "dbt_quality.yaml")


def rec(uid="model.p.orders", inv="inv-1", rows=None, sql="a", cols="c1", kind="full",
        rtype="model", status="success", deps=()):
    return {
        "invocation_id": inv,
        "unique_id": uid,
        "resource_type": rtype,
        "status": status,
        "execution_time": 0.1,
        "materialization": "table",
        "run_kind": kind,
        "rows": rows,
        "sql_sha256": sql,
        "columns_sha256": cols,
        "depends_on": list(deps),
    }


def past(*recs):
    return [(r, f"hash-{i}") for i, r in enumerate(recs)]


def verdict(r, history=(), has_catalog=True):
    h = History(past(*history))
    prepared, out = h.prepare(r, has_catalog)
    d = enforce(POLICY, "", out)
    return d.verdict, d.matched_rule_id, out


def test_dedupe_same_invocation_and_node():
    h = History(past(rec(inv="inv-1")))
    assert h.prepare(rec(inv="inv-1"), True) is None
    assert h.prepare(rec(inv="inv-2"), True) is not None


def test_refs_point_at_latest_record_of_each_upstream():
    h = History(past(rec(uid="seed.p.raw", inv="inv-1"), rec(uid="seed.p.raw", inv="inv-2")))
    prepared, _ = h.prepare(rec(deps=["seed.p.raw", "model.p.never_ran"]), True)
    assert prepared["refs"] == {"seed.p.raw": "hash-1", "model.p.never_ran": None}
    assert "depends_on" not in prepared


def test_partial_run_only_compares_node_to_itself():
    # orders had big runs before, customers is new and small. neither should be
    # compared to the other, and nodes missing from this run are just ignored
    history = [rec(uid="model.p.orders", inv=f"i{i}", rows=1000) for i in range(3)]
    history.append(rec(uid="model.p.payments", inv="i0", rows=500))
    assert verdict(rec(uid="model.p.customers", rows=10), history)[0] == "allow"
    assert verdict(rec(uid="model.p.orders", rows=900), history)[0] == "allow"


def test_incremental_only_compares_same_kind():
    full = [rec(inv=f"f{i}", rows=10_000, kind="full") for i in range(3)]
    inc = [rec(inv=f"i{i}", rows=100, kind="incremental") for i in range(3)]
    # a normal incremental batch is tiny next to a full refresh, that's fine
    assert verdict(rec(rows=95, kind="incremental"), full + inc)[0] == "allow"
    # but small against other incremental runs is a drop
    assert verdict(rec(rows=50, kind="incremental"), full + inc)[1] == "flag_row_drop"
    # and a full refresh is only held to other full refreshes
    assert verdict(rec(rows=9_000, kind="full"), full + inc)[0] == "allow"


def test_row_window_is_last_seven():
    old = [rec(inv=f"o{i}", rows=100_000) for i in range(5)]
    recent = [rec(inv=f"r{i}", rows=100) for i in range(7)]
    assert verdict(rec(rows=90), old + recent)[0] == "allow"


def test_missing_catalog_skips_schema_check():
    history = [rec(inv="i0", cols="c1")]
    v, rule, out = verdict(rec(cols=None), history, has_catalog=False)
    assert "schema=skipped" in out
    assert v == "allow"


def test_failed_test_blocks():
    assert verdict(rec(rtype="test", status="fail"))[:2] == ("block", "block_failed_test")
    assert verdict(rec(rtype="test", status="error"))[:2] == ("block", "block_failed_test")


def test_warn_test_is_recorded_but_never_blocks():
    v, rule, out = verdict(rec(rtype="test", status="warn"))
    assert "test=warn" in out
    assert v == "allow" and rule is None


def test_row_drop_flags():
    history = [rec(inv=f"i{i}", rows=r) for i, r in enumerate([100, 110, 90])]
    assert verdict(rec(rows=69), history)[:2] == ("flag", "flag_row_drop")
    assert verdict(rec(rows=70), history)[0] == "allow"


def test_row_drop_with_new_sql_is_code_change():
    history = [rec(inv=f"i{i}", rows=100, sql="old") for i in range(3)]
    assert verdict(rec(rows=10, sql="new"), history)[:2] == ("flag", "flag_code_change")


def test_rows_null_never_flags():
    history = [rec(inv=f"i{i}", rows=100) for i in range(3)]
    assert verdict(rec(rows=None), history)[0] == "allow"


def test_schema_change_flags():
    history = [rec(inv="i0", cols="c1")]
    assert verdict(rec(cols="c2"), history)[:2] == ("flag", "flag_schema_change")
    assert verdict(rec(cols="c1"), history)[0] == "allow"


@pytest.mark.parametrize("status", ["fail", "error"])
def test_failed_test_wins_over_flags(status):
    history = [rec(rtype="test", inv="i0", cols="c1")]
    assert verdict(rec(rtype="test", status=status, cols="c2"), history)[0] == "block"
