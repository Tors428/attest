import json

from attest.dbt_runs import group_runs, nodes


def row(seq, inv, uid, verdict, refs=None, rule=None):
    rec = {"invocation_id": inv, "unique_id": uid, "status": "success", "rows": 10}
    text = json.dumps({**rec, "refs": refs or {}})
    reasons = {"matched_rule_id": rule, "reason": "x" if rule else "default"}
    return (seq, f"2026-01-01T00:00:0{seq}", f"h{seq}", verdict, reasons, text, "status=success")


ROWS = [
    row(1, "a", "seed.raw_orders", "allow"),
    row(2, "a", "model.stg_orders", "allow", {"seed.raw_orders": "h1"}),
    row(3, "b", "seed.raw_orders", "allow"),
    row(4, "b", "model.stg_orders", "flag", {"seed.raw_orders": "h3"}, "flag_row_drop"),
    row(5, "b", "test.unique_orders", "block", {"model.stg_orders": "h4"}, "block_failed_test"),
]


def test_runs_are_grouped_newest_first():
    runs = group_runs(nodes(ROWS))
    assert [r["invocation_id"] for r in runs] == ["b", "a"]
    assert runs[0]["counts"] == {"allow": 1, "flag": 1, "block": 1}
    assert runs[0]["total"] == 3
    assert runs[0]["started_at"] == "2026-01-01T00:00:03"
    assert runs[1]["counts"] == {"allow": 2}


def test_refs_point_at_upstream_seq():
    out = nodes(ROWS)
    assert out[3]["refs"] == [{"unique_id": "seed.raw_orders", "seq": 3}]
    assert out[4]["matched_rule_id"] == "block_failed_test"


def test_unknown_ref_and_bad_payload():
    bad = (2, "t", "h2", "allow", {}, "not json", "")
    out = nodes([row(1, "a", "model.x", "allow", {"model.gone": "nope"}), bad])
    assert len(out) == 1
    assert out[0]["refs"] == [{"unique_id": "model.gone", "seq": None}]
