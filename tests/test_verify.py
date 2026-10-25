import json
import uuid
from dataclasses import replace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attest.chain import GENESIS_PREV_HASH, ChainInputs, build_entry, now_utc
from attest.hashing import sha256_bytes
from attest.replay import ReplayRecord, b64
from attest.verify import downstream, find_problems

POLICY_ID = uuid.uuid4()


def keys():
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return raw, priv.public_key().public_bytes_raw()


def build(priv, nodes):
    # nodes: [(name, [upstream names])] in run order
    records, latest, prev = [], {}, GENESIS_PREV_HASH
    for seq, (name, ups) in enumerate(nodes, start=1):
        text = json.dumps({"unique_id": name, "rows": 10, "refs": {u: latest.get(u) for u in ups}})
        inputs = ChainInputs(
            decision_id=uuid.uuid4(),
            input_hash=sha256_bytes(text),
            output_hash=sha256_bytes("ok"),
            verdict="allow",
            reasons={"matched_rule_id": None},
            signed_at=now_utc(),
            raw_output_hash=sha256_bytes("ok"),
            policy_id=POLICY_ID,
            policy_version=1,
        )
        entry = build_entry(prev, inputs, priv)
        records.append(ReplayRecord(seq, inputs, entry, "dbt_quality", {}, text, "ok"))
        latest[name] = b64(entry.entry_hash)
        prev = entry.entry_hash
    return records


DAG = [
    ("seed.raw_orders", []),
    ("seed.raw_customers", []),
    ("model.stg_orders", ["seed.raw_orders"]),
    ("model.stg_customers", ["seed.raw_customers"]),
    ("model.customers", ["model.stg_orders", "model.stg_customers"]),
    ("test.unique_orders", ["model.stg_orders"]),
]


def test_clean_chain_has_no_problems():
    priv, pub = keys()
    assert find_problems(build(priv, DAG), pub) == []


def test_edited_row_count_is_caught_with_everything_downstream():
    priv, pub = keys()
    records = build(priv, DAG)
    records[0].input_text = records[0].input_text.replace('"rows": 10', '"rows": 9999')

    problems = find_problems(records, pub)
    assert [p.seq for p in problems] == [1]
    assert "input_hash" in problems[0].reason
    # stg_orders, customers (through stg_orders) and the test. not the customers side
    assert downstream(records, [1]) == {1: [3, 5, 6]}


def test_keeps_going_after_first_problem():
    priv, pub = keys()
    records = build(priv, DAG)
    records[1].input_text += " "
    records[3].inputs = replace(records[3].inputs, verdict="block")
    assert [p.seq for p in find_problems(records, pub)] == [2, 4]


def test_deleted_entry_breaks_the_next_link():
    priv, pub = keys()
    records = build(priv, DAG)
    del records[2]
    problems = find_problems(records, pub)
    assert problems[0].seq == 4
    assert "prev_hash" in problems[0].reason


def test_records_without_refs_have_no_downstream():
    priv, _ = keys()
    records = build(priv, DAG)
    records[0].input_text = "not json"
    assert downstream(records, [6]) == {6: []}
