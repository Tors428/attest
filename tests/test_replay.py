import uuid
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from attest.chain import GENESIS_PREV_HASH, ChainInputs, build_entry, now_utc, verify_entry
from attest.hashing import sha256_bytes
from attest.loader import load_from_file
from attest.matcher import enforce
from attest.replay import (
    ReplayRecord,
    ReplayRefused,
    build_report,
    replay,
    sign_report,
    verify_chain,
    verify_report,
)

V1 = load_from_file("policies/pii_redaction.yaml")
V2 = load_from_file("policies/pii_redaction_v2.yaml")
POLICY_ID = uuid.uuid4()

TRAFFIC = [
    ("hi", "hello there"),
    ("ssn?", "it's 123-45-6789"),
    ("ssn spaced?", "it's 123 45 6789"),
    ("order?", "your order 482915736 shipped"),
    ("email?", "write to jane@example.com"),
]


def _raw(priv) -> bytes:
    return priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture
def keys():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw()
    return _raw(priv), pub


def make_records(priv, traffic=TRAFFIC, policy=V1, store_payload=True):
    records, prev = [], GENESIS_PREV_HASH
    for i, (inp, out) in enumerate(traffic, start=1):
        d = enforce(policy, inp, out)
        inputs = ChainInputs(
            decision_id=uuid.uuid4(),
            input_hash=sha256_bytes(inp),
            output_hash=sha256_bytes(d.output),
            verdict=d.verdict,
            reasons={"matched_rule_id": d.matched_rule_id, "reason": d.reason},
            signed_at=now_utc(),
            raw_output_hash=sha256_bytes(out),
            policy_id=POLICY_ID,
            policy_version=policy.version,
        )
        entry = build_entry(prev, inputs, priv)
        records.append(
            ReplayRecord(
                seq=i,
                inputs=inputs,
                entry=entry,
                policy_name=policy.name,
                policy_dsl=policy.model_dump(),
                input_text=inp if store_payload else None,
                raw_output_text=out if store_payload else None,
            )
        )
        prev = entry.entry_hash
    return records


def test_v1_hash_unchanged_by_v2_fields(keys):
    priv, pub = keys
    base = make_records(priv)[0].inputs
    v1 = replace(base, raw_output_hash=None, policy_id=None, policy_version=None)
    entry = build_entry(GENESIS_PREV_HASH, v1, priv)
    assert verify_entry(v1, entry, pub)
    # dropping the v2 fields from a v2 entry must not verify
    v2_entry = build_entry(GENESIS_PREV_HASH, base, priv)
    assert not verify_entry(v1, v2_entry, pub)


def test_v2_binds_policy_version(keys):
    priv, pub = keys
    r = make_records(priv)[0]
    assert verify_entry(r.inputs, r.entry, pub)
    assert not verify_entry(replace(r.inputs, policy_version=99), r.entry, pub)


def test_tighter_ssn_rule_flips_spaced_ssn_and_order_number(keys):
    priv, pub = keys
    records = make_records(priv)
    verify_chain(records, pub)
    res = replay(records, V2, 1, len(records))

    assert res.replayed == 5
    assert res.baseline_mismatch == []
    flipped = {c["seq"]: c for c in res.changes}
    assert set(flipped) == {3, 4}
    for seq in (3, 4):
        assert flipped[seq]["kind"] == "allow_to_block"
        assert flipped[seq]["cause_rule"] == "block_ssn"


def test_block_to_allow_names_the_rule_that_stopped_firing(keys):
    priv, pub = keys
    loose = V1.model_copy(update={"version": 3, "rules": V1.rules[1:]})
    res = replay(make_records(priv), loose, 1, 5)
    (c,) = res.changes
    assert c["kind"] == "block_to_allow"
    assert c["old_rule"] == "block_ssn"
    assert c["cause_rule"] == "block_ssn"


def test_range_limits_what_gets_replayed(keys):
    priv, _ = keys
    res = replay(make_records(priv), V2, 4, 5)
    assert res.replayed == 2
    assert [c["seq"] for c in res.changes] == [4]


def test_refuses_when_verdict_tampered(keys):
    priv, pub = keys
    records = make_records(priv)
    records[2].inputs = replace(records[2].inputs, verdict="block")
    with pytest.raises(ReplayRefused) as e:
        verify_chain(records, pub)
    assert e.value.seq == 3


def test_refuses_when_entry_deleted(keys):
    priv, pub = keys
    records = make_records(priv)
    del records[1]
    with pytest.raises(ReplayRefused) as e:
        verify_chain(records, pub)
    assert e.value.seq == 3


def test_refuses_when_payload_edited(keys):
    priv, pub = keys
    records = make_records(priv)
    records[1].raw_output_text = "it's fine, nothing here"
    verify_chain(records, pub)  # chain only holds hashes, so it still passes
    with pytest.raises(ReplayRefused, match="raw_output_hash"):
        replay(records, V2, 1, 5)


def test_missing_payloads_are_skipped_not_guessed(keys):
    priv, _ = keys
    res = replay(make_records(priv, store_payload=False), V2, 1, 5)
    assert res.replayed == 0
    assert res.skipped_no_payload == 5


def test_other_policies_are_skipped(keys):
    priv, _ = keys
    other = V2.model_copy(update={"name": "something_else"})
    res = replay(make_records(priv), other, 1, 5)
    assert res.skipped_other_policy == 5


def test_baseline_mismatch_is_reported(keys):
    priv, pub = keys
    # sign a decision the v1 policy would never have produced
    records = make_records(priv, traffic=[("q", "123-45-6789")])
    r = records[0]
    r.inputs = replace(r.inputs, verdict="allow", reasons={"matched_rule_id": None, "reason": "x"})
    r.entry = build_entry(GENESIS_PREV_HASH, r.inputs, priv)
    verify_chain(records, pub)
    res = replay(records, V2, 1, 1)
    assert res.baseline_mismatch == [1]


def _report(priv, pub):
    records = make_records(priv)
    chain = verify_chain(records, pub)
    res = replay(records, V2, 1, 5)
    return build_report(
        candidate=V2, from_seq=1, to_seq=5, chain=chain, result=res, timing={"total_s": 0.01}
    )


def test_signed_report_roundtrip(keys):
    priv, pub = keys
    env = sign_report(_report(priv, pub), priv)
    assert verify_report(env, pub) == (True, "ok")
    assert env["report"]["summary"]["allow_to_block"] == 2
    assert env["report"]["by_rule"] == {"block_ssn": 2}


def test_editing_report_breaks_signature(keys):
    priv, pub = keys
    env = sign_report(_report(priv, pub), priv)
    env["report"]["summary"]["allow_to_block"] = 0
    ok, why = verify_report(env, pub)
    assert not ok and "digest" in why


def test_report_rejects_wrong_key(keys):
    priv, pub = keys
    env = sign_report(_report(priv, pub), priv)
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
    assert verify_report(env, other)[0] is False
