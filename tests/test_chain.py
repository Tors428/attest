import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

from attest.chain import (
    GENESIS_PREV_HASH,
    ChainInputs,
    build_entry,
    compute_entry_hash,
    now_utc,
    verify_entry,
)
from attest.hashing import sha256_bytes


@pytest.fixture
def keypair():
    priv = Ed25519PrivateKey.generate()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


@pytest.fixture
def sample_inputs():
    return ChainInputs(
        decision_id=uuid.uuid4(),
        input_hash=sha256_bytes("hello"),
        output_hash=sha256_bytes("world"),
        verdict="allow",
        reasons={"matched": "no_rule"},
        signed_at=now_utc(),
    )


def test_entry_hash_is_32_bytes(sample_inputs):
    h = compute_entry_hash(GENESIS_PREV_HASH, sample_inputs)
    assert len(h) == 32


def test_entry_hash_is_deterministic(sample_inputs):
    h1 = compute_entry_hash(GENESIS_PREV_HASH, sample_inputs)
    h2 = compute_entry_hash(GENESIS_PREV_HASH, sample_inputs)
    assert h1 == h2


def test_reasons_dict_order_does_not_affect_hash(sample_inputs):
    a = ChainInputs(**{**sample_inputs.__dict__, "reasons": {"a": 1, "b": 2}})
    b = ChainInputs(**{**sample_inputs.__dict__, "reasons": {"b": 2, "a": 1}})
    assert compute_entry_hash(GENESIS_PREV_HASH, a) == compute_entry_hash(
        GENESIS_PREV_HASH, b
    )


def test_build_and_verify_roundtrip(keypair, sample_inputs):
    priv, pub = keypair
    entry = build_entry(GENESIS_PREV_HASH, sample_inputs, priv)
    assert verify_entry(sample_inputs, entry, pub) is True


def test_tampering_with_output_breaks_verify(keypair, sample_inputs):
    priv, pub = keypair
    entry = build_entry(GENESIS_PREV_HASH, sample_inputs, priv)
    tampered = ChainInputs(**{**sample_inputs.__dict__, "output_hash": sha256_bytes("evil")})
    assert verify_entry(tampered, entry, pub) is False


def test_tampering_with_verdict_breaks_verify(keypair, sample_inputs):
    priv, pub = keypair
    entry = build_entry(GENESIS_PREV_HASH, sample_inputs, priv)
    tampered = ChainInputs(**{**sample_inputs.__dict__, "verdict": "block"})
    assert verify_entry(tampered, entry, pub) is False


def test_wrong_public_key_breaks_verify(sample_inputs):
    priv1 = Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    priv2_pub = Ed25519PrivateKey.generate().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    entry = build_entry(GENESIS_PREV_HASH, sample_inputs, priv1)
    assert verify_entry(sample_inputs, entry, priv2_pub) is False


def test_chain_link_changes_when_prev_changes(sample_inputs):
    h1 = compute_entry_hash(GENESIS_PREV_HASH, sample_inputs)
    h2 = compute_entry_hash(b"\x01" * 32, sample_inputs)
    assert h1 != h2


def test_prev_hash_wrong_length_raises(sample_inputs):
    with pytest.raises(ValueError):
        compute_entry_hash(b"\x00" * 16, sample_inputs)