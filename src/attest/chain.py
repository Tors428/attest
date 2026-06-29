import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from uuid import UUID

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

GENESIS_PREV_HASH = b"\x00" * 32


@dataclass(frozen=True)
class ChainInputs:
    decision_id: UUID
    input_hash: bytes
    output_hash: bytes
    verdict: str
    reasons: dict
    signed_at: datetime


@dataclass(frozen=True)
class ChainEntry:
    prev_hash: bytes
    entry_hash: bytes
    signature: bytes
    signed_at: datetime


def _canonical_reasons(reasons: dict) -> bytes:
    # sort_keys for deterministic serialization across runs/processes
    return json.dumps(reasons, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_entry_hash(prev_hash: bytes, inputs: ChainInputs) -> bytes:
    if len(prev_hash) != 32:
        raise ValueError(f"prev_hash must be 32 bytes, got {len(prev_hash)}")

    h = hashlib.sha256()
    h.update(prev_hash)
    h.update(inputs.decision_id.bytes)
    h.update(inputs.input_hash)
    h.update(inputs.output_hash)
    h.update(inputs.verdict.encode("utf-8"))
    h.update(_canonical_reasons(inputs.reasons))
    h.update(inputs.signed_at.isoformat().encode("utf-8"))
    return h.digest()


def sign_entry(entry_hash: bytes, private_key_bytes: bytes) -> bytes:
    priv = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return priv.sign(entry_hash)


def build_entry(
    prev_hash: bytes,
    inputs: ChainInputs,
    private_key_bytes: bytes,
) -> ChainEntry:
    entry_hash = compute_entry_hash(prev_hash, inputs)
    signature = sign_entry(entry_hash, private_key_bytes)
    return ChainEntry(
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        signature=signature,
        signed_at=inputs.signed_at,
    )


def verify_entry(
    inputs: ChainInputs,
    entry: ChainEntry,
    public_key_bytes: bytes,
) -> bool:
    expected_hash = compute_entry_hash(entry.prev_hash, inputs)
    if expected_hash != entry.entry_hash:
        return False

    pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    try:
        pub.verify(entry.signature, entry.entry_hash)
    except InvalidSignature:
        return False
    return True


def now_utc() -> datetime:
    return datetime.now(timezone.utc)