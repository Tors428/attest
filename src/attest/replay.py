"""replay recorded decisions against a candidate policy.

the flow is: verify the chain from genesis up to the last record, check every
stored payload against the hashes the chain signed, then run the candidate
policy over each payload and diff it against the signed verdict. the result is
a report that is itself signed, so it can be handed to someone as evidence.
"""

import base64
import hashlib
import json
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from attest.chain import GENESIS_PREV_HASH, ChainEntry, ChainInputs, now_utc, verify_entry
from attest.dsl import PolicyDSL
from attest.hashing import sha256_bytes
from attest.matcher import enforce

REPORT_KIND = "attest.replay_report"
REPORT_FORMAT = 1

# transform still delivers an output, so for flip purposes it counts as allowed
ALLOWED = {"allow", "transform"}


class ReplayRefused(Exception):
    def __init__(self, seq: int | None, reason: str):
        super().__init__(f"seq {seq}: {reason}" if seq is not None else reason)
        self.seq = seq
        self.reason = reason


@dataclass
class ReplayRecord:
    seq: int
    inputs: ChainInputs
    entry: ChainEntry
    policy_name: str
    policy_dsl: dict
    input_text: str | None
    raw_output_text: str | None

    @property
    def verdict(self) -> str:
        return self.inputs.verdict

    @property
    def rule(self) -> str | None:
        return self.inputs.reasons.get("matched_rule_id")


@dataclass
class ChainCheck:
    entries_checked: int
    head_seq: int | None
    head_entry_hash: bytes


@dataclass
class ReplayResult:
    replayed: int = 0
    unchanged: int = 0
    skipped_no_payload: int = 0
    skipped_other_policy: int = 0
    baseline_mismatch: list[int] = field(default_factory=list)
    changes: list[dict] = field(default_factory=list)
    baseline_versions: Counter = field(default_factory=Counter)
    evaluate_s: float = 0.0


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def canonical_json(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def verify_chain(records: list[ReplayRecord], public_key: bytes) -> ChainCheck:
    """records must start at the first entry of the chain, ordered by seq."""
    expected_prev = GENESIS_PREV_HASH
    for r in records:
        if r.entry.prev_hash != expected_prev:
            raise ReplayRefused(r.seq, "prev_hash does not match preceding entry_hash")
        if not verify_entry(r.inputs, r.entry, public_key):
            raise ReplayRefused(r.seq, "hash or signature mismatch, entry has been tampered with")
        expected_prev = r.entry.entry_hash
    return ChainCheck(
        entries_checked=len(records),
        head_seq=records[-1].seq if records else None,
        head_entry_hash=expected_prev,
    )


def check_payload(r: ReplayRecord) -> bool:
    """False if there's nothing to replay. raises if the payload doesn't match the chain."""
    if r.input_text is None or r.raw_output_text is None or r.inputs.raw_output_hash is None:
        return False
    if sha256_bytes(r.input_text) != r.inputs.input_hash:
        raise ReplayRefused(r.seq, "stored input does not match the signed input_hash")
    if sha256_bytes(r.raw_output_text) != r.inputs.raw_output_hash:
        raise ReplayRefused(r.seq, "stored output does not match the signed raw_output_hash")
    return True


def classify(old_verdict: str, new_verdict: str) -> str:
    if old_verdict in ALLOWED and new_verdict == "block":
        return "allow_to_block"
    if old_verdict == "block" and new_verdict in ALLOWED:
        return "block_to_allow"
    if old_verdict != new_verdict:
        return "verdict_changed"
    return "rule_changed"


def replay(
    records: list[ReplayRecord],
    candidate: PolicyDSL,
    from_seq: int,
    to_seq: int,
) -> ReplayResult:
    res = ReplayResult()
    baseline_cache: dict[tuple[str, int], PolicyDSL] = {}

    t0 = time.perf_counter()
    for r in records:
        if r.seq < from_seq or r.seq > to_seq:
            continue
        if r.policy_name != candidate.name:
            res.skipped_other_policy += 1
            continue
        if not check_payload(r):
            res.skipped_no_payload += 1
            continue

        key = (r.policy_name, r.inputs.policy_version)
        baseline = baseline_cache.get(key)
        if baseline is None:
            baseline = baseline_cache[key] = PolicyDSL.model_validate(r.policy_dsl)
        res.baseline_versions[r.inputs.policy_version] += 1

        # the old policy should reproduce the signed verdict exactly. if it
        # doesn't, the matcher changed underneath us and the diff can't be trusted
        again = enforce(baseline, r.input_text, r.raw_output_text)
        if again.verdict != r.verdict or again.matched_rule_id != r.rule:
            res.baseline_mismatch.append(r.seq)

        new = enforce(candidate, r.input_text, r.raw_output_text)
        res.replayed += 1

        if new.verdict == r.verdict and new.matched_rule_id == r.rule:
            res.unchanged += 1
            continue

        kind = classify(r.verdict, new.verdict)
        # the rule responsible: the one that now fires, or for a block that went
        # away, the old rule that stopped firing
        cause = new.matched_rule_id if new.verdict == "block" else (r.rule or new.matched_rule_id)
        res.changes.append(
            {
                "seq": r.seq,
                "decision_id": str(r.inputs.decision_id),
                "kind": kind,
                "old_verdict": r.verdict,
                "new_verdict": new.verdict,
                "old_rule": r.rule,
                "new_rule": new.matched_rule_id,
                "cause_rule": cause,
                "new_reason": new.reason,
                "baseline_policy_version": r.inputs.policy_version,
            }
        )
    res.evaluate_s = time.perf_counter() - t0
    return res


def build_report(
    *,
    candidate: PolicyDSL,
    from_seq: int,
    to_seq: int,
    chain: ChainCheck,
    result: ReplayResult,
    timing: dict,
    generated_at: datetime | None = None,
) -> dict:
    kinds = Counter(c["kind"] for c in result.changes)
    by_rule = Counter(c["cause_rule"] or "(default)" for c in result.changes)
    candidate_dsl = candidate.model_dump()
    return {
        "kind": REPORT_KIND,
        "format": REPORT_FORMAT,
        "generated_at": (generated_at or now_utc()).isoformat(),
        "range": {"from_seq": from_seq, "to_seq": to_seq},
        "chain": {
            "verified_from_seq": 1 if chain.entries_checked else None,
            "verified_to_seq": chain.head_seq,
            "entries_checked": chain.entries_checked,
            "head_entry_hash_b64": b64(chain.head_entry_hash),
        },
        "baseline": {
            "policy_name": candidate.name,
            "versions": {str(v): n for v, n in sorted(result.baseline_versions.items())},
        },
        "candidate": {
            "policy_name": candidate.name,
            "version": candidate.version,
            "dsl_sha256_b64": b64(hashlib.sha256(canonical_json(candidate_dsl)).digest()),
            "dsl": candidate_dsl,
        },
        "summary": {
            "replayed": result.replayed,
            "unchanged": result.unchanged,
            "changed": len(result.changes),
            "allow_to_block": kinds["allow_to_block"],
            "block_to_allow": kinds["block_to_allow"],
            "verdict_changed": kinds["verdict_changed"],
            "rule_changed": kinds["rule_changed"],
            "skipped_no_payload": result.skipped_no_payload,
            "skipped_other_policy": result.skipped_other_policy,
            "baseline_mismatch": len(result.baseline_mismatch),
        },
        "by_rule": dict(sorted(by_rule.items())),
        "baseline_mismatch_seqs": result.baseline_mismatch[:100],
        "changes": result.changes,
        "timing": timing,
    }


def key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def sign_report(report: dict, private_key: bytes) -> dict:
    digest = hashlib.sha256(canonical_json(report)).digest()
    priv = Ed25519PrivateKey.from_private_bytes(private_key)
    pub = priv.public_key().public_bytes_raw()
    return {
        "report": report,
        "signature": {
            "alg": "ed25519",
            "report_sha256_b64": b64(digest),
            "signature_b64": b64(priv.sign(digest)),
            "key_id": key_id(pub),
        },
    }


def verify_report(envelope: dict, public_key: bytes) -> tuple[bool, str]:
    sig = envelope.get("signature") or {}
    if sig.get("alg") != "ed25519":
        return False, "unsupported or missing signature alg"
    digest = hashlib.sha256(canonical_json(envelope.get("report"))).digest()
    if b64(digest) != sig.get("report_sha256_b64"):
        return False, "report body does not match signed digest"
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            base64.b64decode(sig["signature_b64"]), digest
        )
    except (InvalidSignature, KeyError, ValueError):
        return False, "signature does not verify with this key"
    return True, "ok"
