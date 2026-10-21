from uuid import uuid4

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from attest.chain import GENESIS_PREV_HASH, ChainEntry, ChainInputs, build_entry, now_utc
from attest.hashing import sha256_bytes
from attest.matcher import Decision as MatchDecision
from attest.models import AuditEntry, Decision, DecisionPayload, Policy, Verdict

AUDIT_CHAIN_LOCK_KEY = 0xA77E57


def chain_inputs_for(decision: Decision, signed_at) -> ChainInputs:
    # v1 rows have no raw_output_hash and hash the old way
    v2 = decision.raw_output_hash is not None
    return ChainInputs(
        decision_id=decision.id,
        input_hash=decision.input_hash,
        output_hash=decision.output_hash,
        verdict=decision.verdict.value,
        reasons=decision.reasons or {},
        signed_at=signed_at,
        raw_output_hash=decision.raw_output_hash,
        policy_id=decision.policy_id if v2 else None,
        policy_version=decision.policy_version if v2 else None,
    )


def entry_of(row: AuditEntry) -> ChainEntry:
    return ChainEntry(
        prev_hash=row.prev_hash,
        entry_hash=row.entry_hash,
        signature=row.signature,
        signed_at=row.signed_at,
    )


async def lock_chain(session: AsyncSession) -> None:
    await session.execute(text("select pg_advisory_xact_lock(:k)"), {"k": AUDIT_CHAIN_LOCK_KEY})


async def append_decision(
    session: AsyncSession,
    policy_row: Policy,
    input_text: str,
    raw_output: str,
    decision: MatchDecision,
    latency_ms: int,
    signing_key: bytes,
    store_payload: bool = True,
) -> Decision:
    """write decision + payload + chain link. caller holds the chain lock and commits."""
    decision_row = Decision(
        id=uuid4(),
        policy_id=policy_row.id,
        policy_version=policy_row.version,
        input_hash=sha256_bytes(input_text),
        output_hash=sha256_bytes(decision.output),
        raw_output_hash=sha256_bytes(raw_output),
        verdict=Verdict(decision.verdict),
        reasons={
            "matched_rule_id": decision.matched_rule_id,
            "reason": decision.reason,
        },
        latency_ms=latency_ms,
    )
    session.add(decision_row)
    if store_payload:
        session.add(
            DecisionPayload(
                decision_id=decision_row.id,
                input_text=input_text,
                raw_output_text=raw_output,
            )
        )
    await session.flush()

    prev_result = await session.execute(
        select(AuditEntry.entry_hash).order_by(AuditEntry.seq.desc()).limit(1)
    )
    prev_hash = prev_result.scalar() or GENESIS_PREV_HASH

    entry = build_entry(prev_hash, chain_inputs_for(decision_row, now_utc()), signing_key)
    session.add(
        AuditEntry(
            decision_id=decision_row.id,
            prev_hash=entry.prev_hash,
            entry_hash=entry.entry_hash,
            signature=entry.signature,
            signed_at=entry.signed_at,
        )
    )
    await session.flush()
    return decision_row
