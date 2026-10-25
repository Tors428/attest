import base64
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from attest.chain import verify_entry
from attest.cli import _load_records
from attest.config import settings
from attest.db import SessionLocal
from attest.ledger import chain_inputs_for, entry_of
from attest.models import AuditEntry, Decision, DecisionPayload
from attest.verify import report

router = APIRouter(prefix="/v1/audit", tags=["audit"])


async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


class AuditRow(BaseModel):
    seq: int
    decision_id: UUID
    verdict: str
    matched_rule_id: str | None
    policy_id: UUID
    policy_version: int
    latency_ms: int
    prev_hash_b64: str
    entry_hash_b64: str
    signature_b64: str
    signed_at: str
    created_at: str


class PayloadRead(BaseModel):
    decision_id: UUID
    input_text: str
    raw_output_text: str


class VerifyResult(BaseModel):
    entries_checked: int
    valid: bool
    failed_at_seq: int | None = None
    failure_reason: str | None = None


class FullVerify(BaseModel):
    entries_checked: int
    valid: bool
    problems: list[dict]


@router.get("", response_model=list[AuditRow])
async def list_audit(
    limit: int = Query(50, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(AuditEntry, Decision)
        .join(Decision, AuditEntry.decision_id == Decision.id)
        .order_by(AuditEntry.seq.desc())
        .limit(limit)
    )
    rows = result.all()
    return [
        AuditRow(
            seq=entry.seq,
            decision_id=decision.id,
            verdict=decision.verdict.value,
            matched_rule_id=(decision.reasons or {}).get("matched_rule_id"),
            policy_id=decision.policy_id,
            policy_version=decision.policy_version,
            latency_ms=decision.latency_ms,
            prev_hash_b64=_b64(entry.prev_hash),
            entry_hash_b64=_b64(entry.entry_hash),
            signature_b64=_b64(entry.signature),
            signed_at=entry.signed_at.isoformat(),
            created_at=decision.created_at.isoformat(),
        )
        for entry, decision in rows
    ]


@router.get("/verify", response_model=VerifyResult)
async def verify_chain(session: AsyncSession = Depends(get_session)):
    result = await session.execute(
        select(AuditEntry, Decision)
        .join(Decision, AuditEntry.decision_id == Decision.id)
        .order_by(AuditEntry.seq.asc())
    )
    rows = result.all()

    pub = settings.verify_key_bytes
    checked = 0
    expected_prev = b"\x00" * 32

    for entry, decision in rows:
        if entry.prev_hash != expected_prev:
            return VerifyResult(
                entries_checked=checked,
                valid=False,
                failed_at_seq=entry.seq,
                failure_reason="prev_hash does not match preceding entry_hash",
            )

        inputs = chain_inputs_for(decision, entry.signed_at)
        candidate = entry_of(entry)

        if not verify_entry(inputs, candidate, pub):
            return VerifyResult(
                entries_checked=checked,
                valid=False,
                failed_at_seq=entry.seq,
                failure_reason="hash or signature mismatch — entry has been tampered with",
            )

        expected_prev = entry.entry_hash
        checked += 1

    return VerifyResult(entries_checked=checked, valid=True)


@router.get("/verify/full", response_model=FullVerify)
async def verify_full(session: AsyncSession = Depends(get_session)):
    # unlike /verify this keeps going and says what each bad entry fed into
    records = await _load_records(session, 2**62)
    problems = report(records, settings.verify_key_bytes)
    return FullVerify(entries_checked=len(records), valid=not problems, problems=problems)


@router.get("/{decision_id}", response_model=AuditRow)
async def get_audit(
    decision_id: UUID,
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(AuditEntry, Decision)
        .join(Decision, AuditEntry.decision_id == Decision.id)
        .where(Decision.id == decision_id)
    )
    row = result.one_or_none()
    if row is None:
        raise HTTPException(404, f"no audit entry for decision {decision_id}")
    entry, decision = row
    return AuditRow(
        seq=entry.seq,
        decision_id=decision.id,
        verdict=decision.verdict.value,
        matched_rule_id=(decision.reasons or {}).get("matched_rule_id"),
        policy_id=decision.policy_id,
        policy_version=decision.policy_version,
        latency_ms=decision.latency_ms,
        prev_hash_b64=_b64(entry.prev_hash),
        entry_hash_b64=_b64(entry.entry_hash),
        signature_b64=_b64(entry.signature),
        signed_at=entry.signed_at.isoformat(),
        created_at=decision.created_at.isoformat(),
    )


@router.get("/{decision_id}/payload", response_model=PayloadRead)
async def get_payload(
    decision_id: UUID,
    session: AsyncSession = Depends(get_session),
):
    payload = await session.get(DecisionPayload, decision_id)
    if payload is None:
        raise HTTPException(404, f"no stored payload for decision {decision_id}")
    return PayloadRead(
        decision_id=payload.decision_id,
        input_text=payload.input_text,
        raw_output_text=payload.raw_output_text,
    )
