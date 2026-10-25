from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from attest.db import SessionLocal
from attest.dbt_runs import POLICY_NAME, group_runs, nodes
from attest.models import AuditEntry, Decision, DecisionPayload, Policy
from attest.replay import b64

router = APIRouter(prefix="/v1/dbt", tags=["dbt"])


async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session


class RunSummary(BaseModel):
    invocation_id: str
    started_at: str
    first_seq: int
    total: int
    counts: dict[str, int]


class Ref(BaseModel):
    unique_id: str
    seq: int | None


class Node(BaseModel):
    seq: int
    unique_id: str
    resource_type: str | None
    status: str | None
    rows: int | None
    sql_sha256: str | None
    columns_sha256: str | None
    verdict: str
    matched_rule_id: str | None
    reason: str | None
    signals: str | None
    refs: list[Ref]


async def _nodes(session: AsyncSession) -> list[dict]:
    result = await session.execute(
        select(
            AuditEntry.seq,
            AuditEntry.signed_at,
            AuditEntry.entry_hash,
            Decision.verdict,
            Decision.reasons,
            DecisionPayload.input_text,
            DecisionPayload.raw_output_text,
        )
        .join(Decision, AuditEntry.decision_id == Decision.id)
        .join(Policy, Decision.policy_id == Policy.id)
        .join(DecisionPayload, DecisionPayload.decision_id == Decision.id)
        .where(Policy.name == POLICY_NAME)
        .order_by(AuditEntry.seq.asc())
    )
    return nodes(
        (seq, signed_at.isoformat(), b64(h), verdict.value, reasons, text, out)
        for seq, signed_at, h, verdict, reasons, text, out in result.all()
    )


@router.get("/runs", response_model=list[RunSummary])
async def list_runs(session: AsyncSession = Depends(get_session)):
    return group_runs(await _nodes(session))


@router.get("/runs/{invocation_id}", response_model=list[Node])
async def get_run(invocation_id: str, session: AsyncSession = Depends(get_session)):
    run = [n for n in await _nodes(session) if n["invocation_id"] == invocation_id]
    if not run:
        raise HTTPException(404, f"no dbt run {invocation_id}")
    return run
