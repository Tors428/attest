from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from attest.config import settings
from attest.db import SessionLocal
from attest.models import ReplayReport
from attest.replay import b64, key_id, verify_report

router = APIRouter(prefix="/v1/replays", tags=["replays"])


async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session


class ReplaySummary(BaseModel):
    id: UUID
    policy_name: str
    candidate_version: int
    from_seq: int
    to_seq: int
    summary: dict
    created_at: str


class ReplayVerify(BaseModel):
    valid: bool
    reason: str
    key_id: str


def _envelope(row: ReplayReport) -> dict:
    return {
        "report": row.report,
        "signature": {
            "alg": "ed25519",
            "report_sha256_b64": b64(row.report_sha256),
            "signature_b64": b64(row.signature),
            "key_id": key_id(settings.verify_key_bytes),
        },
    }


async def _get(session: AsyncSession, report_id: UUID) -> ReplayReport:
    row = await session.get(ReplayReport, report_id)
    if row is None:
        raise HTTPException(404, f"no replay report {report_id}")
    return row


@router.get("", response_model=list[ReplaySummary])
async def list_replays(
    limit: int = Query(20, ge=1, le=100),
    session: AsyncSession = Depends(get_session),
):
    result = await session.execute(
        select(ReplayReport).order_by(ReplayReport.created_at.desc()).limit(limit)
    )
    return [
        ReplaySummary(
            id=r.id,
            policy_name=r.policy_name,
            candidate_version=r.candidate_version,
            from_seq=r.from_seq,
            to_seq=r.to_seq,
            summary=r.report.get("summary", {}),
            created_at=r.created_at.isoformat(),
        )
        for r in result.scalars().all()
    ]


@router.get("/{report_id}")
async def get_replay(report_id: UUID, session: AsyncSession = Depends(get_session)):
    # returned as the same signed envelope the cli writes to disk
    return _envelope(await _get(session, report_id))


@router.get("/{report_id}/verify", response_model=ReplayVerify)
async def verify_replay(report_id: UUID, session: AsyncSession = Depends(get_session)):
    row = await _get(session, report_id)
    ok, why = verify_report(_envelope(row), settings.verify_key_bytes)
    return ReplayVerify(valid=ok, reason=why, key_id=key_id(settings.verify_key_bytes))
