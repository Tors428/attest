import time
from uuid import UUID, uuid4

import structlog
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from attest.config import settings
from attest.db import SessionLocal
from attest.dsl import PolicyDSL
from attest.ledger import append_decision, lock_chain
from attest.llm import generate
from attest.matcher import enforce as run_policy
from attest.metrics import (
    chain_write_latency_seconds,
    enforce_latency_seconds,
    enforce_requests,
    llm_latency_seconds,
)
from attest.models import Policy

router = APIRouter(prefix="/v1", tags=["enforce"])
log = structlog.get_logger("attest.enforce")


async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session


class EnforceRequest(BaseModel):
    policy_name: str
    input: str


class EnforceResponse(BaseModel):
    decision_id: UUID
    verdict: str
    output: str
    matched_rule_id: str | None
    reason: str
    latency_ms: int


@router.post("/enforce", response_model=EnforceResponse)
async def enforce_endpoint(
    payload: EnforceRequest,
    session: AsyncSession = Depends(get_session),
):
    request_id = str(uuid4())
    structlog.contextvars.bind_contextvars(
        request_id=request_id, policy_name=payload.policy_name
    )
    t0 = time.perf_counter()

    # 1. fetch latest policy by name
    result = await session.execute(
        select(Policy)
        .where(Policy.name == payload.policy_name)
        .order_by(Policy.version.desc())
        .limit(1)
    )
    policy_row = result.scalar_one_or_none()
    if policy_row is None:
        log.info("policy_not_found")
        raise HTTPException(404, f"no policy named '{payload.policy_name}'")

    policy_dsl = PolicyDSL.model_validate(policy_row.dsl)

    # 2. call the LLM (instrumented)
    t_llm = time.perf_counter()
    llm_output = await generate(payload.input)
    llm_latency_seconds.observe(time.perf_counter() - t_llm)

    # 3. deterministic enforcement
    decision = run_policy(policy_dsl, payload.input, llm_output)

    latency_ms = int((time.perf_counter() - t0) * 1000)

    # 4. write decision + audit entry — advisory lock keeps the chain linear
    t_chain = time.perf_counter()
    try:
        await lock_chain(session)
        decision_row = await append_decision(
            session,
            policy_row,
            payload.input,
            llm_output,
            decision,
            latency_ms,
            settings.signing_key_bytes,
            store_payload=settings.attest_store_payloads,
        )
        await session.commit()
    except Exception:
        await session.rollback()
        raise
    finally:
        chain_write_latency_seconds.observe(time.perf_counter() - t_chain)
    decision_id = decision_row.id

    enforce_latency_seconds.observe(time.perf_counter() - t0)
    enforce_requests.labels(verdict=decision.verdict).inc()

    log.info(
        "enforce_done",
        decision_id=str(decision_id),
        verdict=decision.verdict,
        matched_rule_id=decision.matched_rule_id,
        latency_ms=latency_ms,
    )

    return EnforceResponse(
        decision_id=decision_row.id,
        verdict=decision.verdict,
        output=decision.output,
        matched_rule_id=decision.matched_rule_id,
        reason=decision.reason,
        latency_ms=latency_ms,
    )