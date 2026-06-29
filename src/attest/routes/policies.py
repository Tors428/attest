from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from attest.db import SessionLocal
from attest.dsl import PolicyDSL
from attest.models import Policy

router = APIRouter(prefix="/v1/policies", tags=["policies"])


async def get_session() -> AsyncSession:
    async with SessionLocal() as session:
        yield session


class PolicyCreate(BaseModel):
    dsl: PolicyDSL


class PolicyRead(BaseModel):
    id: UUID
    name: str
    version: int
    dsl: dict

    class Config:
        from_attributes = True


@router.post("", status_code=status.HTTP_201_CREATED, response_model=PolicyRead)
async def create_policy(payload: PolicyCreate, session: AsyncSession = Depends(get_session)):
    # latest version for this name, +1
    result = await session.execute(
        select(Policy.version)
        .where(Policy.name == payload.dsl.name)
        .order_by(Policy.version.desc())
        .limit(1)
    )
    latest = result.scalar()
    next_version = (latest or 0) + 1

    if payload.dsl.version != next_version:
        raise HTTPException(
            status_code=409,
            detail=f"version mismatch: next version for '{payload.dsl.name}' is {next_version}, got {payload.dsl.version}",
        )

    policy = Policy(
        name=payload.dsl.name,
        version=payload.dsl.version,
        dsl=payload.dsl.model_dump(),
    )
    session.add(policy)
    await session.commit()
    await session.refresh(policy)
    return policy


@router.get("", response_model=list[PolicyRead])
async def list_policies(session: AsyncSession = Depends(get_session)):
    # latest version of each named policy
    result = await session.execute(
        select(Policy).order_by(Policy.name, Policy.version.desc())
    )
    rows = result.scalars().all()
    seen = set()
    out = []
    for row in rows:
        if row.name in seen:
            continue
        seen.add(row.name)
        out.append(row)
    return out


@router.get("/{name}", response_model=PolicyRead)
async def get_policy(name: str, session: AsyncSession = Depends(get_session)):
    result = await session.execute(
        select(Policy)
        .where(Policy.name == name)
        .order_by(Policy.version.desc())
        .limit(1)
    )
    policy = result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(status_code=404, detail=f"no policy named '{name}'")
    return policy


@router.get("/{name}/{version}", response_model=PolicyRead)
async def get_policy_version(
    name: str, version: int, session: AsyncSession = Depends(get_session)
):
    result = await session.execute(
        select(Policy).where(Policy.name == name, Policy.version == version)
    )
    policy = result.scalar_one_or_none()
    if policy is None:
        raise HTTPException(
            status_code=404, detail=f"no policy '{name}' at version {version}"
        )
    return policy