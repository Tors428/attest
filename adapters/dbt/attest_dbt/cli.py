import argparse
import asyncio
import json
import sys
from collections import Counter
from pathlib import Path

import structlog
from sqlalchemy import select

from attest.loader import load_from_file
from attest.matcher import enforce
from attest.models import AuditEntry, Decision, DecisionPayload, Policy
from attest.replay import b64, canonical_json
from attest_dbt.artifacts import parse
from attest_dbt.checks import History

log = structlog.get_logger("attest.dbt")

DEFAULT_POLICY = Path(__file__).resolve().parent.parent / "policies" / "dbt_quality.yaml"


async def get_policy(session, dsl) -> Policy:
    row = (
        await session.execute(
            select(Policy).where(Policy.name == dsl.name, Policy.version == dsl.version)
        )
    ).scalar_one_or_none()
    if row is None:
        row = Policy(name=dsl.name, version=dsl.version, dsl=dsl.model_dump())
        session.add(row)
        await session.flush()
    return row


async def load_past(session, policy_name: str) -> list[tuple[dict, str]]:
    result = await session.execute(
        select(DecisionPayload.input_text, AuditEntry.entry_hash)
        .join(Decision, Decision.id == DecisionPayload.decision_id)
        .join(AuditEntry, AuditEntry.decision_id == Decision.id)
        .join(Policy, Policy.id == Decision.policy_id)
        .where(Policy.name == policy_name)
        .order_by(AuditEntry.seq)
    )
    return [(json.loads(text), b64(h)) for text, h in result.all()]


async def ingest(target_dir: str, policy_path: str) -> int:
    # settings reads .env from the cwd, so only touch it once we actually need the db
    from attest.config import settings
    from attest.db import SessionLocal, engine
    from attest.ledger import append_decision, lock_chain

    records, has_catalog = parse(target_dir)
    if not has_catalog:
        log.warning("catalog_missing", target_dir=target_dir, note="schema check skipped")
    dsl = load_from_file(policy_path)

    verdicts = Counter()
    hits = []
    skipped = 0
    async with SessionLocal() as session:
        async with session.begin():
            # take the lock before reading history so two ingests can't interleave
            await lock_chain(session)
            policy_row = await get_policy(session, dsl)
            history = History(await load_past(session, dsl.name))

            for rec in records:
                prepared = history.prepare(rec, has_catalog)
                if prepared is None:
                    skipped += 1
                    continue
                rec, out = prepared
                text = canonical_json(rec).decode("utf-8")
                d = enforce(dsl, text, out)
                row = await append_decision(
                    session, policy_row, text, out, d, 0, settings.signing_key_bytes
                )
                entry_hash = (
                    await session.execute(
                        select(AuditEntry.entry_hash).where(AuditEntry.decision_id == row.id)
                    )
                ).scalar_one()
                history.add(rec, b64(entry_hash))
                verdicts[d.verdict] += 1
                if d.matched_rule_id:
                    hits.append((rec["unique_id"], d.verdict, d.matched_rule_id))
    await engine.dispose()

    print(f"ingested {sum(verdicts.values())} records, skipped {skipped} already on the chain")
    for v, n in sorted(verdicts.items()):
        print(f"  {v:<6} {n}")
    for uid, v, rule in hits:
        print(f"  {v.upper():<6} {uid}  ({rule})")
    return 1 if verdicts["block"] else 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="attest-dbt")
    sub = p.add_subparsers(dest="cmd", required=True)
    i = sub.add_parser("ingest", help="record a dbt run on the attest chain")
    i.add_argument("target_dir")
    i.add_argument("--policy", default=str(DEFAULT_POLICY))
    args = p.parse_args(argv)
    return asyncio.run(ingest(args.target_dir, args.policy))


if __name__ == "__main__":
    sys.exit(main())
