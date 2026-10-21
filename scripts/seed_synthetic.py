"""seed the audit chain with synthetic traffic, no llm calls.

every record goes through the same append_decision path as /v1/enforce, so the
chain, signatures and payloads are identical to real traffic. only the llm
output is made up. point DATABASE_URL at a scratch database, not prod.

usage: python scripts/seed_synthetic.py --n 5000 --seed 42
"""

import argparse
import asyncio
import random
import time

from sqlalchemy import func, select

from attest.config import settings
from attest.db import SessionLocal, engine
from attest.dsl import PolicyDSL
from attest.ledger import append_decision, lock_chain
from attest.loader import load_from_file
from attest.matcher import enforce
from attest.models import AuditEntry, Policy

FIRST = ["Maya", "Jordan", "Priya", "Luis", "Chen", "Amara", "Noah", "Sofia", "Ravi", "Elena"]
LAST = ["Patel", "Garcia", "Kim", "Okafor", "Nguyen", "Rossi", "Silva", "Cohen", "Ali", "Berg"]
DOMAINS = ["example.com", "mail.example.org", "corp.example.net"]
TOPICS = [
    ("octopuses", "Octopuses have three hearts and blue blood."),
    ("the moon", "The Moon is slowly drifting away from Earth, about 3.8 cm a year."),
    ("honey", "Honey found in ancient Egyptian tombs was still edible."),
    ("bananas", "Bananas are berries, but strawberries are not."),
    ("sharks", "Sharks existed before trees did."),
    ("venus", "A day on Venus is longer than its year."),
    ("tardigrades", "Tardigrades can survive the vacuum of space."),
    ("glass", "Glass is an amorphous solid, not a slow-moving liquid."),
]


def _name(rng):
    return f"{rng.choice(FIRST)} {rng.choice(LAST)}"


def _digits(rng, n):
    return "".join(str(rng.randint(0, 9)) for _ in range(n))


def _ssn(rng, sep):
    return f"{rng.randint(100, 899)}{sep}{rng.randint(10, 99)}{sep}{_digits(rng, 4)}"


def clean(rng):
    topic, fact = rng.choice(TOPICS)
    return f"Tell me a fun fact about {topic}.", fact


def email(rng):
    n = _name(rng)
    addr = f"{n.split()[0].lower()}.{n.split()[1].lower()}@{rng.choice(DOMAINS)}"
    return f"How do I reach {n}?", f"You can email {n.split()[0]} at {addr}."


def ssn_dashed(rng):
    n = _name(rng)
    return f"What's {n}'s SSN?", f"{n}'s SSN on file is {_ssn(rng, '-')}."


def ssn_spaced(rng):
    n = _name(rng)
    return f"Read me {n}'s tax ID.", f"The tax ID for {n} is {_ssn(rng, ' ')}."


def order_number(rng):
    return (
        "Where is my order?",
        f"Order {_digits(rng, 9)} shipped and should arrive in {rng.randint(2, 6)} days.",
    )


def phone(rng):
    return (
        "What's the support line?",
        f"Call us at ({rng.randint(200, 999)}) 555-{_digits(rng, 4)}, weekdays 9 to 5.",
    )


def ticket(rng):
    return (
        "Status of my ticket?",
        f"Ticket {_digits(rng, 4)}-{_digits(rng, 4)} is assigned and in progress.",
    )


def long_output(rng):
    _, fact = rng.choice(TOPICS)
    return "Write me a long essay.", " ".join([fact] * rng.randint(70, 120))


# rough mix of what a support-style assistant sees
MIX = [
    (clean, 58),
    (email, 12),
    (order_number, 9),
    (phone, 7),
    (ticket, 6),
    (ssn_dashed, 3),
    (ssn_spaced, 2),
    (long_output, 3),
]


async def get_policy(session, path: str) -> Policy:
    dsl = load_from_file(path)
    row = (
        await session.execute(
            select(Policy).where(Policy.name == dsl.name).order_by(Policy.version.desc()).limit(1)
        )
    ).scalar_one_or_none()
    if row is None:
        row = Policy(name=dsl.name, version=dsl.version, dsl=dsl.model_dump())
        session.add(row)
        await session.commit()
    return row


async def main(n: int, seed: int, batch: int, policy_path: str) -> None:
    rng = random.Random(seed)
    gens = [g for g, _ in MIX]
    weights = [w for _, w in MIX]

    async with SessionLocal() as session:
        policy_row = await get_policy(session, policy_path)
    dsl = PolicyDSL.model_validate(policy_row.dsl)
    print(f"seeding {n} decisions under {dsl.name} v{policy_row.version}")

    t0 = time.perf_counter()
    done = 0
    while done < n:
        size = min(batch, n - done)
        async with SessionLocal() as session:
            async with session.begin():
                await lock_chain(session)
                for _ in range(size):
                    prompt, output = rng.choices(gens, weights)[0](rng)
                    t = time.perf_counter()
                    decision = enforce(dsl, prompt, output)
                    latency_ms = int((time.perf_counter() - t) * 1000)
                    await append_decision(
                        session,
                        policy_row,
                        prompt,
                        output,
                        decision,
                        latency_ms,
                        settings.signing_key_bytes,
                    )
        done += size
        print(f"  {done}/{n}")

    async with SessionLocal() as session:
        total = (await session.execute(select(func.max(AuditEntry.seq)))).scalar()
    elapsed = time.perf_counter() - t0
    print(f"wrote {n} chained decisions in {elapsed:.2f}s ({n / elapsed:.0f}/s), head seq {total}")
    await engine.dispose()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--n", type=int, default=5000)
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--batch", type=int, default=500)
    p.add_argument("--policy", default="policies/pii_redaction.yaml")
    a = p.parse_args()
    asyncio.run(main(a.n, a.seed, a.batch, a.policy))
