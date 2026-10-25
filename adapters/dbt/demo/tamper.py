# rewrite the row count on the oldest raw_orders record, straight in postgres
import asyncio

from sqlalchemy import text

from attest.db import SessionLocal, engine

SQL = text("""
update decision_payloads p
set input_text = regexp_replace(p.input_text, :pattern, :new)
where p.decision_id = (
    select d.id from decisions d
    join audit_entries a on a.decision_id = d.id
    join decision_payloads x on x.decision_id = d.id
    where x.input_text like :node
    order by a.seq limit 1
)
returning p.decision_id
""")


async def main():
    async with SessionLocal() as session:
        row = (
            await session.execute(
                SQL,
                {
                    "pattern": '"rows":[0-9]+',
                    "new": '"rows":9999',
                    "node": '%"unique_id":"seed.jaffle_shop.raw_orders"%',
                },
            )
        ).first()
        await session.commit()
    await engine.dispose()
    print(f"set rows=9999 on decision {row[0]}" if row else "no raw_orders record found")


asyncio.run(main())
