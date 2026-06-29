from fastapi import FastAPI, Response
from sqlalchemy import text

from attest.db import engine
from attest.routes import policies

app = FastAPI(title="attest")
app.include_router(policies.router)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/readyz")
async def readyz(response: Response):
    try:
        async with engine.connect() as conn:
            await conn.execute(text("select 1"))
        return {"status": "ready"}
    except Exception as e:
        response.status_code = 503
        return {"status": "not ready", "error": str(e)}