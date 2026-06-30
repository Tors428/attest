from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text

from attest.db import engine
from attest.logging_setup import configure_logging
from attest.routes import audit, enforce, policies

configure_logging()

app = FastAPI(title="attest")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(policies.router)
app.include_router(enforce.router)
app.include_router(audit.router)


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


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)