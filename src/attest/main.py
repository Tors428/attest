from fastapi import FastAPI

app = FastAPI(title="attest")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}