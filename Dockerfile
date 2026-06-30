# multi-stage build to keep the runtime image small
FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src ./src

# install into the system site-packages of this stage, not a custom dir
RUN pip install --no-cache-dir .


FROM python:3.11-slim

WORKDIR /app

# copy the installed packages AND the entrypoint scripts (uvicorn, alembic, etc.)
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /app/src /app/src

ENV PYTHONPATH=/app/src
ENV PORT=8080

CMD exec uvicorn attest.main:app --host 0.0.0.0 --port ${PORT} --workers 2