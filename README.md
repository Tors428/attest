# Attest

A policy-enforcement gateway that produces a **portable, tamper-evident conformance
receipt** for every LLM decision — a signed, hash-linked audit record that a third party
can verify without trusting the system that produced it.

Identity and authorization have interoperable standards; *behavioral conformance* — what an
authenticated agent actually does at inference time — does not. Attest is a minimal reference
implementation of the missing piece: cheap, verifiable, per-decision evidence. Design
rationale and limits: **[docs/behavioral-conformance.md](docs/behavioral-conformance.md)**.

**Stack:** async FastAPI · PostgreSQL · Ed25519 · React/TypeScript

The verifier caught a database-level bypass without any application-layer help. Anyone holding the public verify key can run this check.

## Load characteristics

Measured against the local FastAPI instance with Neon as the database, over k6 ramping 3 → 5 → 8 concurrent virtual users for 30 seconds each.

| Metric | Value |
|--------|-------|
| p50 end-to-end latency | 4.67s |
| p95 end-to-end latency | 5.38s |
| p99 end-to-end latency | ~6.0s |
| Chain write (advisory lock + hash + sign + insert) | median <25ms |
| LLM call (Groq, Llama 3.3 70B) | ~3-4s p50 |

**End-to-end latency is dominated by the LLM call.** Attestation itself is single-digit milliseconds. This was the load test's real question: does adding a cryptographic audit chain make LLM enforcement too slow to be practical? The answer is no — the cost is under 1% of the LLM latency at p95.

At 8+ concurrent VUs, some requests fail with `connection reset by peer`. Investigation showed these correspond to Groq's free-tier rate limit dropping the LLM connection, not any bottleneck in Attest's own code path. On a paid LLM tier, this ceiling extends.

## Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/v1/enforce` | Run a policy against an LLM output |
| POST | `/v1/policies` | Create a new policy version |
| GET | `/v1/policies` | List latest version of each policy |
| GET | `/v1/policies/{name}` | Fetch latest version |
| GET | `/v1/policies/{name}/{version}` | Fetch a specific version |
| GET | `/v1/audit` | Recent audit entries (paginated) |
| GET | `/v1/audit/{decision_id}` | Single decision's audit entry |
| GET | `/v1/audit/verify` | Walk and verify the whole chain |
| GET | `/healthz` | Process liveness |
| GET | `/readyz` | Postgres reachability |
| GET | `/metrics` | Prometheus scrape |

## Running locally

```bash
git clone https://github.com/Tors428/attest
cd attest
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env  # fill in DATABASE_URL, ATTEST_SIGNING_KEY, ATTEST_VERIFY_KEY, GROQ_API_KEY
alembic upgrade head
uvicorn attest.main:app --port 8000
```

The dashboard is a sibling Vite project:

```bash
cd dashboard
npm install
npm run dev  # http://localhost:5173
```

## Deployment

Deployed on GCP Cloud Run via Cloud Build. From the repo root:

```bash
gcloud run deploy attest \
  --source . \
  --region us-west1 \
  --allow-unauthenticated \
  --port 8080 \
  --min-instances 0 \
  --max-instances 3 \
  --memory 512Mi \
  --cpu 1 \
  --env-vars-file .env.production.yaml
```

The Dockerfile is multi-stage (builder + slim runtime) and the deployed image is ~150MB.

## Known limitations, documented honestly

- **Verdict enum casing:** `verdict` is stored as an uppercase Postgres enum (`ALLOW`/`BLOCK`/`TRANSFORM`) but hashed as lowercase (`.value`) via the SQLAlchemy round-trip. The signer and verifier both see lowercase, so the chain works — but a raw-SQL viewer would see the uppercase form. A production version would either use `values_callable` on the SAEnum to canonicalize, or normalize at the model layer.
- **Load test ceiling is the LLM, not the app.** Groq's free-tier rate limit surfaces as `connection reset by peer` at >5 VUs. Isolating Attest's own path (via the `chain_write_latency_seconds` metric) shows attestation itself is single-digit ms and would scale with the LLM tier.
- **Advisory lock scope.** The chain critical section uses a single fixed advisory-lock key, which serializes all chain writes globally. Fine for the semantics (chain is linear by design) and cheap in Postgres. A multi-tenant version would key by tenant.

## Tests

- `tests/test_matcher.py` — deterministic enforcement across allow/transform/block cases, plus a determinism property test (same input twice = identical decision)
- `tests/test_chain.py` — 9 property tests: hash length, determinism, key-order independence for `reasons`, build-and-verify roundtrip, tamper-detection for verdict and output changes, wrong-key rejection, chain-link changes when prev_hash changes, invalid-length prev_hash raises

Run: `pytest -v`

## Files worth reading first

- `src/attest/chain.py` — the cryptographic core
- `src/attest/routes/enforce.py` — the hot path with the advisory lock
- `src/attest/routes/audit.py` — the verifier
- `src/attest/matcher.py` — the deterministic enforcement function
- `tests/test_chain.py` — the property tests that prove tamper detection
