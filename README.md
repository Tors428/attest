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

## Policy replay

Most gateways log a decision and forget it. Attest keeps a signed, hash-linked history of every decision, so that history doubles as a test set: before shipping a policy change, you can replay it over past traffic and see exactly which decisions would flip, with proof the history wasn't edited first.

```bash
attest replay --policy policies/pii_redaction_v2.yaml --from 1 --to 5000
attest verify-report replay-report.json
```

What `replay` does, in order:

1. **Verifies the chain** from genesis up to `--to` (prev-hash links and every Ed25519 signature). Any break and it refuses to run.
2. **Checks every stored payload** against the hashes the chain signed. Raw input and the raw (pre-policy) model output live in `decision_payloads`; their hashes are bound into each v2 chain entry along with the policy id and version. An edited payload is refused, not silently replayed.
3. **Re-runs the old policy** on each payload as a sanity check. If it doesn't reproduce the signed verdict, the record is counted as a baseline mismatch and called out, because a diff on top of that can't be trusted.
4. **Runs the candidate policy** and diffs against the signed verdict: allowed → blocked, blocked → allowed, allow ↔ transform, or same verdict via a different rule. Each change names the rule responsible.
5. **Signs the report** (SHA-256 of canonical JSON, Ed25519) and stores it in `replay_reports`. The report pins the chain head hash it was computed against and the SHA-256 of the candidate policy, so it stands on its own as evidence.

The dashboard's **policy replay** tab lists the flipped decisions with the rule that caused each one, and expands a row to show the original prompt and output.

### Measured

5,000 synthetic decisions seeded through the real write path (`scripts/seed_synthetic.py --n 5000 --seed 42`, no LLM calls), then one rule changed: `block_ssn` widened from `\d{3}-\d{2}-\d{4}` to `\d{3}[- ]?\d{2}[- ]?\d{4}` so it also catches SSNs written with spaces.

| | |
|---|---|
| Decisions replayed | 5,000 |
| Flipped allow → block | 539 (10.8%) |
| …of which spaced SSNs the old rule missed | 115 |
| …of which 9-digit order numbers now wrongly blocked | 424 |
| Flipped block → allow | 0 |
| Chain verify (5,000 signatures) | 1.68s, ~2,980 entries/s |
| Policy evaluation | 0.14s, ~35,600 records/s |
| End to end (load + verify + evaluate) | 2.07s, ~2,420 records/s |

Three runs, all within 2% of each other. Local Postgres 17, Apple M3, Python 3.13. The headline: the "obvious" regex fix catches 115 real SSNs but would block 424 legitimate order-status replies, which is the kind of thing you want to know before deploying, not after.

Replay throughput is bound by Ed25519 verification (~330µs per signature through `cryptography`, and it holds the GIL, so threads don't help). Policy evaluation itself is about 12x faster than verification.

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
| GET | `/v1/audit/{decision_id}/payload` | Stored input and raw output for a decision |
| GET | `/v1/replays` | Recent replay reports |
| GET | `/v1/replays/{id}` | Signed replay report |
| GET | `/v1/replays/{id}/verify` | Re-check a report's signature |
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
- **Replay needs payloads.** Storing raw text is the price of being able to replay. It sits in its own table so it can be purged on a retention schedule without breaking the chain (the chain only holds hashes); purged or pre-v2 records are skipped and counted, never guessed. Set `ATTEST_STORE_PAYLOADS=false` to opt out.
- **Replay loads the range into memory.** Fine at tens of thousands of records. A much larger chain would want verification checkpoints (signed chain heads) so replay doesn't re-verify from genesis every time, and a process pool for signature checks.
- **Advisory lock scope.** The chain critical section uses a single fixed advisory-lock key, which serializes all chain writes globally. Fine for the semantics (chain is linear by design) and cheap in Postgres. A multi-tenant version would key by tenant.

## Tests

- `tests/test_matcher.py` — deterministic enforcement across allow/transform/block cases, plus a determinism property test (same input twice = identical decision)
- `tests/test_replay.py` — replay end to end in memory: v1 entries still verify, v2 binds policy version, the SSN rule change flips the right records, refusal on edited verdicts, deleted entries and edited payloads, signed report roundtrip and tamper detection
- `tests/test_chain.py` — 9 property tests: hash length, determinism, key-order independence for `reasons`, build-and-verify roundtrip, tamper-detection for verdict and output changes, wrong-key rejection, chain-link changes when prev_hash changes, invalid-length prev_hash raises

Run: `pytest -v`

## Files worth reading first

- `src/attest/chain.py` — the cryptographic core
- `src/attest/routes/enforce.py` — the hot path with the advisory lock
- `src/attest/routes/audit.py` — the verifier
- `src/attest/replay.py` — replaying history against a new policy, signed reports
- `src/attest/matcher.py` — the deterministic enforcement function
- `tests/test_chain.py` — the property tests that prove tamper detection
