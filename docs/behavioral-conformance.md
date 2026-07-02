# Behavioral conformance needs a portable receipt

*A note on why I built [Attest](https://github.com/Tors428/attest), and where it stops.*

Most of the work in AI agent security goes into verifying *who* an agent is. That's the tractable half. The harder half is *what the agent does once it's authenticated* — and that half has no standard at all.

Enterprise trust really needs three layers: **identity**, **authorization**, and **behavioral conformance**. The first two have interoperable, vendor-neutral standards. The third — whether an authenticated, authorized agent actually stayed inside policy during inference — is where standardization is almost entirely missing. And it's the layer that bites in production: a fully authenticated, correctly authorized agent can still drift off-compliance mid-inference. Identity checks at the door don't catch what happens after the agent is inside.

I think there's a specific reason the first two layers standardized and the third didn't, and it points at what the third layer is missing.

## Why identity and authorization standardized: the artifact

Identity and authorization didn't become interoperable because everyone agreed on a philosophy of trust. They became interoperable because each produced a **portable artifact that a party who wasn't present can verify without trusting the system that issued it.** A signed token is the whole game. I can hand it to a relying party, they can check a signature against a public key, and they never have to trust my infrastructure or take my word for what happened.

Behavioral conformance has no equivalent artifact. What it has is *monitoring* — dashboards, logs, alerting — and monitoring is vendor-specific by construction. A conformance claim today means "our system watched the agent and our system says it behaved." That is unverifiable by anyone outside the vendor. It's the exact property that blocks standardization: there is nothing portable to standardize *on*.

So the primitive I think the third layer needs is a **per-decision conformance receipt**: a signed record, emitted at the moment of each governed decision, that a third party — a regulator, an auditor, a downstream service — can verify after the fact without trusting the system that produced it.

To be useful, that receipt has to bind, in a way that can't be forged or backdated:

- **which input** was governed (or a hash of it),
- **which output** the model produced (or a hash),
- **which policy, at which version,** was applied,
- **the verdict** (allow / transform / block), and
- **the position of this decision in the sequence of all prior decisions** — so you can't silently delete or reorder history.

That last property is the one monitoring never gives you. A log can be edited. A receipt chain, done right, can't be edited without the edit being detectable.

## Attest: a minimal reference implementation

[Attest](https://github.com/Tors428/attest) is a policy-enforcement gateway I built to test whether that receipt primitive actually works end to end. It is deliberately small. It is not a product. It exists to demonstrate one thing: that a tamper-evident, independently verifiable conformance receipt can be produced per decision at negligible cost.

**The decision flow.** A request hits `POST /v1/enforce` with a policy name and an input. Attest pulls the latest version of that policy from Postgres, calls the model (Groq, Llama 3.3 70B) to produce an output, then runs a **deterministic matcher** over `(policy, input, output)` to reach a verdict. The verdict, the content hashes, the policy version, and timing all get written inside a single transaction that also appends one link to a hash-linked, signed audit chain.

**The policy format is a decidable subset, on purpose.** Policies are YAML (or JSON — same schema). A policy has a name, an integer version, a default verdict, and an ordered list of rules. Each rule has one match — `regex`, `contains`, or `length` — and one action — `allow`, `block`, or `transform` (rewrite the output). First match wins; if nothing matches, the default applies. The matcher is a pure function of its inputs. There is no LLM-as-judge step and no dynamic evaluation, which means it always terminates and always produces the same verdict for the same inputs. That's a real limitation — I'll come back to it — but it is the property that makes the verdict *attestable* rather than merely *observed*.

```yaml
# policies/pii_redaction.yaml
- id: redact_email
  match:
    type: regex
    field: output
    pattern: '[\w.+-]+@[\w-]+\.[\w.-]+'
  action:
    verdict: transform
    replace_with: "[email redacted]"
    reason: PII email detected
```

**The chain is where the guarantee lives.** Each audit entry stores:

```
entry_hash = SHA256(
    prev_hash || decision_id || input_hash || output_hash
    || verdict || canonical_reasons_json || signed_at
)
```

That `entry_hash` is then signed with Ed25519. `prev_hash` threads every entry back to the one before it, all the way to a genesis of 32 zero bytes. The verifier at `GET /v1/audit/verify` walks the chain from genesis, recomputes each entry's hash *from the underlying decision row*, checks the signature against the public key, and threads the expected previous hash forward one link at a time. On success it reports how many entries it checked; on failure it reports the exact sequence number where the chain broke and why.

The important consequence: **the append-only guarantee is cryptographic, not schema-enforced.** I did not lock down the Postgres table with triggers or revoked permissions. Anyone with database access can edit a row. The point is that they can't do it *undetectably*. I tested this directly — a raw SQL `UPDATE` flipping a stored verdict from `allow` to `block` made the verifier return `valid: false, failed_at_seq: 1`. Reverting the row returned it to `valid: true`. The receipt doesn't prevent tampering; it makes tampering evidence.

## The number that matters

The obvious objection to per-decision signing is cost. It isn't one.

Under load testing (k6, local server, Neon and Groq free tiers):

| Measurement | Value |
|---|---|
| End-to-end enforce latency, p50 | 4.67 s |
| End-to-end enforce latency, p95 | 5.38 s |
| LLM call (Groq, Llama 3.3 70B), p50 | ~3–4 s |
| Chain critical section (lock + insert + hash + sign + append), median | < 25 ms |
| **Attestation overhead as a share of p95 latency** | **< 1%** |

The entire cost of a governed decision is the model call. The attestation — the thing that turns an opaque output into a verifiable, tamper-evident record — is under 1% of that. Whatever the reasons are that behavioral conformance hasn't standardized, *the cost of emitting the evidence is not one of them.*

## Where this stops — and why that's the interesting part

I want to be precise about what Attest is not, because the boundary is exactly where the real problem lives.

**It's app-layer, so it's bypassable in principle.** Attest can only attest calls that come *through* it. The application in front of it could always call the model directly. The receipt says "when Attest was used, this is what happened" — not "Attest was always used." A serious version of this needs a non-bypassability guarantee that an app-layer gateway fundamentally can't provide on its own.

**It reasons over text, not representations.** The matcher sees the literal output string — regex, substring, length. That's what buys determinism, and it's also the ceiling. It cannot catch an output that is semantically off-policy but lexically clean. "The model said something dishonest, just phrased carefully" is not expressible as a text pattern. This is the trade I made for attestability, and it is the trade that a text-level system can't buy its way out of.

**That gap is the whole point.** The receipt is the easy 20%. Producing a *trustworthy conformance verdict in the first place* — one that catches behavioral drift at the level of the model's representations, not its output string — is the hard 80%. That's the layer where the real work is: deterministic control over model behavior at inference time, intervening on representations rather than pattern-matching text. Attest demonstrates that the *evidence format* for such a verdict can be portable, cheap, and verifiable. It does nothing to solve the harder problem of generating the verdict itself.

Which is the honest reason I find this direction compelling enough to build on my own time: the portable-receipt primitive is a small, tractable piece of a real standardization gap, and the part it *doesn't* solve is the part worth spending years on.

---

**Repo:** [github.com/Tors428/attest](https://github.com/Tors428/attest) — async FastAPI · PostgreSQL · Ed25519 · React/TypeScript.
Others are attacking the enforcement and non-bypassability side of this problem; Attest is narrowly about the *portable evidence* side. If any of the above is wrong or naive, I'd genuinely like to know where.
