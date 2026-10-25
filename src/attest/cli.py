import argparse
import asyncio
import base64
import json
import sys
import time
from pathlib import Path

from sqlalchemy import select


def _load_records_stmt(to_seq: int):
    from attest.models import AuditEntry, Decision, DecisionPayload, Policy

    return (
        select(
            AuditEntry,
            Decision,
            Policy.name,
            Policy.dsl,
            DecisionPayload.input_text,
            DecisionPayload.raw_output_text,
        )
        .join(Decision, AuditEntry.decision_id == Decision.id)
        .join(Policy, Decision.policy_id == Policy.id)
        .outerjoin(DecisionPayload, DecisionPayload.decision_id == Decision.id)
        .where(AuditEntry.seq <= to_seq)
        .order_by(AuditEntry.seq.asc())
    )


async def _load_records(session, to_seq: int):
    from attest.ledger import chain_inputs_for, entry_of
    from attest.replay import ReplayRecord

    records = []
    stream = await session.stream(_load_records_stmt(to_seq).execution_options(yield_per=2000))
    async for entry, decision, name, dsl, input_text, raw_output_text in stream:
        records.append(
            ReplayRecord(
                seq=entry.seq,
                inputs=chain_inputs_for(decision, entry.signed_at),
                entry=entry_of(entry),
                policy_name=name,
                policy_dsl=dsl,
                input_text=input_text,
                raw_output_text=raw_output_text,
            )
        )
    return records


async def run_replay(args) -> int:
    from attest.config import settings
    from attest.db import SessionLocal, engine
    from attest.loader import load_from_file
    from attest.models import ReplayReport
    from attest.replay import (
        ReplayRefused,
        build_report,
        replay,
        sign_report,
        verify_chain,
    )

    candidate = load_from_file(args.policy)
    if args.from_seq < 1 or args.to_seq < args.from_seq:
        print("error: need 1 <= --from <= --to", file=sys.stderr)
        return 2

    try:
        t0 = time.perf_counter()
        async with SessionLocal() as session:
            records = await _load_records(session, args.to_seq)
        t_loaded = time.perf_counter()

        try:
            chain = verify_chain(records, settings.verify_key_bytes)
        except ReplayRefused as e:
            print(f"refusing to replay: chain check failed at {e}", file=sys.stderr)
            return 1
        t_verified = time.perf_counter()

        try:
            result = replay(records, candidate, args.from_seq, args.to_seq)
        except ReplayRefused as e:
            print(f"refusing to replay: payload check failed at {e}", file=sys.stderr)
            return 1
        t_done = time.perf_counter()

        timing = {
            "load_s": round(t_loaded - t0, 4),
            "verify_s": round(t_verified - t_loaded, 4),
            "evaluate_s": round(result.evaluate_s, 4),
            "total_s": round(t_done - t0, 4),
            "verify_entries_per_sec": round(chain.entries_checked / max(t_verified - t_loaded, 1e-9)),
            "replay_records_per_sec": round(result.replayed / max(result.evaluate_s, 1e-9)),
            "end_to_end_records_per_sec": round(result.replayed / max(t_done - t0, 1e-9)),
        }
        report = build_report(
            candidate=candidate,
            from_seq=args.from_seq,
            to_seq=args.to_seq,
            chain=chain,
            result=result,
            timing=timing,
        )
        envelope = sign_report(report, settings.signing_key_bytes)

        out = Path(args.out)
        out.write_text(json.dumps(envelope, indent=2, sort_keys=True))

        report_id = None
        if not args.no_save:
            async with SessionLocal() as session:
                row = ReplayReport(
                    policy_name=candidate.name,
                    candidate_version=candidate.version,
                    from_seq=args.from_seq,
                    to_seq=args.to_seq,
                    report=report,
                    report_sha256=base64.b64decode(envelope["signature"]["report_sha256_b64"]),
                    signature=base64.b64decode(envelope["signature"]["signature_b64"]),
                )
                session.add(row)
                await session.commit()
                report_id = row.id
    finally:
        await engine.dispose()

    _print_summary(report, out, report_id)
    return 0


def _print_summary(report: dict, out: Path, report_id) -> None:
    s = report["summary"]
    c = report["chain"]
    t = report["timing"]
    print(
        f"chain ok: {c['entries_checked']} entries verified "
        f"(seq 1..{c['verified_to_seq']}) in {t['verify_s']}s"
    )
    print(
        f"replayed {s['replayed']} decisions of policy '{report['candidate']['policy_name']}' "
        f"against v{report['candidate']['version']}"
    )
    print(f"  unchanged        {s['unchanged']}")
    print(f"  allow -> block   {s['allow_to_block']}")
    print(f"  block -> allow   {s['block_to_allow']}")
    print(f"  verdict changed  {s['verdict_changed']}  (allow <-> transform)")
    print(f"  rule changed     {s['rule_changed']}  (same verdict, different rule)")
    if s["skipped_no_payload"] or s["skipped_other_policy"]:
        print(
            f"  skipped          {s['skipped_no_payload']} without payload, "
            f"{s['skipped_other_policy']} under other policies"
        )
    if s["baseline_mismatch"]:
        print(f"  WARNING: {s['baseline_mismatch']} records no longer reproduce their signed verdict")
    if report["by_rule"]:
        print("by rule:")
        for rule, n in report["by_rule"].items():
            print(f"  {rule:<24} {n}")
    print(
        f"evaluate: {t['replay_records_per_sec']} rec/s, "
        f"end to end: {t['end_to_end_records_per_sec']} rec/s ({t['total_s']}s)"
    )
    print(f"signed report written to {out}" + (f" (id {report_id})" if report_id else ""))


async def run_verify(args) -> int:
    from attest.config import settings
    from attest.db import SessionLocal, engine
    from attest.verify import downstream, find_problems, label

    try:
        async with SessionLocal() as session:
            records = await _load_records(session, 2**62)
    finally:
        await engine.dispose()

    problems = find_problems(records, settings.verify_key_bytes)
    print(f"checked {len(records)} entries")
    if not problems:
        print("chain ok")
        return 0

    by_seq = {r.seq: r for r in records}
    below = downstream(records, [p.seq for p in problems])
    for p in problems:
        print(f"TAMPERED seq {p.seq} ({label(by_seq[p.seq])}): {p.reason}")
        for s in below[p.seq]:
            print(f"  downstream seq {s} ({label(by_seq[s])})")
    return 1


def run_verify_report(args) -> int:
    from attest.replay import verify_report

    envelope = json.loads(Path(args.file).read_text())
    if args.pubkey:
        pub = base64.b64decode(args.pubkey)
    else:
        from attest.config import settings

        pub = settings.verify_key_bytes
    ok, why = verify_report(envelope, pub)
    print("valid" if ok else f"INVALID: {why}")
    return 0 if ok else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="attest")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("replay", help="replay recorded decisions against a new policy")
    r.add_argument("--policy", required=True, help="candidate policy yaml/json")
    r.add_argument("--from", dest="from_seq", type=int, default=1)
    r.add_argument("--to", dest="to_seq", type=int, required=True)
    r.add_argument("--out", default="replay-report.json")
    r.add_argument("--no-save", action="store_true", help="don't store the report in the db")

    sub.add_parser("verify", help="check the whole chain and stored payloads, show downstream damage")

    v = sub.add_parser("verify-report", help="check a signed replay report")
    v.add_argument("file")
    v.add_argument("--pubkey", help="base64 ed25519 public key (default: ATTEST_VERIFY_KEY)")

    args = p.parse_args(argv)
    if args.cmd == "replay":
        return asyncio.run(run_replay(args))
    if args.cmd == "verify":
        return asyncio.run(run_verify(args))
    return run_verify_report(args)


if __name__ == "__main__":
    sys.exit(main())
