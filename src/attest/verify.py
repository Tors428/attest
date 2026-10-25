import json
from collections import defaultdict
from dataclasses import dataclass

from attest.chain import GENESIS_PREV_HASH, verify_entry
from attest.replay import ReplayRecord, ReplayRefused, b64, check_payload


@dataclass
class Problem:
    seq: int
    reason: str


def find_problems(records: list[ReplayRecord], public_key: bytes) -> list[Problem]:
    # unlike replay, keep going after the first bad entry so we can report all of them
    problems = []
    prev = GENESIS_PREV_HASH
    for r in records:
        if r.entry.prev_hash != prev:
            problems.append(Problem(r.seq, "prev_hash does not match preceding entry_hash"))
        elif not verify_entry(r.inputs, r.entry, public_key):
            problems.append(Problem(r.seq, "hash or signature mismatch"))
        else:
            try:
                check_payload(r)
            except ReplayRefused as e:
                problems.append(Problem(r.seq, e.reason))
        prev = r.entry.entry_hash
    return problems


def refs_of(r: ReplayRecord) -> list[str]:
    # payloads that are json objects can point at upstream entries with
    # "refs": {name: entry_hash_b64}
    try:
        refs = json.loads(r.input_text or "").get("refs") or {}
    except (ValueError, AttributeError):
        return []
    return [h for h in refs.values() if h]


def label(r: ReplayRecord) -> str:
    try:
        return json.loads(r.input_text or "").get("unique_id") or str(r.inputs.decision_id)
    except (ValueError, AttributeError):
        return str(r.inputs.decision_id)


def downstream(records: list[ReplayRecord], bad_seqs: list[int]) -> dict[int, list[int]]:
    seq_of = {b64(r.entry.entry_hash): r.seq for r in records}
    children = defaultdict(set)
    for r in records:
        for h in refs_of(r):
            if h in seq_of:
                children[seq_of[h]].add(r.seq)

    out = {}
    for start in bad_seqs:
        seen, todo = set(), [start]
        while todo:
            for child in children[todo.pop()]:
                if child not in seen:
                    seen.add(child)
                    todo.append(child)
        out[start] = sorted(seen)
    return out


def report(records: list[ReplayRecord], public_key: bytes) -> list[dict]:
    problems = find_problems(records, public_key)
    by_seq = {r.seq: r for r in records}
    below = downstream(records, [p.seq for p in problems])
    return [
        {
            "seq": p.seq,
            "label": label(by_seq[p.seq]),
            "reason": p.reason,
            "downstream": [{"seq": s, "label": label(by_seq[s])} for s in below[p.seq]],
        }
        for p in problems
    ]
