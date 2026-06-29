import re
from dataclasses import dataclass

from attest.dsl import (
    Action,
    ContainsMatch,
    LengthMatch,
    Match,
    PolicyDSL,
    RegexMatch,
)


@dataclass
class Decision:
    verdict: str
    output: str
    matched_rule_id: str | None
    reason: str


def _get_field(match: Match, input_text: str, output_text: str) -> str:
    return input_text if match.field == "input" else output_text


def _matches(match: Match, input_text: str, output_text: str) -> bool:
    target = _get_field(match, input_text, output_text)

    if isinstance(match, RegexMatch):
        return re.search(match.pattern, target) is not None

    if isinstance(match, ContainsMatch):
        if match.case_sensitive:
            return match.value in target
        return match.value.lower() in target.lower()

    if isinstance(match, LengthMatch):
        n = len(target)
        ops = {
            "gt": n > match.value,
            "lt": n < match.value,
            "gte": n >= match.value,
            "lte": n <= match.value,
            "eq": n == match.value,
        }
        return ops[match.op]

    raise ValueError(f"unknown match type: {type(match)}")


def _apply_action(action: Action, input_text: str, output_text: str, match: Match) -> str:
    if action.verdict != "transform":
        return output_text

    if action.replace_with is None:
        return output_text

    if isinstance(match, RegexMatch) and match.field == "output":
        return re.sub(match.pattern, action.replace_with, output_text)

    return action.replace_with


def enforce(policy: PolicyDSL, input_text: str, output_text: str) -> Decision:
    for rule in policy.rules:
        if _matches(rule.match, input_text, output_text):
            new_output = _apply_action(rule.action, input_text, output_text, rule.match)
            return Decision(
                verdict=rule.action.verdict,
                output=new_output,
                matched_rule_id=rule.id,
                reason=rule.action.reason,
            )

    return Decision(
        verdict=policy.default,
        output=output_text,
        matched_rule_id=None,
        reason="no rule matched, default applied",
    )