import re
from typing import Literal, Union

from pydantic import BaseModel, Field


class RegexMatch(BaseModel):
    type: Literal["regex"]
    field: Literal["input", "output"]
    pattern: str


class ContainsMatch(BaseModel):
    type: Literal["contains"]
    field: Literal["input", "output"]
    value: str
    case_sensitive: bool = False


class LengthMatch(BaseModel):
    type: Literal["length"]
    field: Literal["input", "output"]
    op: Literal["gt", "lt", "gte", "lte", "eq"]
    value: int


Match = Union[RegexMatch, ContainsMatch, LengthMatch]


class Action(BaseModel):
    verdict: Literal["allow", "block", "transform"]
    reason: str
    replace_with: str | None = None


class Rule(BaseModel):
    id: str
    match: Match = Field(discriminator="type")
    action: Action


class PolicyDSL(BaseModel):
    name: str
    version: int
    default: Literal["allow", "block"] = "allow"
    rules: list[Rule]