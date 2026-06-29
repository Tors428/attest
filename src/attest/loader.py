import json
from pathlib import Path

import yaml

from attest.dsl import PolicyDSL


def load_from_string(text: str, format: str = "yaml") -> PolicyDSL:
    if format == "yaml":
        raw = yaml.safe_load(text)
    elif format == "json":
        raw = json.loads(text)
    else:
        raise ValueError(f"unknown format: {format}")
    return PolicyDSL.model_validate(raw)


def load_from_file(path: str | Path) -> PolicyDSL:
    p = Path(path)
    fmt = "yaml" if p.suffix in (".yaml", ".yml") else "json"
    return load_from_string(p.read_text(), format=fmt)