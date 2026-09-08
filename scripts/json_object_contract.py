#!/usr/bin/env python3
"""Shared duplicate-member-safe JSON parsing for reviewed runtime boundaries."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

VERSION = "json-object-uniqueness-v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _hook(label: str):
    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"{label} contains duplicate JSON object key: {key}")
            result[key] = value
        return result
    return unique_object


def loads(text: str, *, label: str = "JSON input") -> Any:
    """Decode JSON while rejecting duplicate object members at every nesting depth."""
    return json.loads(text, object_pairs_hook=_hook(label))


def load_path(path: Path, *, label: str | None = None) -> Any:
    """Read UTF-8 JSON from one path and decode with duplicate-member rejection."""
    return loads(path.read_text(encoding="utf-8"), label=label or str(path))


def self_test() -> None:
    payload = loads('{"outer":{"value":1},"items":[{"id":"a"}]}', label="fixture")
    require(payload == {"outer": {"value": 1}, "items": [{"id": "a"}]},
            "strict JSON parser changed ordinary semantics")
    for raw, key in (
        ('{"version":1,"version":2}', "version"),
        ('{"outer":{"id":1,"id":2}}', "id"),
        ('{"items":[{"name":"a","name":"b"}]}', "name"),
    ):
        try:
            loads(raw, label="fixture")
        except ValueError as exc:
            require(f"duplicate JSON object key: {key}" in str(exc),
                    f"strict JSON self-test failed for wrong reason: {exc}")
        else:
            raise ValueError(f"strict JSON self-test accepted duplicate object key: {key}")


if __name__ == "__main__":
    self_test()
    print(f"Strict JSON object contract passed: {VERSION}")
