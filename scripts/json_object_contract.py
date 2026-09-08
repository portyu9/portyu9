#!/usr/bin/env python3
"""Strict JSON parsing for reviewed generated-evidence runtime boundaries."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

VERSION = "json-object-contract-v2"
ALLOWED_BOOLEAN_KEYS = frozenset({"offline"})


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


def _validate_boolean_surface(value: Any, *, label: str, path: str = "$") -> None:
    """Allow JSON booleans only at explicitly reviewed evidence-marker keys.

    Python ``bool`` is a subclass of ``int``. Without this source-shape guard, values
    such as ``true`` can satisfy downstream ``isinstance(value, int)`` checks and even
    compare equal to ``1``. Generated Ledger/Spotlight JSON currently has exactly one
    reviewed boolean field, ``offline``; every other boolean position fails closed.
    """
    if isinstance(value, bool):
        raise ValueError(f"{label} contains boolean outside a reviewed field: {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_boolean_surface(item, label=label, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            child = f"{path}.{key}"
            if isinstance(item, bool):
                require(
                    key in ALLOWED_BOOLEAN_KEYS,
                    f"{label} contains boolean outside a reviewed field: {child}",
                )
            else:
                _validate_boolean_surface(item, label=label, path=child)


def loads(text: str, *, label: str = "JSON input") -> Any:
    """Decode JSON with duplicate-member and reviewed-boolean-surface enforcement."""
    payload = json.loads(text, object_pairs_hook=_hook(label))
    _validate_boolean_surface(payload, label=label)
    return payload


def load_path(path: Path, *, label: str | None = None) -> Any:
    """Read UTF-8 JSON and apply the strict generated-evidence JSON contract."""
    return loads(path.read_text(encoding="utf-8"), label=label or str(path))


def expect_failure(text: str, expected: str) -> None:
    try:
        loads(text, label="fixture")
    except ValueError as exc:
        require(expected in str(exc), f"strict JSON self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"strict JSON self-test accepted invalid input: {expected}")


def self_test() -> None:
    payload = loads(
        '{"outer":{"value":1,"offline":true},"items":[{"id":"a","offline":false}]}',
        label="fixture",
    )
    require(
        payload == {"outer": {"value": 1, "offline": True}, "items": [{"id": "a", "offline": False}]},
        "strict JSON parser changed ordinary semantics",
    )
    for raw, key in (
        ('{"version":1,"version":2}', "version"),
        ('{"outer":{"id":1,"id":2}}', "id"),
        ('{"items":[{"name":"a","name":"b"}]}', "name"),
    ):
        expect_failure(raw, f"duplicate JSON object key: {key}")
    for raw, path in (
        ('{"run_id":true}', "$.run_id"),
        ('{"result_summary":{"PASSING":true}}', "$.result_summary.PASSING"),
        ('{"items":[true]}', "$.items[0]"),
    ):
        expect_failure(raw, f"boolean outside a reviewed field: {path}")


if __name__ == "__main__":
    self_test()
    print(f"Strict JSON object contract passed: {VERSION} · duplicate members and unreviewed booleans rejected")
