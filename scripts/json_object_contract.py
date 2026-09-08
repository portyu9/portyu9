#!/usr/bin/env python3
"""Strict JSON parsing and object-shape contracts for generated profile evidence."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

VERSION = "json-object-contract-v3"
ALLOWED_BOOLEAN_KEYS = frozenset({"offline"})

LEDGER_ROOT_KEYS = frozenset({
    "version", "kind", "owner", "as_of_date_utc", "evidence_semantics",
    "subject_policy", "freshness_basis", "classification_policy",
    "portfolio_registry", "system_count", "result_summary", "binding_summary",
    "freshness_summary", "systems", "evidence_id", "evidence_digest",
})
REGISTRY_KEYS = frozenset({"version", "digest"})
SYSTEM_KEYS = frozenset({
    "repository", "title", "classification", "subject_revision",
    "evidence_max_age_days", "evidence_contract", "signals",
})
CONTRACT_KEYS = frozenset({"label", "workflow", "scope"})
SIGNAL_KEYS = frozenset({
    "label", "workflow", "scope", "result", "binding", "freshness",
    "run_id", "run_number", "run_url", "head_sha", "completed_at_utc",
    "age_days", "offline", "ordinal",
})
SPOTLIGHT_ROOT_KEYS = frozenset({
    "version", "selection_date_utc", "selection_policy", "evidence_model",
    "evidence_source", "evidence_semantics", "portfolio_registry",
    "portfolio_evidence_id", "portfolio_evidence_digest",
    "portfolio_as_of_date_utc", "freshness_basis", "live_policy", "slots",
})
SPOTLIGHT_SLOT_KEYS = frozenset({
    "slot", "repository", "title", "glyph", "topology", "subject_revision",
    "evidence_contract", "signals",
})


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
    """Allow JSON booleans only at explicitly reviewed evidence-marker keys."""
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


def require_exact_keys(value: Any, expected: frozenset[str], label: str) -> dict[str, Any]:
    """Require one object to contain exactly the reviewed member inventory."""
    require(isinstance(value, dict), f"{label} must be an object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise ValueError(
            f"{label} object members changed: missing={missing} unexpected={unexpected}"
        )
    return value


def _validate_contract_records(value: Any, label: str) -> None:
    require(isinstance(value, list), f"{label} must be an array")
    for index, record in enumerate(value):
        require_exact_keys(record, CONTRACT_KEYS, f"{label}[{index}]")


def _validate_signal_records(value: Any, label: str) -> None:
    require(isinstance(value, list), f"{label} must be an array")
    for index, record in enumerate(value):
        require_exact_keys(record, SIGNAL_KEYS, f"{label}[{index}]")


def validate_portfolio_ledger_shape(payload: Any, *, label: str = "Portfolio evidence ledger") -> dict[str, Any]:
    """Close every fixed Ledger object to its reviewed member set."""
    ledger = require_exact_keys(payload, LEDGER_ROOT_KEYS, label)
    require_exact_keys(ledger["portfolio_registry"], REGISTRY_KEYS, f"{label}.portfolio_registry")
    systems = ledger["systems"]
    require(isinstance(systems, list), f"{label}.systems must be an array")
    for index, raw_system in enumerate(systems):
        system_label = f"{label}.systems[{index}]"
        system = require_exact_keys(raw_system, SYSTEM_KEYS, system_label)
        _validate_contract_records(system["evidence_contract"], f"{system_label}.evidence_contract")
        _validate_signal_records(system["signals"], f"{system_label}.signals")
    return ledger


def validate_spotlight_manifest_shape(payload: Any, *, label: str = "Engineering Spotlight manifest") -> dict[str, Any]:
    """Close every fixed Spotlight manifest object to its reviewed member set."""
    manifest = require_exact_keys(payload, SPOTLIGHT_ROOT_KEYS, label)
    require_exact_keys(manifest["portfolio_registry"], REGISTRY_KEYS, f"{label}.portfolio_registry")
    slots = manifest["slots"]
    require(isinstance(slots, list), f"{label}.slots must be an array")
    for index, raw_slot in enumerate(slots):
        slot_label = f"{label}.slots[{index}]"
        slot = require_exact_keys(raw_slot, SPOTLIGHT_SLOT_KEYS, slot_label)
        _validate_contract_records(slot["evidence_contract"], f"{slot_label}.evidence_contract")
        _validate_signal_records(slot["signals"], f"{slot_label}.signals")
    return manifest


def load_path(path: Path, *, label: str | None = None) -> Any:
    """Read one canonical evidence JSON path and enforce its reviewed object shape."""
    resolved_label = label or str(path)
    payload = loads(path.read_text(encoding="utf-8"), label=resolved_label)
    if path.name == "portfolio-evidence-ledger.json":
        return validate_portfolio_ledger_shape(payload, label=resolved_label)
    if path.name == "spotlight-manifest.json":
        return validate_spotlight_manifest_shape(payload, label=resolved_label)
    return payload


def expect_failure(text: str, expected: str) -> None:
    try:
        loads(text, label="fixture")
    except ValueError as exc:
        require(expected in str(exc), f"strict JSON self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"strict JSON self-test accepted invalid input: {expected}")


def _contract_fixture() -> dict[str, Any]:
    return {"label": "CI", "workflow": "ci.yml", "scope": "workflow"}


def _signal_fixture() -> dict[str, Any]:
    return {
        "label": "CI", "workflow": "ci.yml", "scope": "workflow",
        "result": "PASSING", "binding": "CURRENT_SUBJECT", "freshness": "SAME_DAY",
        "run_id": 1, "run_number": 1, "run_url": "https://github.com/example/actions/runs/1",
        "head_sha": "1" * 40, "completed_at_utc": "2026-09-08T00:00:00Z",
        "age_days": 0, "offline": False, "ordinal": 1,
    }


def _ledger_fixture() -> dict[str, Any]:
    return {
        "version": "portfolio-evidence-ledger-v2", "kind": "portfolio-evidence-ledger",
        "owner": "portyu9", "as_of_date_utc": "2026-09-08",
        "evidence_semantics": "execution-result-subject-binding-freshness-v1",
        "subject_policy": "current-main-revision-per-system",
        "freshness_basis": "UTC whole-day age from workflow evidence timestamp",
        "classification_policy": "fixture", "portfolio_registry": {"version": "fixture", "digest": "fixture"},
        "system_count": 1, "result_summary": {"PASSING": 1},
        "binding_summary": {"CURRENT_SUBJECT": 1}, "freshness_summary": {"SAME_DAY": 1},
        "systems": [{
            "repository": "portyu9/fixture", "title": "fixture", "classification": "rotating",
            "subject_revision": "1" * 40, "evidence_max_age_days": 0,
            "evidence_contract": [_contract_fixture()], "signals": [_signal_fixture()],
        }],
        "evidence_id": "PL2-0000000000000000", "evidence_digest": "sha256:" + "0" * 64,
    }


def _spotlight_fixture() -> dict[str, Any]:
    return {
        "version": "engineering-spotlight-v2.1", "selection_date_utc": "2026-09-08",
        "selection_policy": "fixture", "evidence_model": "fixture",
        "evidence_source": "portfolio-evidence-ledger-v2",
        "evidence_semantics": "execution-result-subject-binding-freshness-v1",
        "portfolio_registry": {"version": "fixture", "digest": "fixture"},
        "portfolio_evidence_id": "PL2-0000000000000000",
        "portfolio_evidence_digest": "sha256:" + "0" * 64,
        "portfolio_as_of_date_utc": "2026-09-08",
        "freshness_basis": "UTC whole-day age from workflow evidence timestamp",
        "live_policy": "fixture",
        "slots": [{
            "slot": 1, "repository": "portyu9/fixture", "title": "fixture",
            "glyph": "fixture", "topology": "fixture", "subject_revision": "1" * 40,
            "evidence_contract": [_contract_fixture()], "signals": [_signal_fixture()],
        }],
    }


def _expect_shape_failure(payload: dict[str, Any], validator: Any, expected: str) -> None:
    try:
        validator(payload, label="fixture")
    except ValueError as exc:
        require(expected in str(exc), f"shape self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"shape self-test accepted unreviewed object member: {expected}")


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

    ledger = _ledger_fixture()
    validate_portfolio_ledger_shape(ledger, label="fixture")
    for mutate, expected in (
        (lambda value: value.__setitem__("unexpected", "x"), "unexpected=['unexpected']"),
        (lambda value: value["systems"][0].__setitem__("debug", "x"), "unexpected=['debug']"),
        (lambda value: value["systems"][0]["signals"][0].__setitem__("note", "x"), "unexpected=['note']"),
        (lambda value: value["systems"][0]["evidence_contract"][0].__setitem__("extra", "x"), "unexpected=['extra']"),
    ):
        drift = copy.deepcopy(ledger)
        mutate(drift)
        _expect_shape_failure(drift, validate_portfolio_ledger_shape, expected)

    spotlight = _spotlight_fixture()
    validate_spotlight_manifest_shape(spotlight, label="fixture")
    for mutate, expected in (
        (lambda value: value.__setitem__("unexpected", "x"), "unexpected=['unexpected']"),
        (lambda value: value["slots"][0].__setitem__("debug", "x"), "unexpected=['debug']"),
        (lambda value: value["slots"][0]["signals"][0].__setitem__("note", "x"), "unexpected=['note']"),
    ):
        drift = copy.deepcopy(spotlight)
        mutate(drift)
        _expect_shape_failure(drift, validate_spotlight_manifest_shape, expected)


if __name__ == "__main__":
    self_test()
    print(
        f"Strict JSON object contract passed: {VERSION} · duplicate members, unreviewed booleans, "
        "and unreviewed generated-evidence object members rejected"
    )
