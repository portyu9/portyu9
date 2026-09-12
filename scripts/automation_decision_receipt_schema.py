#!/usr/bin/env python3
"""Bind the frozen Automation Decision Receipt v1 schema to builder constants."""
from __future__ import annotations

import json
from typing import Any

import automation_decision_receipt as builder

EXPECTED_EFFECT_JOBS = {
    "spotlight-workflow-dispatch": "dispatch",
    "stale-candidate-reconciliation": "reconcile",
    "spotlight-candidate-publication": "propose",
    "workflow-run-approval-request": "approve",
    "spotlight-terminal-merge": "merge",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"Automation Decision Receipt schema contains duplicate key: {key}")
        result[key] = value
    return result


def load_schema() -> dict[str, Any]:
    require(builder.PREDICATE_SCHEMA.is_file() and not builder.PREDICATE_SCHEMA.is_symlink(),
            "Automation Decision Receipt schema is missing or aliased")
    try:
        value = json.loads(builder.PREDICATE_SCHEMA.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Automation Decision Receipt schema is invalid JSON: {exc}") from exc
    require(isinstance(value, dict), "Automation Decision Receipt schema root must be an object")
    return value


def validate(schema: dict[str, Any]) -> None:
    require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema",
            "Automation Decision Receipt schema draft identity changed")
    require(schema.get("$id") == builder.PREDICATE_TYPE,
            "Automation Decision Receipt schema ID differs from builder predicate type")
    require(schema.get("type") == "object" and schema.get("additionalProperties") is False,
            "Automation Decision Receipt schema root closure changed")
    properties = schema.get("properties")
    require(isinstance(properties, dict), "Automation Decision Receipt schema properties are malformed")
    require(properties.get("schemaVersion") == {"const": builder.SCHEMA_VERSION},
            "Automation Decision Receipt schema version differs from builder")
    require(properties.get("kind") == {"const": builder.KIND},
            "Automation Decision Receipt schema kind differs from builder")
    require(properties.get("repository") == {"const": builder.REPOSITORY},
            "Automation Decision Receipt schema repository differs from builder")
    require(properties.get("workflowRef") == {
        "enum": [
            f"{builder.REPOSITORY}/{builder.PROFILE_WORKFLOW}@refs/heads/main",
            f"{builder.REPOSITORY}/{builder.SPOTLIGHT_WORKFLOW}@refs/heads/main",
        ]
    }, "Automation Decision Receipt workflow-ref schema differs from builder")
    require(properties.get("claim") == {"const": builder.CLAIM},
            "Automation Decision Receipt claim differs from builder")
    predicate_schema = properties.get("predicateSchema", {}).get("properties", {})
    require(predicate_schema.get("id") == {"const": builder.PREDICATE_TYPE},
            "Automation Decision Receipt predicateSchema.id differs from builder")

    effect = schema.get("$defs", {}).get("effect")
    require(isinstance(effect, dict) and effect.get("type") == "object"
            and effect.get("additionalProperties") is False,
            "Automation Decision Receipt effect schema is not closed")
    effect_properties = effect.get("properties", {})
    require(set(effect_properties.get("kind", {}).get("enum", [])) == builder.EFFECT_KINDS,
            "Automation Decision Receipt effect-kind inventory differs from builder")
    require(set(effect_properties.get("job", {}).get("enum", [])) == set(EXPECTED_EFFECT_JOBS.values()),
            "Automation Decision Receipt effect-job inventory differs from builder")
    conditions = effect.get("allOf")
    require(isinstance(conditions, list) and len(conditions) == len(EXPECTED_EFFECT_JOBS),
            "Automation Decision Receipt conditional effect inventory changed")
    observed: dict[str, str] = {}
    for condition in conditions:
        require(isinstance(condition, dict) and set(condition) == {"if", "then"},
                "Automation Decision Receipt effect condition shape changed")
        kind = condition.get("if", {}).get("properties", {}).get("kind", {}).get("const")
        job = condition.get("then", {}).get("properties", {}).get("job", {}).get("const")
        require(isinstance(kind, str) and isinstance(job, str),
                "Automation Decision Receipt effect condition identity is malformed")
        require(kind not in observed, f"Automation Decision Receipt effect condition is duplicated: {kind}")
        observed[kind] = job
    require(observed == EXPECTED_EFFECT_JOBS,
            "Automation Decision Receipt effect kind→job schema binding differs from builder")


def self_test() -> None:
    schema = load_schema()
    validate(schema)
    changed = json.loads(json.dumps(schema))
    changed["properties"]["kind"]["const"] = "unreviewed"
    try:
        validate(changed)
    except ValueError as exc:
        require("kind differs" in str(exc), f"schema-binding self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("schema-binding self-test accepted changed receipt kind")
