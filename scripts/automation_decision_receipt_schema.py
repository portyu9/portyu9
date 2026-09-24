#!/usr/bin/env python3
"""Bind the frozen Automation Decision Receipt v1 schema to builder constants."""
from __future__ import annotations

import copy
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
DISPATCH_DOWNSTREAM_REQUIRED = [
    "workflowId",
    "runId",
    "runAttempt",
    "checkSuiteId",
    "path",
    "event",
    "headBranch",
    "headSha",
    "actorLogin",
    "actorId",
    "triggeringActorLogin",
    "triggeringActorId",
    "repository",
    "repositoryId",
    "headRepository",
    "headRepositoryId",
]
DISPATCH_ANCESTRY_REQUIRED = [
    "baseSha",
    "headSha",
    "status",
    "mergeBaseSha",
    "aheadBy",
    "behindBy",
]


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


def dispatch_condition(conditions: list[Any]) -> dict[str, Any]:
    matches = [
        condition for condition in conditions
        if condition.get("if", {}).get("properties", {}).get("kind", {}).get("const")
        == "spotlight-workflow-dispatch"
    ]
    require(len(matches) == 1, "Automation Decision Receipt dispatch schema condition changed")
    return matches[0]


def validate_dispatch_schema(conditions: list[Any]) -> None:
    condition = dispatch_condition(conditions)
    properties = condition.get("then", {}).get("properties", {})
    require(properties.get("job") == {"const": "dispatch"}
            and properties.get("outcome") == {"const": "applied"},
            "Automation Decision Receipt dispatch job/outcome schema changed")
    observation = properties.get("observation")
    require(isinstance(observation, dict) and observation.get("type") == "object"
            and observation.get("additionalProperties") is False,
            "Automation Decision Receipt dispatch observation must remain closed")
    require(
        observation.get("required")
        == ["acceptedStatus", "previousRunHighWater", "downstreamRun", "sourceAncestry"],
        "Automation Decision Receipt dispatch observation required set changed",
    )
    observed = observation.get("properties", {})
    require(observed.get("acceptedStatus") == {"const": 204},
            "Automation Decision Receipt dispatch acceptance schema changed")
    require(observed.get("previousRunHighWater") == {"$ref": "#/$defs/nonNegativeInteger"},
            "Automation Decision Receipt dispatch high-water schema changed")
    downstream = observed.get("downstreamRun")
    require(isinstance(downstream, dict) and downstream.get("type") == "object"
            and downstream.get("additionalProperties") is False,
            "Automation Decision Receipt downstream run schema must remain closed")
    require(downstream.get("required") == DISPATCH_DOWNSTREAM_REQUIRED,
            "Automation Decision Receipt downstream run required set changed")
    fields = downstream.get("properties", {})
    require(fields.get("runAttempt") == {"const": 1},
            "Automation Decision Receipt downstream run attempt schema changed")
    require(fields.get("path") == {"const": builder.SPOTLIGHT_WORKFLOW}
            and fields.get("event") == {"const": "workflow_dispatch"}
            and fields.get("headBranch") == {"const": "main"},
            "Automation Decision Receipt downstream workflow/event/branch schema changed")
    require(fields.get("actorLogin") == {"const": builder.BOT_LOGIN}
            and fields.get("actorId") == {"const": builder.BOT_ID}
            and fields.get("triggeringActorLogin") == {"const": builder.BOT_LOGIN}
            and fields.get("triggeringActorId") == {"const": builder.BOT_ID},
            "Automation Decision Receipt downstream bot actor schema changed")
    require(fields.get("repository") == {"const": builder.REPOSITORY}
            and fields.get("headRepository") == {"const": builder.REPOSITORY},
            "Automation Decision Receipt downstream repository schema changed")
    for field in ("workflowId", "runId", "checkSuiteId", "repositoryId", "headRepositoryId"):
        require(fields.get(field) == {"$ref": "#/$defs/positiveInteger"},
                f"Automation Decision Receipt downstream {field} schema changed")
    require(fields.get("headSha") == {"$ref": "#/$defs/sha40"},
            "Automation Decision Receipt downstream head SHA schema changed")

    ancestry = observed.get("sourceAncestry")
    require(isinstance(ancestry, dict) and ancestry.get("type") == "object"
            and ancestry.get("additionalProperties") is False,
            "Automation Decision Receipt dispatch source ancestry must remain closed")
    require(ancestry.get("required") == DISPATCH_ANCESTRY_REQUIRED,
            "Automation Decision Receipt dispatch source ancestry required set changed")
    ancestry_fields = ancestry.get("properties", {})
    for field in ("baseSha", "headSha", "mergeBaseSha"):
        require(ancestry_fields.get(field) == {"$ref": "#/$defs/sha40"},
                f"Automation Decision Receipt dispatch source ancestry {field} schema changed")
    require(ancestry_fields.get("status") == {"enum": ["identical", "ahead"]},
            "Automation Decision Receipt dispatch source ancestry status schema changed")
    require(ancestry_fields.get("aheadBy") == {"$ref": "#/$defs/nonNegativeInteger"},
            "Automation Decision Receipt dispatch source ancestry aheadBy schema changed")
    require(ancestry_fields.get("behindBy") == {"const": 0},
            "Automation Decision Receipt dispatch source ancestry behindBy schema changed")


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

    definitions = schema.get("$defs", {})
    require(definitions.get("nonNegativeInteger") == {"type": "integer", "minimum": 0},
            "Automation Decision Receipt non-negative integer schema changed")
    effect = definitions.get("effect")
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
    validate_dispatch_schema(conditions)


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

    changed_dispatch = copy.deepcopy(schema)
    dispatch = dispatch_condition(changed_dispatch["$defs"]["effect"]["allOf"])
    dispatch["then"]["properties"]["observation"]["properties"]["downstreamRun"]["properties"]["event"] = {
        "const": "schedule"
    }
    try:
        validate(changed_dispatch)
    except ValueError as exc:
        require("workflow/event/branch" in str(exc),
                f"schema-binding dispatch self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("schema-binding self-test accepted changed downstream dispatch event")

    changed_ancestry = copy.deepcopy(schema)
    dispatch = dispatch_condition(changed_ancestry["$defs"]["effect"]["allOf"])
    dispatch["then"]["properties"]["observation"]["properties"]["sourceAncestry"]["properties"]["status"] = {
        "enum": ["identical", "ahead", "diverged"]
    }
    try:
        validate(changed_ancestry)
    except ValueError as exc:
        require("source ancestry status" in str(exc),
                f"schema-binding ancestry self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("schema-binding self-test accepted broadened dispatch ancestry status")
