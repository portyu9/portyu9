#!/usr/bin/env python3
"""Bind attestation-builder identity/claim constants to immutable v3 schema consts.

The builder validates predicates against its own constants. This independent contract
prevents those constants and their self-tests from drifting together away from the
published profile-evidence-v3 schema and exact production workflow identity.
"""
from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts/build-profile-evidence-attestation.py"
SCHEMA = ROOT / ".github/attestation/profile-evidence-v3.schema.json"

TARGETS = (
    "REPOSITORY",
    "WORKFLOW_REF",
    "KIND",
    "SCHEMA_VERSION",
    "PREDICATE_TYPE",
    "EVIDENCE_SCHEMA",
    "PORTFOLIO_LEDGER_VERSION",
    "PORTFOLIO_EVIDENCE_SEMANTICS",
    "AUTHORITY_SEPARATION",
    "CLAIM",
)
EXPECTED_WORKFLOW_REF = "portyu9/portyu9/.github/workflows/profile-stats.yml@refs/heads/main"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def evaluate_static(node: ast.AST, resolved: dict[str, object]) -> object:
    """Evaluate only the tiny literal/f-string subset used by builder identity constants."""
    try:
        return ast.literal_eval(node)
    except (ValueError, TypeError):
        pass
    if isinstance(node, ast.JoinedStr):
        pieces: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                pieces.append(value.value)
            elif isinstance(value, ast.FormattedValue) and isinstance(value.value, ast.Name):
                bound = resolved.get(value.value.id)
                require(isinstance(bound, str), f"unresolved/non-string f-string binding: {value.value.id}")
                require(value.conversion == -1 and value.format_spec is None,
                        "formatted/conversion f-string syntax is forbidden in attestation identity constants")
                pieces.append(bound)
            else:
                raise ValueError("dynamic attestation identity constant expression is forbidden")
        return "".join(pieces)
    raise ValueError("dynamic attestation identity constant expression is forbidden")


def builder_constants(source: str) -> dict[str, object]:
    tree = ast.parse(source, filename=str(BUILDER))
    resolved: dict[str, object] = {}
    seen: set[str] = set()
    for node in tree.body:
        target: ast.Name | None = None
        value: ast.AST | None = None
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target = node.targets[0]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            target = node.target
            value = node.value
        if target is None or value is None or target.id not in TARGETS:
            continue
        require(target.id not in seen, f"duplicate attestation builder constant: {target.id}")
        resolved[target.id] = evaluate_static(value, resolved)
        seen.add(target.id)
    require(set(resolved) == set(TARGETS),
            f"attestation builder constant inventory changed: expected={sorted(TARGETS)} observed={sorted(resolved)}")
    return resolved


def schema_const(schema: dict[str, Any], *path: str) -> object:
    current: object = schema
    for key in path:
        require(isinstance(current, dict) and key in current,
                "attestation v3 schema binding path is missing: " + ".".join(path))
        current = current[key]
    return current


def expected_bindings(schema: dict[str, Any]) -> dict[str, object]:
    return {
        "REPOSITORY": schema_const(schema, "properties", "repository", "const"),
        "KIND": schema_const(schema, "properties", "kind", "const"),
        "SCHEMA_VERSION": schema_const(schema, "properties", "schemaVersion", "const"),
        "PREDICATE_TYPE": schema_const(schema, "properties", "predicateSchema", "properties", "id", "const"),
        "EVIDENCE_SCHEMA": schema_const(schema, "properties", "signalFieldEvidence", "properties", "schema", "const"),
        "PORTFOLIO_LEDGER_VERSION": schema_const(schema, "properties", "portfolioEvidenceLedger", "properties", "version", "const"),
        "PORTFOLIO_EVIDENCE_SEMANTICS": schema_const(schema, "properties", "portfolioEvidenceLedger", "properties", "semantics", "const"),
        "AUTHORITY_SEPARATION": schema_const(schema, "properties", "authority", "properties", "separation", "const"),
        "CLAIM": schema_const(schema, "properties", "claim", "const"),
    }


def validate_values(values: dict[str, object], schema: dict[str, Any]) -> None:
    expected = expected_bindings(schema)
    for name, schema_value in expected.items():
        require(values.get(name) == schema_value,
                f"attestation builder {name} differs from immutable v3 schema const")
    require(values.get("WORKFLOW_REF") == EXPECTED_WORKFLOW_REF,
            "attestation builder WORKFLOW_REF differs from exact production workflow identity")
    require(values.get("REPOSITORY") == "portyu9/portyu9",
            "attestation builder repository differs from governed repository")

    authority = schema_const(schema, "properties", "authority", "properties")
    require(isinstance(authority, dict), "attestation v3 authority schema is malformed")
    fixed_authority = {
        "generation": "contents:read",
        "attestation": "contents:read,id-token:write,attestations:write",
        "publication": "contents:write",
    }
    for key, expected_value in fixed_authority.items():
        require(schema_const(schema, "properties", "authority", "properties", key, "const") == expected_value,
                f"attestation v3 schema {key} authority const changed")


def fixture_schema() -> dict[str, Any]:
    return {
        "properties": {
            "schemaVersion": {"const": 3},
            "kind": {"const": "profile-evidence-attestation"},
            "repository": {"const": "portyu9/portyu9"},
            "predicateSchema": {"properties": {"id": {"const": "https://example.test/v3.json"}}},
            "signalFieldEvidence": {"properties": {"schema": {"const": "signal-field-evidence-v1"}}},
            "portfolioEvidenceLedger": {"properties": {
                "version": {"const": "portfolio-evidence-ledger-v2"},
                "semantics": {"const": "execution-result-subject-binding-freshness-v1"},
            }},
            "authority": {"properties": {
                "generation": {"const": "contents:read"},
                "attestation": {"const": "contents:read,id-token:write,attestations:write"},
                "publication": {"const": "contents:write"},
                "separation": {"const": "separated"},
            }},
            "claim": {"const": "bounded claim"},
        }
    }


def self_test() -> None:
    source = '''\
REPOSITORY = "portyu9/portyu9"
WORKFLOW_REF = f"{REPOSITORY}/.github/workflows/profile-stats.yml@refs/heads/main"
KIND = "profile-evidence-attestation"
SCHEMA_VERSION = 3
PREDICATE_TYPE = ("https://example.test/" "v3.json")
EVIDENCE_SCHEMA = "signal-field-evidence-v1"
PORTFOLIO_LEDGER_VERSION = "portfolio-evidence-ledger-v2"
PORTFOLIO_EVIDENCE_SEMANTICS = "execution-result-subject-binding-freshness-v1"
AUTHORITY_SEPARATION = ("sepa" "rated")
CLAIM = "bounded claim"
'''
    schema = fixture_schema()
    values = builder_constants(source)
    validate_values(values, schema)

    for label, name, value, expected in (
        ("claim", "CLAIM", "expanded claim", "CLAIM"),
        ("authority separation", "AUTHORITY_SEPARATION", "not separated", "AUTHORITY_SEPARATION"),
        ("repository", "REPOSITORY", "other/repo", "REPOSITORY"),
        ("predicate type", "PREDICATE_TYPE", "https://example.test/v4.json", "PREDICATE_TYPE"),
        ("workflow ref", "WORKFLOW_REF", "portyu9/portyu9/.github/workflows/other.yml@refs/heads/main", "WORKFLOW_REF"),
    ):
        mutated = dict(values)
        mutated[name] = value
        try:
            validate_values(mutated, schema)
        except ValueError as exc:
            require(expected in str(exc), f"{label} self-test failed for wrong reason: {exc}")
        else:
            raise ValueError(f"attestation schema binding self-test accepted {label} drift")

    schema_drift = copy.deepcopy(schema)
    schema_drift["properties"]["claim"]["const"] = "schema drift"
    try:
        validate_values(values, schema_drift)
    except ValueError as exc:
        require("CLAIM" in str(exc), f"schema-drift self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("attestation schema binding self-test accepted schema const drift")


def main() -> int:
    try:
        self_test()
        require(BUILDER.is_file() and not BUILDER.is_symlink(), "attestation builder must be one real regular file")
        require(SCHEMA.is_file() and not SCHEMA.is_symlink(), "attestation v3 schema must be one real regular file")
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        require(isinstance(schema, dict), "attestation v3 schema root must be an object")
        values = builder_constants(BUILDER.read_text(encoding="utf-8"))
        validate_values(values, schema)
        print(
            "Attestation builder/schema binding passed: builder identity, evidence semantics, authority separation, "
            "bounded claim, and exact production workflow ref match immutable v3 schema/governance constants"
        )
        return 0
    except (OSError, SyntaxError, json.JSONDecodeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
