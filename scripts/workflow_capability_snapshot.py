#!/usr/bin/env python3
"""Load the canonical Workflow Capability BOM as a strict composite snapshot.

The item-12 five-workflow snapshot remains byte-frozen. Item 13 adds the trusted admission
workflow as a small canonical extension. This module is the only assembly boundary: callers
receive one ordinary six-workflow BOM object whose semantic/canonical representation is
compared with live trusted compilation.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import automation_policy
import workflow_capability_bom as compiler

ROOT = Path(__file__).resolve().parents[1]
BASE_SNAPSHOT = ROOT / ".github/workflow-capability-bom-v1.json"
ADMISSION_EXTENSION = ROOT / ".github/workflow-capability-bom-v1-capability-admission.json"
EXPECTED_ROOT_KEYS = {"schemaVersion", "bomId", "repository", "automationPolicyId", "workflows"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_part(path: Path, label: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"{label} is missing or aliased: {path}")
    raw = path.read_text(encoding="utf-8")
    try:
        payload = automation_policy.strict_json_loads(raw)
    except (UnicodeDecodeError, ValueError) as exc:
        raise ValueError(f"{label} JSON is invalid: {exc}") from exc
    require(isinstance(payload, dict), f"{label} root must be an object")
    require(set(payload) == EXPECTED_ROOT_KEYS, f"{label} root keys changed: {sorted(payload)}")
    require(payload.get("schemaVersion") == compiler.SCHEMA_VERSION, f"{label} schema version changed")
    require(payload.get("bomId") == compiler.BOM_ID, f"{label} BOM identity changed")
    require(payload.get("repository") == automation_policy.REPOSITORY, f"{label} repository changed")
    require(payload.get("automationPolicyId") == automation_policy.POLICY_ID,
            f"{label} Automation Policy binding changed")
    require(isinstance(payload.get("workflows"), list), f"{label} workflows must be an array")
    require(raw == compiler.canonical_json(payload), f"{label} bytes are not canonical JSON")
    return payload


def load_combined() -> dict[str, Any]:
    base = load_part(BASE_SNAPSHOT, "base Workflow Capability BOM snapshot")
    extension = load_part(ADMISSION_EXTENSION, "Capability admission BOM extension")
    require(len(base["workflows"]) == 5, "base Workflow Capability BOM historical workflow count changed")
    require(len(extension["workflows"]) == 1, "Capability admission BOM extension must contain exactly one workflow")
    admission = extension["workflows"][0]
    require(admission.get("id") == "capability-admission",
            "Capability admission BOM extension workflow identity changed")
    require(admission.get("path") == ".github/workflows/capability-admission.yml",
            "Capability admission BOM extension workflow path changed")

    workflows = list(base["workflows"]) + list(extension["workflows"])
    ids = [workflow.get("id") for workflow in workflows]
    paths = [workflow.get("path") for workflow in workflows]
    require(len(ids) == len(set(ids)), "composite Workflow Capability BOM contains duplicate workflow IDs")
    require(len(paths) == len(set(paths)), "composite Workflow Capability BOM contains duplicate workflow paths")
    workflows.sort(key=lambda workflow: workflow["path"])

    combined = {key: base[key] for key in base if key != "workflows"}
    combined["workflows"] = workflows
    return combined


def self_test() -> None:
    combined = load_combined()
    require(len(combined["workflows"]) == 6, "composite Workflow Capability BOM must contain six workflows")
    require(combined["workflows"][0]["id"] == "capability-admission",
            "composite Workflow Capability BOM ordering changed")


if __name__ == "__main__":
    self_test()
    print("Composite Workflow Capability BOM snapshot validation passed: 6 workflows.")
