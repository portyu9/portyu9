#!/usr/bin/env python3
"""Recompile and validate the canonical Workflow Capability BOM snapshot."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys
from typing import Any
from urllib.request import urlopen

import capability_admission_workflow_contract
import trusted_workflow_capability
import workflow_capability_admission
import workflow_capability_authorization
import workflow_capability_bom as compiler
import workflow_capability_diff as capability_diff
import workflow_capability_snapshot

ROOT = Path(__file__).resolve().parents[1]
DIAGNOSTIC_BASE = "604c4ea335f0f2979ec7ec542032c45158af6281"
DIAGNOSTIC_TCB = "scripts/workflow_capability_tcb.py"
LEGACY_PROTECTED_EXACT = {
    ".github/workflow-capability-bom-v1.json",
    ".github/workflow-capability-bom-v1-capability-admission.json",
    ".github/workflows/capability-admission.yml",
    "scripts/profile_stats_decision_receipt.py",
    "scripts/spotlight_decision_receipt.py",
    "scripts/spotlight_profile_links.py",
    "scripts/trusted_workflow_capability.py",
    "scripts/verify-python-runtime.py",
    "scripts/workflow_authority_contract_core.py",
}
LEGACY_PROTECTED_PREFIXES = (
    "scripts/automation_",
    "scripts/workflow_capability_",
)
LEGACY_RESERVED_MODULES = {
    "argparse", "copy", "hashlib", "json", "os", "pathlib", "re", "shlex",
    "stat", "subprocess", "sys", "typing",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def first_difference(expected: Any, observed: Any, path: str = "$") -> str | None:
    if type(expected) is not type(observed):
        return f"{path}: type expected={type(expected).__name__} observed={type(observed).__name__}"
    if isinstance(expected, dict):
        expected_keys = set(expected)
        observed_keys = set(observed)
        if expected_keys != observed_keys:
            return f"{path}: keys expected={sorted(expected_keys)} observed={sorted(observed_keys)}"
        for key in sorted(expected):
            difference = first_difference(expected[key], observed[key], f"{path}.{key}")
            if difference is not None:
                return difference
        return None
    if isinstance(expected, list):
        if len(expected) != len(observed):
            return f"{path}: length expected={len(expected)} observed={len(observed)}"
        for index, (left, right) in enumerate(zip(expected, observed, strict=True)):
            difference = first_difference(left, right, f"{path}[{index}]")
            if difference is not None:
                return difference
        return None
    if expected != observed:
        return f"{path}: expected={expected!r} observed={observed!r}"
    return None


def legacy_protected(path: str) -> bool:
    value = path.strip().replace("\\", "/")
    require(value and not value.startswith("/") and ".." not in value.split("/"),
            f"diagnostic TCB path invalid: {path!r}")
    if value in LEGACY_PROTECTED_EXACT or any(value.startswith(prefix) for prefix in LEGACY_PROTECTED_PREFIXES):
        return value.endswith(".py") or value.startswith(".github/")
    if value.startswith("scripts/"):
        relative = value[len("scripts/"):]
        if "/" not in relative and relative.endswith(".py"):
            return relative[:-3] in LEGACY_RESERVED_MODULES
        if relative.endswith("/__init__.py") and relative.count("/") == 1:
            return relative.split("/", 1)[0] in LEGACY_RESERVED_MODULES
    return False


def diagnostic_protected_digest() -> tuple[str, str, str]:
    files: dict[str, str] = {}
    for directory in (ROOT / ".github", ROOT / "scripts"):
        for path in directory.rglob("*"):
            if path.is_file() and not path.is_symlink():
                relative = path.relative_to(ROOT).as_posix()
                if legacy_protected(relative):
                    files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    payload = b"".join(
        path.encode("utf-8") + b"\0" + files[path].encode("ascii") + b"\n"
        for path in sorted(files)
    )
    candidate_tcb_digest = hashlib.sha256(payload).hexdigest()
    candidate_tcb_sha = files[DIAGNOSTIC_TCB]

    url = f"https://raw.githubusercontent.com/portyu9/portyu9/{DIAGNOSTIC_BASE}/{DIAGNOSTIC_TCB}"
    with urlopen(url, timeout=15) as response:  # noqa: S310 - immutable constant GitHub URL for disposable hash diagnostic.
        base_bytes = response.read()
    base_tcb_sha = hashlib.sha256(base_bytes).hexdigest()
    return base_tcb_sha, candidate_tcb_sha, candidate_tcb_digest


def emit_authorization_diagnostic() -> None:
    snapshot = workflow_capability_snapshot.load_combined()
    bom_sha = capability_diff.digest(snapshot)
    base_tcb_sha, candidate_tcb_sha, candidate_tcb_digest = diagnostic_protected_digest()
    expansion = [{
        "direction": "expansion",
        "category": "trusted-control-source",
        "workflow": "capability-admission",
        "key": DIAGNOSTIC_TCB,
        "before": {"sha256": base_tcb_sha},
        "after": {
            "sha256": candidate_tcb_sha,
            "candidateTcbSha256": candidate_tcb_digest,
        },
    }]
    expansion_sha = capability_diff.digest(expansion)
    print(
        "TCB_AUTH_DIAGNOSTIC "
        f"baseBomSha256={bom_sha} candidateBomSha256={bom_sha} expansionSha256={expansion_sha} "
        f"baseTcbFileSha256={base_tcb_sha} candidateTcbFileSha256={candidate_tcb_sha} "
        f"candidateTcbSha256={candidate_tcb_digest}"
    )


def validate_snapshot() -> tuple[int, int]:
    snapshot = workflow_capability_snapshot.load_combined()

    compiler.self_test()
    capability_diff.self_test()
    trusted_workflow_capability.self_test()
    workflow_capability_authorization.self_test()
    workflow_capability_snapshot.self_test()
    capability_admission_workflow_contract.self_test()
    capability_admission_workflow_contract.validate()
    workflow_capability_admission.self_test()

    compiled = compiler.compile_bom()
    difference = first_difference(compiled, snapshot)
    if difference is not None:
        raise ValueError(f"Workflow Capability BOM snapshot differs from compiled source: {difference}")

    require(compiler.canonical_json(snapshot) == compiler.canonical_json(compiled),
            "composite Workflow Capability BOM canonical bytes differ from live compilation")
    identity_diff = capability_diff.semantic_diff(snapshot, compiled)
    require(not identity_diff["hasExpansion"] and not identity_diff["reductions"],
            "identical canonical BOMs produced a semantic capability diff")

    workflows = compiled["workflows"]
    jobs = sum(len(workflow["jobs"]) for workflow in workflows)
    require(len(workflows) == 6, f"Workflow Capability BOM workflow count changed: {len(workflows)}")
    require(jobs > 0, "Workflow Capability BOM contains no jobs")
    return len(workflows), jobs


def main() -> int:
    try:
        emit_authorization_diagnostic()
        workflows, jobs = validate_snapshot()
        print(
            f"Workflow Capability BOM validation passed: {workflows} workflows, {jobs} jobs; "
            "semantic diff, trusted alternate-tree compiler, exact expansion authorization, "
            "composite snapshot, exact trusted-workflow bytes, and admission self-tests passed."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
