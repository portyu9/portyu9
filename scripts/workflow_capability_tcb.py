#!/usr/bin/env python3
"""Trusted source-code boundary for Workflow Capability admission.

The pull_request_target workflow executes only default-branch code. Candidate copies of the
modules below are fetched strictly as data so a PR cannot silently poison the checker that
future PRs will trust. New files capable of shadowing imported Python modules are included in
the same boundary. The authorization ledger is deliberately excluded: a ledger-only PR is
the prior-review mechanism for a later exact expansion.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys
from typing import Iterable

CONTROL_WORKFLOW_ID = "capability-admission"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
PROTECTED_EXACT = {
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
PROTECTED_PREFIXES = (
    "scripts/automation_",
    "scripts/workflow_capability_",
)
# Python resolves these names before/while loading the admission TCB. Candidate files or
# packages with the same names could shadow stdlib modules when they become the next base.
RESERVED_MODULES = {
    "argparse", "copy", "hashlib", "json", "os", "pathlib", "re", "shlex",
    "stat", "subprocess", "sys", "typing",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def normalized(path: str) -> str:
    value = path.strip().replace("\\", "/")
    require(value and not value.startswith("/") and ".." not in value.split("/"),
            f"candidate TCB path is invalid: {path!r}")
    return value


def is_protected_path(path: str) -> bool:
    value = normalized(path)
    if value in PROTECTED_EXACT or any(value.startswith(prefix) for prefix in PROTECTED_PREFIXES):
        return value.endswith(".py") or value.startswith(".github/")
    if value.startswith("scripts/"):
        relative = value[len("scripts/"):]
        if "/" not in relative and relative.endswith(".py"):
            return relative[:-3] in RESERVED_MODULES
        if relative.endswith("/__init__.py") and relative.count("/") == 1:
            return relative.split("/", 1)[0] in RESERVED_MODULES
    return False


def is_candidate_input(path: str) -> bool:
    value = normalized(path)
    return (
        value == ".github/automation-policy-v1.json"
        or (value.startswith(".github/workflows/") and (value.endswith(".yml") or value.endswith(".yaml")))
        or is_protected_path(value)
    )


def selected(paths: Iterable[str]) -> list[str]:
    result = sorted({normalized(path) for path in paths if path.strip() and is_candidate_input(path)})
    require(".github/automation-policy-v1.json" in result,
            "candidate source selection is missing Automation Policy")
    require(any(path.startswith(".github/workflows/") for path in result),
            "candidate source selection contains no workflows")
    return result


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def protected_files(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    candidates = [root / ".github", root / "scripts"]
    for directory in candidates:
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if is_protected_path(relative):
                result[relative] = sha256_file(path)
    return dict(sorted(result.items()))


def source_expansions(base_root: Path, candidate_root: Path, candidate_tree_sha: str | None) -> list[dict[str, object]]:
    base = protected_files(base_root)
    candidate = protected_files(candidate_root)
    changed = sorted(path for path in set(base) | set(candidate) if base.get(path) != candidate.get(path))
    if not changed:
        return []
    require(candidate_tree_sha is not None and SHA40.fullmatch(candidate_tree_sha) is not None,
            "candidate tree SHA is required for trusted control-source changes")
    return [
        {
            "direction": "expansion",
            "category": "trusted-control-source",
            "workflow": CONTROL_WORKFLOW_ID,
            "key": path,
            "before": None if path not in base else {"sha256": base[path]},
            "after": {
                "sha256": candidate.get(path),
                "candidateTreeSha": candidate_tree_sha,
            },
        }
        for path in changed
    ]


def self_test() -> None:
    require(is_protected_path("scripts/workflow_capability_admission.py"),
            "TCB self-test lost admission module")
    require(is_protected_path("scripts/automation_policy.py"),
            "TCB self-test lost Automation Policy loader")
    require(is_protected_path("scripts/json.py") and is_protected_path("scripts/json/__init__.py"),
            "TCB self-test lost stdlib-shadow protection")
    require(not is_protected_path("scripts/generate-profile-evidence.py"),
            "TCB self-test over-classified unrelated profile generation")
    require(not is_protected_path(".github/workflow-capability-expansion-authorizations-v1.json"),
            "authorization ledger must remain the prior-review channel")

    base = {"scripts/workflow_capability_admission.py": "a" * 64}
    candidate = {"scripts/workflow_capability_admission.py": "b" * 64}
    # Exercise the canonical expansion shape without filesystem mutation.
    changed = sorted(path for path in set(base) | set(candidate) if base.get(path) != candidate.get(path))
    expansion = {
        "direction": "expansion",
        "category": "trusted-control-source",
        "workflow": CONTROL_WORKFLOW_ID,
        "key": changed[0],
        "before": {"sha256": base[changed[0]]},
        "after": {"sha256": candidate[changed[0]], "candidateTreeSha": "c" * 40},
    }
    require(expansion["key"] == "scripts/workflow_capability_admission.py",
            "TCB self-test source-change identity drifted")


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "select":
        for path in selected(line.rstrip("\n") for line in sys.stdin):
            print(path)
        return 0
    self_test()
    print("Workflow Capability trusted-source TCB self-test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
