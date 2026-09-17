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
    ".github/workflow-capability-bom-v1-codeql-autofix.json",
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
    "scripts/codeql_autofix_",
    "scripts/dependabot_",
    "scripts/workflow_capability_",
)
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
    for directory in (root / ".github", root / "scripts"):
        if not directory.is_dir():
            continue
        for path in directory.rglob("*"):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(root).as_posix()
            if is_protected_path(relative):
                result[relative] = sha256_file(path)
    return dict(sorted(result.items()))


def protected_digest(files: dict[str, str]) -> str:
    require(all(isinstance(path, str) and path for path in files),
            "trusted control-source digest contains an invalid path")
    require(all(re.fullmatch(r"[0-9a-f]{64}", digest) is not None for digest in files.values()),
            "trusted control-source digest contains an invalid file SHA-256")
    payload = b"".join(
        path.encode("utf-8") + b"\0" + files[path].encode("ascii") + b"\n"
        for path in sorted(files)
    )
    return hashlib.sha256(payload).hexdigest()


def source_expansions(base_root: Path, candidate_root: Path, candidate_tree_sha: str | None) -> list[dict[str, object]]:
    base = protected_files(base_root)
    candidate = protected_files(candidate_root)
    changed = sorted(path for path in set(base) | set(candidate) if base.get(path) != candidate.get(path))
    if not changed:
        return []

    # The exact tree SHA remains a transport/freshness proof for the fetched candidate bytes,
    # but it is intentionally not part of the authorization digest. The trusted authorization
    # ledger lives in the repository tree, so binding that tree into a record stored in the
    # ledger would create a cryptographic self-reference. Instead bind the complete protected
    # TCB map; ledger-only prior-review PRs cannot change this digest.
    require(candidate_tree_sha is not None and SHA40.fullmatch(candidate_tree_sha) is not None,
            "candidate tree SHA is required for trusted control-source changes")
    candidate_tcb_sha256 = protected_digest(candidate)
    return [
        {
            "direction": "expansion",
            "category": "trusted-control-source",
            "workflow": CONTROL_WORKFLOW_ID,
            "key": path,
            "before": None if path not in base else {"sha256": base[path]},
            "after": {
                "sha256": candidate.get(path),
                "candidateTcbSha256": candidate_tcb_sha256,
            },
        }
        for path in changed
    ]


def self_test() -> None:
    require(is_protected_path("scripts/workflow_capability_admission.py"),
            "TCB self-test lost admission module")
    require(is_protected_path("scripts/automation_policy.py"),
            "TCB self-test lost Automation Policy loader")
    require(is_protected_path(".github/workflow-capability-bom-v1-codeql-autofix.json"),
            "TCB self-test lost CodeQL Autofix BOM extension")
    for path in (
        "scripts/codeql_autofix_admission.py",
        "scripts/codeql_autofix_controller_contract.py",
        "scripts/codeql_autofix_discovery.py",
        "scripts/codeql_autofix_future_module.py",
    ):
        require(is_protected_path(path),
                f"TCB self-test lost CodeQL Autofix controller source: {path}")
    for path in (
        "scripts/dependabot_admission.py",
        "scripts/dependabot_pin_diff.py",
        "scripts/dependabot_pr_identity.py",
        "scripts/dependabot_reconciliation.py",
        "scripts/dependabot_future_module.py",
    ):
        require(is_protected_path(path),
                f"TCB self-test lost Dependabot controller source: {path}")
    require(is_protected_path("scripts/json.py") and is_protected_path("scripts/json/__init__.py"),
            "TCB self-test lost stdlib-shadow protection")
    require(not is_protected_path("scripts/generate-profile-evidence.py"),
            "TCB self-test over-classified unrelated profile generation")
    require(not is_protected_path(".github/workflow-capability-expansion-authorizations-v1.json"),
            "authorization ledger must remain the prior-review channel")

    base = {"scripts/workflow_capability_admission.py": "a" * 64}
    candidate = {"scripts/workflow_capability_admission.py": "b" * 64}
    base_digest = protected_digest(base)
    candidate_digest = protected_digest(candidate)
    require(base_digest != candidate_digest,
            "TCB self-test source digest failed to distinguish protected source changes")
    expansion = {
        "direction": "expansion",
        "category": "trusted-control-source",
        "workflow": CONTROL_WORKFLOW_ID,
        "key": "scripts/workflow_capability_admission.py",
        "before": {"sha256": base["scripts/workflow_capability_admission.py"]},
        "after": {
            "sha256": candidate["scripts/workflow_capability_admission.py"],
            "candidateTcbSha256": candidate_digest,
        },
    }
    require("candidateTreeSha" not in expansion["after"] and
            expansion["after"]["candidateTcbSha256"] == candidate_digest,
            "TCB self-test reintroduced self-referential candidate-tree authorization")


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
