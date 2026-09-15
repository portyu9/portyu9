#!/usr/bin/env python3
"""Trusted source-code boundary for Workflow Capability admission.

The pull_request_target workflow executes only default-branch code. Candidate control-source
bytes are never executed and, for Python TCB files, are never materialized into the trusted
workspace at their repository path. The workflow supplies a digest-only manifest computed
from exact Git blobs. New files capable of shadowing imported Python modules are included in
the same boundary. The authorization ledger is deliberately excluded: a ledger-only PR is
the prior-review mechanism for a later exact expansion.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Iterable, Mapping

CONTROL_WORKFLOW_ID = "capability-admission"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]+$")
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
RESERVED_MODULES = {
    "argparse", "copy", "hashlib", "json", "os", "pathlib", "re", "shlex",
    "stat", "subprocess", "sys", "typing",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def normalized(path: str) -> str:
    """Return one safe repository-relative candidate path or fail closed."""
    require(isinstance(path, str) and path != "", f"candidate TCB path is invalid: {path!r}")
    require(path == path.strip(), f"candidate TCB path has surrounding whitespace: {path!r}")
    require("\\" not in path and not path.startswith("/"),
            f"candidate TCB path is not canonical repository syntax: {path!r}")
    require(not any(ord(character) < 32 or ord(character) == 127 for character in path),
            f"candidate TCB path contains a control character: {path!r}")
    parts = path.split("/")
    require(all(part not in {"", ".", ".."} for part in parts),
            f"candidate TCB path contains an unsafe component: {path!r}")
    require(all(SAFE_COMPONENT.fullmatch(part) is not None for part in parts),
            f"candidate TCB path contains unsupported characters: {path!r}")
    return path


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


def _might_be_candidate_input(path: str) -> bool:
    """Cheap raw-path prefilter so unrelated repository names need no canonical restriction."""
    if path == ".github/automation-policy-v1.json" or path.startswith(".github/workflows/"):
        return True
    if path in PROTECTED_EXACT or any(path.startswith(prefix) for prefix in PROTECTED_PREFIXES):
        return True
    if not path.startswith("scripts/"):
        return False
    relative = path[len("scripts/"):]
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
    result: set[str] = set()
    for raw in paths:
        if not isinstance(raw, str) or not raw or not _might_be_candidate_input(raw):
            continue
        value = normalized(raw)
        if is_candidate_input(value):
            result.add(value)
    ordered = sorted(result)
    require(".github/automation-policy-v1.json" in ordered,
            "candidate source selection is missing Automation Policy")
    require(any(path.startswith(".github/workflows/") for path in ordered),
            "candidate source selection contains no workflows")
    return ordered


def select_json(stream: object) -> list[str]:
    try:
        value = json.load(stream)  # type: ignore[arg-type]
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"candidate Git tree path array is invalid JSON: {exc}") from exc
    require(isinstance(value, list) and all(isinstance(item, str) for item in value),
            "candidate Git tree path input must be an array of strings")
    require(len(value) == len(set(value)), "candidate Git tree path array contains duplicates")
    return selected(value)


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
            if _might_be_candidate_input(relative) and is_protected_path(relative):
                result[relative] = sha256_file(path)
    return dict(sorted(result.items()))


def validate_manifest(files: Mapping[str, str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_path, digest in files.items():
        require(isinstance(raw_path, str) and isinstance(digest, str),
                "candidate TCB manifest must map string paths to string SHA-256 values")
        path = normalized(raw_path)
        require(is_protected_path(path), f"candidate TCB manifest contains an unprotected path: {path}")
        require(SHA256.fullmatch(digest) is not None,
                f"candidate TCB manifest contains an invalid SHA-256 for {path}")
        require(path not in result, f"candidate TCB manifest duplicates path: {path}")
        result[path] = digest
    return dict(sorted(result.items()))


def load_manifest(path: Path) -> dict[str, str]:
    """Load a trusted-workflow-produced path<TAB>sha256 manifest as untrusted data."""
    require(path.is_file() and not path.is_symlink(), f"candidate TCB manifest is missing or aliased: {path}")
    entries: dict[str, str] = {}
    previous: str | None = None
    for line_number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        fields = raw.split("\t")
        require(len(fields) == 2, f"candidate TCB manifest line {line_number} is malformed")
        candidate_path, digest = fields
        candidate_path = normalized(candidate_path)
        require(previous is None or previous < candidate_path,
                "candidate TCB manifest paths must be strictly sorted and unique")
        previous = candidate_path
        require(candidate_path not in entries, f"candidate TCB manifest duplicates path: {candidate_path}")
        entries[candidate_path] = digest
    return validate_manifest(entries)


def protected_digest(files: Mapping[str, str]) -> str:
    validated = validate_manifest(files)
    payload = b"".join(
        path.encode("utf-8") + b"\0" + validated[path].encode("ascii") + b"\n"
        for path in sorted(validated)
    )
    return hashlib.sha256(payload).hexdigest()


def source_expansions(
    base_root: Path,
    candidate_root: Path,
    candidate_tree_sha: str | None,
    *,
    candidate_manifest: Mapping[str, str] | None = None,
) -> list[dict[str, object]]:
    base = protected_files(base_root)
    candidate = protected_files(candidate_root) if candidate_manifest is None else validate_manifest(candidate_manifest)
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
    require(is_protected_path("scripts/json.py") and is_protected_path("scripts/json/__init__.py"),
            "TCB self-test lost stdlib-shadow protection")
    require(not is_protected_path("scripts/generate-profile-evidence.py"),
            "TCB self-test over-classified unrelated profile generation")
    require(not is_protected_path(".github/workflow-capability-expansion-authorizations-v1.json"),
            "authorization ledger must remain the prior-review channel")
    for bad in (
        "scripts/../json.py",
        "scripts/workflow_capability_bad name.py",
        "scripts/workflow_capability_bad\nname.py",
        "scripts\\workflow_capability_bad.py",
    ):
        try:
            normalized(bad)
        except ValueError:
            pass
        else:
            raise ValueError(f"TCB self-test accepted unsafe candidate path: {bad!r}")

    base = {"scripts/workflow_capability_admission.py": "a" * 64}
    candidate = {"scripts/workflow_capability_admission.py": "b" * 64}
    base_digest = protected_digest(base)
    candidate_digest = protected_digest(candidate)
    require(base_digest != candidate_digest,
            "TCB self-test source digest failed to distinguish protected source changes")
    require(validate_manifest(candidate) == candidate,
            "TCB self-test candidate manifest validation drifted")
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
    if len(sys.argv) == 2 and sys.argv[1] == "select-json":
        try:
            for path in select_json(sys.stdin):
                print(path)
            return 0
        except ValueError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
    self_test()
    print("Workflow Capability trusted-source TCB self-test passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
