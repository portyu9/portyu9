#!/usr/bin/env python3
"""Pure, fail-closed derivation for governed Dependabot artifact-action releases.

This module runs only from accepted, trusted main. An untrusted candidate is read
as inert workflow data. It cannot authorize a merge or perform GitHub mutations.
The existing delegated release proof must already bind bot identity, an atomic
pin-only update, immutable tag object and commit, and exact proposed head.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import runpy
from typing import Any, Mapping

from action_identity_lock import (
    ENTRY_KEYS,
    parse_action_lock_json,
    repository_for_action,
    validate_payload,
)
import trusted_workflow_capability
import workflow_capability_bom

REPOSITORIES = frozenset({
    "actions/upload-artifact",
    "actions/download-artifact",
})
SHA40 = re.compile(r"^[0-9a-f]{40}$")
LOCK_PATH = ".github/action-lock.json"
BOM_PATH = ".github/workflow-capability-bom-v1.json"
PRIVILEGED_IDENTITY = "scripts/validate-privileged-workflow-identity.py"
SOURCE_EPOCH_PATH = "scripts/profile-stats-source-epoch-v1.json"
SOURCE_EPOCH_COMPILER = "scripts/validate-profile-stats-trigger-contract.py"
PROFILE_STATS_WORKFLOW = ".github/workflows/profile-stats.yml"
WORKFLOW_PREFIX = ".github/workflows/"
SHARD_PREFIX = ".github/workflow-capability-bom-v1-"
# These are read-only validators/fixture contracts whose identity literals must
# follow the authenticated, exact candidate Action release.
REFERENCE_SOURCES = (
    "scripts/workflow_capability_bom.py",
    "scripts/validate-governance-contract.py",
    "scripts/validate-profile-upstream-retry.py",
    "scripts/governance_contract_item10_core.py",
    "scripts/profile_attestation_contract_item10_core.py",
    "scripts/action_provenance_witness.py",
    "scripts/validate-action-release-provenance.py",
    "scripts/workflow_authority_contract_item11_core.py",
    "scripts/spotlight_ui_merge_authorization_item10_core.py",
    "scripts/profile_generator_compatibility_witness.py",
    "scripts/validate-spotlight-ui-merge-authorization.py",
)


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n"


def identity(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, Mapping) and set(value) == set(ENTRY_KEYS),
            f"{label} release fields differ from the trusted lock schema")
    result = {key: value[key] for key in ENTRY_KEYS}
    require(isinstance(result["sha"], str) and SHA40.fullmatch(result["sha"]) is not None,
            f"{label} SHA is invalid")
    return result


def exact_release(proof: Mapping[str, Any]) -> tuple[str, dict[str, Any], dict[str, Any], set[str]]:
    require(proof.get("classification") == "allowed",
            "artifact reconciliation requires the exact admitted Dependabot proof")
    repo = proof.get("dependencyRepository")
    require(repo in REPOSITORIES, "artifact reconciliation refuses out-of-policy action repository")
    before = identity(proof.get("before"), "before")
    after = identity(proof.get("after"), "after")
    require(before["sha"] != after["sha"] and before["tag"] != after["tag"],
            "artifact reconciliation requires a changed, forward release")
    actions = proof.get("actions")
    require(type(actions) is list and actions == sorted(set(actions)) and bool(actions),
            "artifact reconciliation action inventory is not canonical")
    require(all(type(a) is str and repository_for_action(a) == repo for a in actions),
            "artifact reconciliation proof names an unrelated Action")
    return repo, before, after, set(actions)


def update_lock(trusted_text: str, proof: Mapping[str, Any]) -> str:
    repo, before, after, covered = exact_release(proof)
    payload = parse_action_lock_json(trusted_text)
    locked = validate_payload(payload)
    matched: set[str] = set()
    updated = copy.deepcopy(payload)
    for name in sorted(updated["actions"]):
        if repository_for_action(name) != repo:
            continue
        require(locked[name] == before,
                f"{repo} original lock identity does not match the admitted release")
        updated["actions"][name] = dict(after)
        matched.add(name)
    require(matched == covered,
            "artifact reconciliation did not update every locked Action subpath atomically")
    output = json.dumps(updated, indent=2, ensure_ascii=True) + "\n"
    validate_payload(parse_action_lock_json(output))
    return output


def update_literal_references(text: str, before: Mapping[str, Any],
                              after: Mapping[str, Any], path: str) -> str:
    old_sha, new_sha = before["sha"], after["sha"]
    old_tag, new_tag = before["tag"], after["tag"]
    changed = 0
    result: list[str] = []
    for line in text.splitlines(keepends=True):
        if old_sha in line:
            require(line.count(old_sha) == 1,
                    f"{path}: ambiguous multiple old-SHA references on one source line")
            # A same-line release tag is an inseparable part of the uses identity.
            if old_tag in line:
                require(line.count(old_tag) == 1,
                        f"{path}: ambiguous release tag near Action SHA")
                line = line.replace(old_tag, new_tag, 1)
            line = line.replace(old_sha, new_sha, 1)
            changed += 1
        result.append(line)
    require(changed > 0, f"{path}: no attested Action SHA references to refresh")
    updated = "".join(result)
    require(old_sha not in updated and new_sha in updated,
            f"{path}: Action reference replacement incomplete")
    return updated


def git_blob_sha(value: str) -> str:
    data = value.encode("utf-8")
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def update_privileged_identity(
    original: str, base_workflows: Mapping[str, str],
    candidate_workflows: Mapping[str, str],
) -> str | None:
    output = original
    for path in (
        ".github/workflows/profile-quality.yml",
        ".github/workflows/profile-stats.yml",
        ".github/workflows/spotlight-link-sync.yml",
    ):
        require(path in base_workflows and path in candidate_workflows,
                f"privileged workflow corpus incomplete: {path}")
        before, after = git_blob_sha(base_workflows[path]), git_blob_sha(candidate_workflows[path])
        require(original.count(f'"{path}": "{before}"') == 1,
                f"privileged workflow byte lock not based on exact accepted {path}")
        if before != after:
            output = output.replace(f'"{path}": "{before}"', f'"{path}": "{after}"', 1)
    return output if output != original else None


def update_profile_source_epoch(
    *, trusted_root: Path, base_workflows: Mapping[str, str],
    candidate_workflows: Mapping[str, str], derivatives: Mapping[str, str],
) -> str | None:
    """Derive the entire Profile Stats source-epoch closure from trusted source only.

    Import and execute only the accepted-main validator; never load code from a
    Dependabot branch. Preserve its reviewed source discovery and Git blob
    digest algorithm instead of independently reimplementing either contract.
    """
    require(PROFILE_STATS_WORKFLOW in base_workflows and
            PROFILE_STATS_WORKFLOW in candidate_workflows,
            "profile source epoch requires exact base/candidate Profile Stats workflows")
    compiler = trusted_root / SOURCE_EPOCH_COMPILER
    require(compiler.is_file() and compiler.absolute() == compiler.resolve(),
            "trusted Profile Stats source-epoch compiler is missing or aliased")
    scope = runpy.run_path(str(compiler))
    require(all(name in scope for name in
                ("strict_json", "derive_source_closure", "closure_digest", "validate_epoch")),
            "trusted Profile Stats epoch compiler API changed")
    epoch_path = trusted_root / SOURCE_EPOCH_PATH
    original = scope["strict_json"](epoch_path)
    base_files = scope["derive_source_closure"](base_workflows[PROFILE_STATS_WORKFLOW])
    baseline_digest = scope["closure_digest"](base_files)
    scope["validate_epoch"](original, base_files, baseline_digest)
    candidate_files = scope["derive_source_closure"](candidate_workflows[PROFILE_STATS_WORKFLOW])
    require(candidate_files == base_files,
            "artifact-only Action update changed the trusted Profile Stats script closure")

    digest = hashlib.sha256()
    for relative in candidate_files:
        require(type(relative) is str and not Path(relative).is_absolute() and
                ".." not in Path(relative).parts,
                "Profile Stats source-epoch path escaped the trusted checkout")
        if relative in derivatives:
            data = derivatives[relative].encode("utf-8")
        elif relative in candidate_workflows:
            data = candidate_workflows[relative].encode("utf-8")
        else:
            data = (trusted_root / relative).read_bytes()
        oid = hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(oid.encode("ascii"))
        digest.update(b"\n")
    updated = dict(original)
    updated["closure_sha256"] = digest.hexdigest()
    require(updated["file_count"] == len(candidate_files) and
            updated["version"] == scope["VERSION"] and
            updated["algorithm"] == scope["ALGORITHM"],
            "derived source epoch lost the canonical identity contract")
    value = json.dumps(updated, indent=2, ensure_ascii=True) + "\n"
    current = epoch_path.read_text(encoding="utf-8")
    require(json.loads(current) == original,
            "trusted source-epoch file has inconsistent canonical JSON")
    return value if value != current else None


def derive(
    *, trusted_root: Path, candidate_root: Path,
    proof: Mapping[str, Any],
) -> dict[str, str]:
    """Produce only exact, reproducible governance derivatives, with zero mutation."""
    repo, before, after, _ = exact_release(proof)
    require(trusted_root.is_dir() and candidate_root.is_dir(),
            "artifact derivation requires two distinct repository roots")
    require(trusted_root.resolve() != candidate_root.resolve(),
            "candidate cannot alias the trusted main checkout")

    base_workflows = {
        p.relative_to(trusted_root).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted((trusted_root / ".github/workflows").glob("*.yml"))
    }
    candidate_workflows = {
        p.relative_to(candidate_root).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted((candidate_root / ".github/workflows").glob("*.yml"))
    }
    require(base_workflows.keys() == candidate_workflows.keys() and base_workflows,
            "candidate changed the workflow inventory")
    changed = [path for path in base_workflows
               if base_workflows[path] != candidate_workflows[path]]
    require(changed and set(changed) == set(proof.get("files", [])),
            "candidate changed workflows outside exact admitted atomic pin diff")

    output = {LOCK_PATH: update_lock(
        (trusted_root / LOCK_PATH).read_text(encoding="utf-8"), proof)}
    # Compile the candidate from *trusted* compiler code. Candidate scripts
    # are never executed, imported, or used to derive the policy.
    compiled = trusted_workflow_capability.compile_repository(candidate_root)
    workflows = {item["id"]: item for item in compiled["workflows"]}
    shard_paths = sorted((trusted_root / ".github").glob("workflow-capability-bom-v1-*.json"))
    shard_ids = {path.name[len("workflow-capability-bom-v1-"):-len(".json")]: path
                 for path in shard_paths}
    require(set(shard_ids) < set(workflows) and len(shard_ids) >= 1,
            "repository capability BOM shards changed outside the trusted base")
    base = copy.deepcopy(compiled)
    base["workflows"] = [copy.deepcopy(value) for key, value in sorted(workflows.items())
                         if key not in shard_ids]
    require(len(base["workflows"]) >= 1, "base capability BOM has no workflows")
    output[BOM_PATH] = workflow_capability_bom.canonical_json(base)
    for workflow_id, path in sorted(shard_ids.items()):
        extension = copy.deepcopy(compiled)
        extension["workflows"] = [copy.deepcopy(workflows[workflow_id])]
        value = workflow_capability_bom.canonical_json(extension)
        if value != path.read_text(encoding="utf-8"):
            output[path.relative_to(trusted_root).as_posix()] = value

    for relative in REFERENCE_SOURCES:
        original = (trusted_root / relative).read_text(encoding="utf-8")
        if before["sha"] in original:
            output[relative] = update_literal_references(original, before, after, relative)
    old_sha = before["sha"]
    for path in (trusted_root / "scripts").glob("*.py"):
        relative = path.relative_to(trusted_root).as_posix()
        if relative == PRIVILEGED_IDENTITY or relative in REFERENCE_SOURCES:
            continue
        require(old_sha not in path.read_text(encoding="utf-8"),
                f"unreviewed Action release SHA literal remains in {relative}")

    original = (trusted_root / PRIVILEGED_IDENTITY).read_text(encoding="utf-8")
    updated = update_privileged_identity(original, base_workflows, candidate_workflows)
    if updated is not None:
        output[PRIVILEGED_IDENTITY] = updated

    epoch_update = update_profile_source_epoch(
        trusted_root=trusted_root,
        base_workflows=base_workflows,
        candidate_workflows=candidate_workflows,
        derivatives=output,
    )
    if epoch_update is not None:
        output[SOURCE_EPOCH_PATH] = epoch_update

    # The exact expected diff inventory is determined from trusted paths only.
    require(all(path == LOCK_PATH or path == BOM_PATH or
                path in (PRIVILEGED_IDENTITY, SOURCE_EPOCH_PATH) or path in REFERENCE_SOURCES or
                (path.startswith(SHARD_PREFIX) and path.endswith(".json"))
                for path in output), "unapproved artifact governance derivative")
    require(set(output).isdisjoint(changed),
            "derived trusted governance cannot overwrite native Dependabot workflow pins")
    require(repo in REPOSITORIES and all(isinstance(v, str) and v
            for v in output.values()), "artifact outputs are not canonical text")
    return {name: output[name] for name in sorted(output)}


def self_test() -> None:
    prior = {
        "repositoryId": 1, "releaseId": 2, "sha": "a" * 40,
        "tag": "v7.0.1", "tagRefSha": "a" * 40, "tagRefType": "commit",
    }
    next_release = {
        "repositoryId": 1, "releaseId": 3, "sha": "b" * 40,
        "tag": "v7.0.2", "tagRefSha": "b" * 40, "tagRefType": "commit",
    }
    proof = {
        "classification": "allowed",
        "dependencyRepository": "actions/upload-artifact",
        "before": prior, "after": next_release,
        "actions": ["actions/upload-artifact"],
    }
    payload = {"version": "github-actions-identity-lock-v2",
               "actions": {"actions/upload-artifact": prior}}
    changed = update_lock(json.dumps(payload) + "\n", proof)
    require(json.loads(changed)["actions"]["actions/upload-artifact"] == next_release,
            "artifact release lock is not atomically updated")
    sample = f'uses: actions/upload-artifact@{"a"*40} # v7.0.1\n'
    require(update_literal_references(sample, prior, next_release, "fixture") ==
            f'uses: actions/upload-artifact@{"b"*40} # v7.0.2\n',
            "release reference and tag did not advance together")
    try:
        update_lock(json.dumps(payload), {**proof, "actions": ["actions/checkout"]})
    except ValueError:
        pass
    else:
        raise ValueError("artifact reconciler allowed mismatched trusted lock coverage")
    try:
        exact_release({**proof, "dependencyRepository": "actions/checkout"})
    except ValueError:
        pass
    else:
        raise ValueError("artifact reconciler allowed unreviewed dependency expansion")


if __name__ == "__main__":
    self_test()
    print("Artifact-action derivative self-test passed: approved release-only, exact lock closure.")
