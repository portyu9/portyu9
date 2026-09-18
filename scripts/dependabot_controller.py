#!/usr/bin/env python3
"""Trusted, network-free planning for zero-touch Dependabot CodeQL Action updates.

The module never executes candidate-authored source. Callers provide trusted GitHub PR
metadata plus repository trees assembled as data. It proves the native Dependabot identity
and atomic immutable pin diff, binds public release provenance supplied by the caller, and
derives the exact repository-governance files that must accompany one CodeQL Action release.
Repository/API mutations remain visible in the trusted workflow rather than hidden here.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import re
import shutil
import tempfile
from typing import Any, Mapping

from action_identity_lock import (
    load_action_lock,
    parse_action_lock_json,
    repository_for_action,
    validate_payload as validate_action_lock_payload,
)
from dependabot_admission import evaluate_dependabot_admission
from dependabot_pin_diff import classify_pin_only_update
from dependabot_pr_identity import classify_pr_identity, fixture as pr_fixture
import trusted_workflow_capability
import workflow_capability_bom

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "portyu9/portyu9"
CODEQL_REPOSITORY = "github/codeql-action"
ACTION_LOCK = Path(".github/action-lock.json")
CODEQL_VALIDATOR = Path("scripts/validate-codeql-contract.py")
BASE_BOM = Path(".github/workflow-capability-bom-v1.json")
DERIVED_PATHS = (ACTION_LOCK.as_posix(), BASE_BOM.as_posix(), CODEQL_VALIDATOR.as_posix())
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def strict_json(path: Path, label: str) -> Any:
    require(path.is_file() and not path.is_symlink(), f"{label} is missing or aliased: {path}")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"JSON object contains duplicate key: {key}")
        result[key] = value
    return result


def workflow_corpus(root: Path) -> dict[str, str]:
    directory = root / ".github/workflows"
    require(directory.is_dir() and not directory.is_symlink(), "workflow corpus directory is missing or aliased")
    paths = sorted({*directory.glob("*.yml"), *directory.glob("*.yaml")})
    require(paths, "workflow corpus is empty")
    return {path.relative_to(root).as_posix(): path.read_text(encoding="utf-8") for path in paths}


def probe(
    *,
    pr: Mapping[str, Any],
    expected_head_sha: str,
    base_root: Path,
    candidate_root: Path,
) -> dict[str, object]:
    require(SHA40.fullmatch(expected_head_sha) is not None, "Dependabot controller expected head SHA is invalid")
    identity = classify_pr_identity(pr, repository=REPOSITORY, expected_head_sha=expected_head_sha)
    require(identity.get("classification") == "dependabot-github-actions",
            "Dependabot controller applies only to exact native GitHub-Actions Dependabot PRs")
    pin = classify_pin_only_update(
        workflow_corpus(base_root),
        workflow_corpus(candidate_root),
        load_action_lock(base_root / ACTION_LOCK),
    )
    require(pin.get("repository") == CODEQL_REPOSITORY,
            "zero-touch delegated admission is initially restricted to github/codeql-action")
    return {
        "classification": "dependabot-codeql-probe",
        "repository": REPOSITORY,
        "pullRequest": identity["pullRequest"],
        "headRef": identity["headRef"],
        "headSha": identity["headSha"],
        "dependencyRepository": pin["repository"],
        "before": copy.deepcopy(pin["before"]),
        "after": copy.deepcopy(pin["after"]),
        "actions": copy.deepcopy(pin["actions"]),
        "files": copy.deepcopy(pin["files"]),
        "occurrences": pin["occurrences"],
    }


def admit(
    *,
    pr: Mapping[str, Any],
    expected_head_sha: str,
    base_root: Path,
    candidate_root: Path,
    resolved_release_sha: str,
) -> dict[str, object]:
    require(SHA40.fullmatch(resolved_release_sha) is not None,
            "resolved Dependabot release SHA is invalid")
    result = evaluate_dependabot_admission(
        pr=pr,
        repository=REPOSITORY,
        expected_head_sha=expected_head_sha,
        base_files=workflow_corpus(base_root),
        candidate_files=workflow_corpus(candidate_root),
        trusted_lock=load_action_lock(base_root / ACTION_LOCK),
        resolve_tag=lambda repository, tag: resolved_release_sha,
    )
    require(result.get("classification") == "allowed", "Dependabot release was not admitted")
    require(result.get("dependencyRepository") == CODEQL_REPOSITORY,
            "zero-touch delegated admission is initially restricted to github/codeql-action")
    return result


def _replace_exact_assignment(text: str, name: str, old: str, new: str) -> str:
    before = f'{name} = "{old}"'
    after = f'{name} = "{new}"'
    require(text.count(before) == 1, f"trusted CodeQL validator lost exact {name} assignment")
    require(after not in text or old == new, f"trusted CodeQL validator already contains unexpected {name} target")
    return text.replace(before, after, 1)


def derive_codeql_files(
    *,
    base_root: Path,
    candidate_root: Path,
    proof: Mapping[str, Any],
) -> dict[str, str]:
    require(proof.get("classification") == "allowed", "Dependabot reconciliation requires an allowed provenance proof")
    require(proof.get("dependencyRepository") == CODEQL_REPOSITORY,
            "Dependabot reconciliation only derives CodeQL Action governance")
    after = proof.get("after")
    before = proof.get("before")
    require(isinstance(after, Mapping) and isinstance(before, Mapping), "Dependabot proof lost release identities")
    target_sha = after.get("sha")
    target_tag = after.get("tag")
    old_sha = before.get("sha")
    old_tag = before.get("tag")
    require(all(isinstance(value, str) for value in (target_sha, target_tag, old_sha, old_tag)),
            "Dependabot proof release identities are malformed")
    require(SHA40.fullmatch(str(target_sha)) is not None and SHA40.fullmatch(str(old_sha)) is not None,
            "Dependabot proof release SHA is malformed")

    lock_path = base_root / ACTION_LOCK
    payload = parse_action_lock_json(lock_path.read_text(encoding="utf-8"))
    lock = validate_action_lock_payload(payload)
    updated_actions = copy.deepcopy(payload["actions"])
    matched = []
    for action in sorted(updated_actions):
        if repository_for_action(action) != CODEQL_REPOSITORY:
            continue
        require(lock[action] == {"sha": old_sha, "tag": old_tag},
                f"trusted CodeQL Action lock base identity drifted for {action}")
        updated_actions[action] = {"sha": target_sha, "tag": target_tag}
        matched.append(action)
    require(matched and set(matched) == set(proof.get("actions", [])),
            "Dependabot proof does not cover every locked CodeQL sub-action")
    lock_output = canonical_json({"version": payload["version"], "actions": updated_actions})
    validate_action_lock_payload(parse_action_lock_json(lock_output))

    validator_text = (base_root / CODEQL_VALIDATOR).read_text(encoding="utf-8")
    validator_text = _replace_exact_assignment(validator_text, "CODEQL_SHA", str(old_sha), str(target_sha))
    validator_text = _replace_exact_assignment(validator_text, "CODEQL_RELEASE", str(old_tag), str(target_tag))

    compiled = trusted_workflow_capability.compile_repository(candidate_root)
    extension_ids = {"bot-pr-user-approval", "capability-admission", "codeql-autofix", "dependabot-controller"}
    base_workflows = [
        copy.deepcopy(workflow)
        for workflow in compiled["workflows"]
        if workflow.get("id") not in extension_ids
    ]
    require(len(base_workflows) == 5, "Dependabot reconciliation expected the historical five-workflow base snapshot")
    base_snapshot = {key: copy.deepcopy(compiled[key]) for key in compiled if key != "workflows"}
    base_snapshot["workflows"] = base_workflows
    bom_output = workflow_capability_bom.canonical_json(base_snapshot)

    return {
        ACTION_LOCK.as_posix(): lock_output,
        BASE_BOM.as_posix(): bom_output,
        CODEQL_VALIDATOR.as_posix(): validator_text,
    }


def validate_reconciled_candidate(
    *,
    base_root: Path,
    candidate_root: Path,
    proof: Mapping[str, Any],
    changed_paths: list[str],
) -> dict[str, object]:
    expected = derive_codeql_files(base_root=base_root, candidate_root=candidate_root, proof=proof)
    pin_files = proof.get("files")
    require(isinstance(pin_files, list) and all(isinstance(path, str) for path in pin_files),
            "Dependabot proof changed-file inventory is malformed")
    expected_paths = sorted(set(pin_files) | set(DERIVED_PATHS))
    require(sorted(set(changed_paths)) == expected_paths,
            f"reconciled Dependabot PR changed unexpected files: expected={expected_paths} observed={sorted(set(changed_paths))}")
    for relative, text in expected.items():
        path = candidate_root / relative
        require(path.is_file() and not path.is_symlink(), f"reconciled Dependabot derived file is missing: {relative}")
        require(path.read_text(encoding="utf-8") == text,
                f"reconciled Dependabot derived file differs from trusted derivation: {relative}")
    return {
        "classification": "dependabot-codeql-reconciled",
        "pullRequest": proof["pullRequest"],
        "headSha": proof["headSha"],
        "dependencyRepository": CODEQL_REPOSITORY,
        "changedPaths": expected_paths,
    }


def write_outputs(files: Mapping[str, str], output_root: Path) -> None:
    for relative, text in files.items():
        path = output_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def load_json(path: Path) -> Any:
    return strict_json(path, str(path))


def self_test() -> None:
    base = ROOT
    lock = load_action_lock(base / ACTION_LOCK)
    codeql_actions = sorted(action for action in lock if repository_for_action(action) == CODEQL_REPOSITORY)
    require(codeql_actions, "Dependabot controller self-test found no CodeQL actions")
    old_sha = lock[codeql_actions[0]]["sha"]
    old_tag = lock[codeql_actions[0]]["tag"]
    require(all(lock[action] == {"sha": old_sha, "tag": old_tag} for action in codeql_actions),
            "Dependabot controller self-test requires one CodeQL base release")
    new_sha = "b" * 40 if old_sha != "b" * 40 else "c" * 40
    new_tag = "v999.0.0"
    with tempfile.TemporaryDirectory(prefix="dependabot-controller-") as directory:
        candidate = Path(directory) / "candidate"
        shutil.copytree(base, candidate, symlinks=True)
        for path in (candidate / ".github/workflows").glob("*.yml"):
            text = path.read_text(encoding="utf-8")
            for action in codeql_actions:
                text = text.replace(f"{action}@{old_sha} # {old_tag}", f"{action}@{new_sha} # {new_tag}")
            path.write_text(text, encoding="utf-8")
        pr = pr_fixture()
        pr["head"]["sha"] = "d" * 40
        proof = admit(
            pr=pr,
            expected_head_sha="d" * 40,
            base_root=base,
            candidate_root=candidate,
            resolved_release_sha=new_sha,
        )
        derived = derive_codeql_files(base_root=base, candidate_root=candidate, proof=proof)
        write_outputs(derived, candidate)
        changed = sorted(set(proof["files"]) | set(DERIVED_PATHS))
        reconciled = validate_reconciled_candidate(
            base_root=base,
            candidate_root=candidate,
            proof=proof,
            changed_paths=changed,
        )
        require(reconciled["classification"] == "dependabot-codeql-reconciled",
                "Dependabot controller self-test failed reconciliation")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    sub = value.add_subparsers(dest="command", required=True)
    for name in ("probe", "admit"):
        command = sub.add_parser(name)
        command.add_argument("--pr", type=Path, required=True)
        command.add_argument("--expected-head", required=True)
        command.add_argument("--base-root", type=Path, required=True)
        command.add_argument("--candidate-root", type=Path, required=True)
        command.add_argument("--out", type=Path, required=True)
        if name == "admit":
            command.add_argument("--resolved-release-sha", required=True)
    derive = sub.add_parser("derive")
    derive.add_argument("--proof", type=Path, required=True)
    derive.add_argument("--base-root", type=Path, required=True)
    derive.add_argument("--candidate-root", type=Path, required=True)
    derive.add_argument("--output-root", type=Path, required=True)
    validate = sub.add_parser("validate")
    validate.add_argument("--proof", type=Path, required=True)
    validate.add_argument("--base-root", type=Path, required=True)
    validate.add_argument("--candidate-root", type=Path, required=True)
    validate.add_argument("--changed-paths", type=Path, required=True)
    validate.add_argument("--out", type=Path, required=True)
    sub.add_parser("self-test")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "self-test":
            self_test()
            print("Dependabot zero-touch controller self-test passed.")
            return 0
        if args.command in {"probe", "admit"}:
            pr = load_json(args.pr)
            if args.command == "probe":
                result = probe(
                    pr=pr,
                    expected_head_sha=args.expected_head,
                    base_root=args.base_root,
                    candidate_root=args.candidate_root,
                )
            else:
                result = admit(
                    pr=pr,
                    expected_head_sha=args.expected_head,
                    base_root=args.base_root,
                    candidate_root=args.candidate_root,
                    resolved_release_sha=args.resolved_release_sha,
                )
            args.out.write_text(canonical_json(result), encoding="utf-8")
            return 0
        proof = load_json(args.proof)
        if args.command == "derive":
            files = derive_codeql_files(base_root=args.base_root, candidate_root=args.candidate_root, proof=proof)
            write_outputs(files, args.output_root)
            return 0
        if args.command == "validate":
            changed = [line.strip() for line in args.changed_paths.read_text(encoding="utf-8").splitlines() if line.strip()]
            result = validate_reconciled_candidate(
                base_root=args.base_root,
                candidate_root=args.candidate_root,
                proof=proof,
                changed_paths=changed,
            )
            args.out.write_text(canonical_json(result), encoding="utf-8")
            return 0
        raise ValueError("unknown Dependabot controller command")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
