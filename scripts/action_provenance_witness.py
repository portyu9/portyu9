#!/usr/bin/env python3
"""Build and validate short-lived attested GitHub Action provenance witnesses.

The witness is intentionally authority-neutral. A trusted-main producer may call
`build` only after the existing live release-provenance proof succeeds; a consumer
may call `verify` only as the external-availability portion of provenance validation.
Local workflow/action-lock closure remains a separate mandatory gate.

This module performs no network access and no repository mutation.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping

from action_identity_lock import (
    VERSION as ACTION_LOCK_VERSION,
    parse_action_lock_json,
    repository_for_action,
    validate_payload as validate_action_lock_payload,
)

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "portyu9/portyu9"
REPOSITORY_ID = 1355082509
SCHEMA_VERSION = 1
KIND = "action-provenance-witness"
SUBJECT_KIND = "action-provenance-witness-subject"
SOURCE_REF = "refs/heads/main"
WORKFLOW_REF = (
    "portyu9/portyu9/.github/workflows/"
    "action-provenance-witness.yml@refs/heads/main"
)
TTL_SECONDS = 21600
PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "action-provenance-witness-v1.schema.json"
)
PREDICATE_SCHEMA = ROOT / ".github/attestation/action-provenance-witness-v1.schema.json"
AUTHORITY_SEPARATION = (
    "Live provenance preparation is read-only and separate from the OIDC attestation "
    "writer; neither grants repository mutation authority."
)
CLAIM = (
    "This witness proves that the exact action-lock v2 release set matched public "
    "upstream repository/release/tag-ref/commit identity during its bounded validity "
    "interval. It does not authorize a different lock or provenance-policy epoch and "
    "does not replace local workflow/lock closure, branch protection, or trusted "
    "capability admission."
)

# Closed-world provenance-policy epoch. These bytes jointly determine whether an old
# live proof may be reused. The future producer workflow is deliberately included so
# authority changes invalidate reuse as well as parser/policy changes.
POLICY_PATHS = (
    ".github/GOVERNANCE.md",
    ".github/action-lock.json",
    ".github/attestation/action-provenance-witness-v1.schema.json",
    ".github/workflows/action-provenance-witness.yml",
    ".github/workflows/profile-quality.yml",
    "scripts/action_identity_lock.py",
    "scripts/action_provenance_witness.py",
    "scripts/dependabot_release.py",
    "scripts/validate-action-release-provenance.py",
    "scripts/validate-codeql-contract.py",
    "scripts/validate-dependency-review-contract.py",
    "scripts/validate-governance-contract.py",
)

SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY_NAME = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
TOP_LEVEL_KEYS = (
    "schemaVersion",
    "kind",
    "repository",
    "repositoryId",
    "source",
    "validity",
    "predicateSchema",
    "actionLock",
    "policyEpoch",
    "releases",
    "authority",
    "claim",
)
SUBJECT_KEYS = (
    "schemaVersion",
    "kind",
    "repository",
    "actionLockDigest",
    "policyEpochDigest",
    "predicateDigest",
    "sourceSha",
    "runId",
    "runAttempt",
    "issuedAtEpoch",
    "expiresAtEpoch",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"witness JSON contains duplicate object key: {key}")
        result[key] = value
    return result


def strict_json(text: str) -> Any:
    return json.loads(text, object_pairs_hook=_unique_object)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n"


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _positive_int(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be a positive integer")
    return value


def _sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None,
            f"{label} must be 40 lowercase hexadecimal characters")
    return value


def _digest(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256.fullmatch(value) is not None,
            f"{label} must be one canonical sha256 digest")
    return value


def predicate_schema_identity() -> dict[str, str]:
    require(PREDICATE_SCHEMA.is_file() and not PREDICATE_SCHEMA.is_symlink(),
            "Action provenance witness predicate schema is missing or aliased")
    return {"id": PREDICATE_TYPE, "digest": digest_bytes(PREDICATE_SCHEMA.read_bytes())}


def _normalized_lock(lock_bytes: bytes) -> tuple[Any, dict[str, dict[str, Any]]]:
    try:
        text = lock_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"action-lock bytes are not UTF-8: {exc}") from exc
    payload = parse_action_lock_json(text)
    normalized = validate_action_lock_payload(payload)
    return payload, normalized


def release_inventory(actions: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_release: dict[tuple[str, str], dict[str, Any]] = {}
    for action in sorted(actions):
        identity = dict(actions[action])
        repository = repository_for_action(action)
        tag = identity.get("tag")
        require(isinstance(tag, str), f"{action}: release tag is malformed")
        key = (repository, tag)
        release = {"repository": repository, **identity}
        previous = by_release.get(key)
        require(previous is None or previous == release,
                f"{repository}@{tag}: action paths disagree on immutable release identity")
        by_release[key] = release
    return [by_release[key] for key in sorted(by_release)]


def _epoch_digest(entries: list[dict[str, str]]) -> str:
    return digest_bytes(canonical_json({"files": entries}).encode("utf-8"))


def policy_epoch(policy_files: Mapping[str, bytes]) -> dict[str, Any]:
    observed = set(policy_files)
    expected = set(POLICY_PATHS)
    require(observed == expected,
            "provenance policy epoch file inventory changed: "
            f"missing={sorted(expected - observed)} extra={sorted(observed - expected)}")
    entries = [
        {"path": path, "digest": digest_bytes(policy_files[path])}
        for path in POLICY_PATHS
    ]
    return {"digest": _epoch_digest(entries), "files": entries}


def policy_files_from_root(root: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for relative in POLICY_PATHS:
        path = root / relative
        require(path.is_file() and not path.is_symlink(),
                f"provenance policy epoch input is missing or aliased: {relative}")
        result[relative] = path.read_bytes()
    return result


def build_predicate(
    *,
    source_sha: str,
    run_id: int,
    run_attempt: int,
    issued_at_epoch: int,
    lock_bytes: bytes,
    policy_files: Mapping[str, bytes],
) -> dict[str, Any]:
    _sha(source_sha, "source SHA")
    run_id = _positive_int(run_id, "run ID")
    run_attempt = _positive_int(run_attempt, "run attempt")
    issued_at_epoch = _positive_int(issued_at_epoch, "issuedAtEpoch")
    expires_at_epoch = issued_at_epoch + TTL_SECONDS
    payload, actions = _normalized_lock(lock_bytes)
    require(payload.get("version") == ACTION_LOCK_VERSION,
            "Action provenance witness requires canonical action-lock v2")

    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": KIND,
        "repository": REPOSITORY,
        "repositoryId": REPOSITORY_ID,
        "source": {
            "sha": source_sha,
            "ref": SOURCE_REF,
            "workflowRef": WORKFLOW_REF,
            "runId": run_id,
            "runAttempt": run_attempt,
            "runUrl": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
        },
        "validity": {
            "issuedAtEpoch": issued_at_epoch,
            "expiresAtEpoch": expires_at_epoch,
            "ttlSeconds": TTL_SECONDS,
        },
        "predicateSchema": predicate_schema_identity(),
        "actionLock": {
            "version": ACTION_LOCK_VERSION,
            "digest": digest_bytes(lock_bytes),
            "actions": {action: dict(actions[action]) for action in sorted(actions)},
        },
        "policyEpoch": policy_epoch(policy_files),
        "releases": release_inventory(actions),
        "authority": {
            "preparation": "contents:read",
            "attestation": "contents:read,id-token:write,attestations:write",
            "separation": AUTHORITY_SEPARATION,
        },
        "claim": CLAIM,
    }


def _validate_policy_epoch(value: Any) -> None:
    require(isinstance(value, dict) and list(value) == ["digest", "files"],
            "policyEpoch object shape/order changed")
    _digest(value.get("digest"), "policyEpoch.digest")
    files = value.get("files")
    require(isinstance(files, list) and len(files) == len(POLICY_PATHS),
            "policyEpoch file inventory length changed")
    expected_entries: list[dict[str, str]] = []
    for index, path in enumerate(POLICY_PATHS):
        item = files[index]
        require(isinstance(item, dict) and list(item) == ["path", "digest"],
                f"policyEpoch.files[{index}] shape/order changed")
        require(item.get("path") == path,
                f"policyEpoch.files[{index}] path changed from {path}")
        digest = _digest(item.get("digest"), f"policyEpoch.files[{index}].digest")
        expected_entries.append({"path": path, "digest": digest})
    require(value["digest"] == _epoch_digest(expected_entries),
            "policyEpoch aggregate digest does not match exact file digest inventory")


def validate_predicate(predicate: Any) -> dict[str, Any]:
    require(isinstance(predicate, dict) and list(predicate) == list(TOP_LEVEL_KEYS),
            "Action provenance witness top-level shape/order changed")
    require(type(predicate.get("schemaVersion")) is int
            and predicate["schemaVersion"] == SCHEMA_VERSION,
            "Action provenance witness schemaVersion changed")
    require(predicate.get("kind") == KIND
            and predicate.get("repository") == REPOSITORY
            and type(predicate.get("repositoryId")) is int
            and predicate["repositoryId"] == REPOSITORY_ID,
            "Action provenance witness repository identity changed")

    source = predicate.get("source")
    require(isinstance(source, dict)
            and list(source) == ["sha", "ref", "workflowRef", "runId", "runAttempt", "runUrl"],
            "Action provenance witness source block shape/order changed")
    source_sha = _sha(source.get("sha"), "source.sha")
    require(source.get("ref") == SOURCE_REF and source.get("workflowRef") == WORKFLOW_REF,
            "Action provenance witness source ref/workflow identity changed")
    run_id = _positive_int(source.get("runId"), "source.runId")
    _positive_int(source.get("runAttempt"), "source.runAttempt")
    require(source.get("runUrl") == f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
            "Action provenance witness run URL changed")

    validity = predicate.get("validity")
    require(isinstance(validity, dict)
            and list(validity) == ["issuedAtEpoch", "expiresAtEpoch", "ttlSeconds"],
            "Action provenance witness validity block shape/order changed")
    issued = _positive_int(validity.get("issuedAtEpoch"), "validity.issuedAtEpoch")
    expires = _positive_int(validity.get("expiresAtEpoch"), "validity.expiresAtEpoch")
    require(type(validity.get("ttlSeconds")) is int
            and validity["ttlSeconds"] == TTL_SECONDS,
            "Action provenance witness TTL changed")
    require(expires == issued + TTL_SECONDS,
            "Action provenance witness expiry is not exactly issuance plus fixed TTL")

    require(predicate.get("predicateSchema") == predicate_schema_identity(),
            "Action provenance witness predicate schema identity changed")

    action_lock = predicate.get("actionLock")
    require(isinstance(action_lock, dict)
            and list(action_lock) == ["version", "digest", "actions"],
            "Action provenance witness actionLock block shape/order changed")
    require(action_lock.get("version") == ACTION_LOCK_VERSION,
            "Action provenance witness action-lock version changed")
    _digest(action_lock.get("digest"), "actionLock.digest")
    actions = action_lock.get("actions")
    require(isinstance(actions, dict) and actions,
            "Action provenance witness action inventory is missing")
    require(list(actions) == sorted(actions),
            "Action provenance witness action inventory is not deterministically sorted")
    normalized = validate_action_lock_payload({
        "version": ACTION_LOCK_VERSION,
        "actions": copy.deepcopy(actions),
    })
    require(actions == normalized,
            "Action provenance witness action inventory is not canonical")

    _validate_policy_epoch(predicate.get("policyEpoch"))
    expected_releases = release_inventory(normalized)
    require(predicate.get("releases") == expected_releases,
            "Action provenance witness release inventory differs from exact locked identities")

    expected_authority = {
        "preparation": "contents:read",
        "attestation": "contents:read,id-token:write,attestations:write",
        "separation": AUTHORITY_SEPARATION,
    }
    require(predicate.get("authority") == expected_authority,
            "Action provenance witness authority-separation contract changed")
    require(predicate.get("claim") == CLAIM,
            "Action provenance witness bounded claim changed")
    require(source_sha == predicate["source"]["sha"],
            "Action provenance witness source identity normalization failed")
    return predicate


def predicate_digest(predicate: Any) -> str:
    validate_predicate(predicate)
    return digest_bytes(canonical_json(predicate).encode("utf-8"))


def build_subject(predicate: Any) -> dict[str, Any]:
    predicate = validate_predicate(predicate)
    source = predicate["source"]
    validity = predicate["validity"]
    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": SUBJECT_KIND,
        "repository": REPOSITORY,
        "actionLockDigest": predicate["actionLock"]["digest"],
        "policyEpochDigest": predicate["policyEpoch"]["digest"],
        "predicateDigest": predicate_digest(predicate),
        "sourceSha": source["sha"],
        "runId": source["runId"],
        "runAttempt": source["runAttempt"],
        "issuedAtEpoch": validity["issuedAtEpoch"],
        "expiresAtEpoch": validity["expiresAtEpoch"],
    }


def validate_subject(subject: Any, predicate: Any) -> dict[str, Any]:
    require(isinstance(subject, dict) and list(subject) == list(SUBJECT_KEYS),
            "Action provenance witness subject shape/order changed")
    expected = build_subject(predicate)
    require(subject == expected,
            "Action provenance witness subject does not bind exact predicate/transaction")
    return subject


def is_fresh(predicate: Any, now_epoch: int) -> bool:
    predicate = validate_predicate(predicate)
    now_epoch = _positive_int(now_epoch, "current epoch")
    validity = predicate["validity"]
    return validity["issuedAtEpoch"] <= now_epoch < validity["expiresAtEpoch"]


def validate_for_consumption(
    *,
    predicate: Any,
    subject: Any,
    current_lock_bytes: bytes,
    current_policy_files: Mapping[str, bytes],
    now_epoch: int,
) -> None:
    predicate = validate_predicate(predicate)
    validate_subject(subject, predicate)
    require(is_fresh(predicate, now_epoch),
            "Action provenance witness is not currently fresh")

    _, current_actions = _normalized_lock(current_lock_bytes)
    require(predicate["actionLock"]["digest"] == digest_bytes(current_lock_bytes),
            "Action provenance witness was minted for different action-lock bytes")
    require(predicate["actionLock"]["actions"]
            == {action: dict(current_actions[action]) for action in sorted(current_actions)},
            "Action provenance witness was minted for different normalized action identities")
    require(predicate["policyEpoch"] == policy_epoch(current_policy_files),
            "Action provenance witness was minted for a different provenance-policy epoch")


def _fixture_lock_bytes() -> bytes:
    lightweight = {
        "repositoryId": 1,
        "releaseId": 2,
        "sha": "a" * 40,
        "tag": "v1.2.3",
        "tagRefSha": "a" * 40,
        "tagRefType": "commit",
    }
    annotated = {
        "repositoryId": 3,
        "releaseId": 4,
        "sha": "b" * 40,
        "tag": "v4.5.6",
        "tagRefSha": "c" * 40,
        "tagRefType": "tag",
    }
    payload = {
        "version": ACTION_LOCK_VERSION,
        "actions": {
            "actions/checkout": lightweight,
            "github/codeql-action/analyze": annotated,
            "github/codeql-action/init": annotated,
        },
    }
    return (json.dumps(payload, indent=2, ensure_ascii=True) + "\n").encode("utf-8")


def _fixture_policy_files() -> dict[str, bytes]:
    return {path: f"fixture:{path}\n".encode("utf-8") for path in POLICY_PATHS}


def _expect_failure(function: Any, expected: str) -> None:
    try:
        function()
    except ValueError as exc:
        require(expected in str(exc),
                f"Action provenance witness self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(
            "Action provenance witness self-test accepted unsafe mutation: " + expected
        )


def self_test() -> None:
    lock_bytes = _fixture_lock_bytes()
    policy_files = _fixture_policy_files()
    predicate = build_predicate(
        source_sha="d" * 40,
        run_id=123456,
        run_attempt=2,
        issued_at_epoch=1700000000,
        lock_bytes=lock_bytes,
        policy_files=policy_files,
    )
    validate_predicate(predicate)
    subject = build_subject(predicate)
    validate_subject(subject, predicate)
    validate_for_consumption(
        predicate=predicate,
        subject=subject,
        current_lock_bytes=lock_bytes,
        current_policy_files=policy_files,
        now_epoch=1700000000 + TTL_SECONDS - 1,
    )
    require(not is_fresh(predicate, 1700000000 + TTL_SECONDS),
            "Action provenance witness self-test accepted exact-expiry replay")

    wrong_expiry = copy.deepcopy(predicate)
    wrong_expiry["validity"]["expiresAtEpoch"] += 1
    _expect_failure(lambda: validate_predicate(wrong_expiry), "expiry")

    wrong_release = copy.deepcopy(predicate)
    wrong_release["actionLock"]["actions"]["actions/checkout"]["releaseId"] += 1
    _expect_failure(lambda: validate_predicate(wrong_release), "release inventory")

    wrong_epoch = copy.deepcopy(predicate)
    wrong_epoch["policyEpoch"]["files"][0]["digest"] = "sha256:" + "f" * 64
    _expect_failure(lambda: validate_predicate(wrong_epoch), "aggregate digest")

    wrong_subject = copy.deepcopy(subject)
    wrong_subject["predicateDigest"] = "sha256:" + "e" * 64
    _expect_failure(
        lambda: validate_subject(wrong_subject, predicate),
        "does not bind exact predicate",
    )

    changed_policy = dict(policy_files)
    changed_policy[POLICY_PATHS[-1]] = b"changed\n"
    _expect_failure(
        lambda: validate_for_consumption(
            predicate=predicate,
            subject=subject,
            current_lock_bytes=lock_bytes,
            current_policy_files=changed_policy,
            now_epoch=1700000001,
        ),
        "different provenance-policy epoch",
    )

    changed_lock_payload = strict_json(lock_bytes.decode("utf-8"))
    changed_lock_payload["actions"]["actions/checkout"]["releaseId"] = 99
    changed_lock = (json.dumps(changed_lock_payload, indent=2) + "\n").encode("utf-8")
    _expect_failure(
        lambda: validate_for_consumption(
            predicate=predicate,
            subject=subject,
            current_lock_bytes=changed_lock,
            current_policy_files=policy_files,
            now_epoch=1700000001,
        ),
        "different action-lock bytes",
    )

    _expect_failure(
        lambda: strict_json('{"schemaVersion":1,"schemaVersion":1}'),
        "duplicate object key",
    )


def _write(path: Path, value: Any) -> None:
    path.write_text(canonical_json(value), encoding="utf-8")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    sub = value.add_subparsers(dest="command", required=True)
    sub.add_parser("self-test")

    build = sub.add_parser("build")
    build.add_argument("--source-sha", required=True)
    build.add_argument("--run-id", type=int, required=True)
    build.add_argument("--run-attempt", type=int, required=True)
    build.add_argument("--issued-at", type=int, required=True)
    build.add_argument("--lock", type=Path, required=True)
    build.add_argument("--policy-root", type=Path, required=True)
    build.add_argument("--predicate-out", type=Path, required=True)
    build.add_argument("--subject-out", type=Path, required=True)

    verify = sub.add_parser("verify")
    verify.add_argument("--predicate", type=Path, required=True)
    verify.add_argument("--subject", type=Path, required=True)
    verify.add_argument("--lock", type=Path, required=True)
    verify.add_argument("--policy-root", type=Path, required=True)
    verify.add_argument("--now", type=int, required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        self_test()
        if args.command == "self-test":
            print(
                "Action provenance witness v1 self-test passed: exact lock/policy epoch, "
                "fixed TTL, run-attempt identity, deterministic release inventory, "
                "subject binding, freshness, and mismatch rejection are fail-closed."
            )
            return 0

        if args.command == "build":
            lock_bytes = args.lock.read_bytes()
            predicate = build_predicate(
                source_sha=args.source_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                issued_at_epoch=args.issued_at,
                lock_bytes=lock_bytes,
                policy_files=policy_files_from_root(args.policy_root),
            )
            _write(args.predicate_out, predicate)
            _write(args.subject_out, build_subject(predicate))
            return 0

        predicate = strict_json(args.predicate.read_text(encoding="utf-8"))
        subject = strict_json(args.subject.read_text(encoding="utf-8"))
        validate_for_consumption(
            predicate=predicate,
            subject=subject,
            current_lock_bytes=args.lock.read_bytes(),
            current_policy_files=policy_files_from_root(args.policy_root),
            now_epoch=args.now,
        )
        print("Action provenance witness is valid and fresh for the exact current provenance epoch.")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
