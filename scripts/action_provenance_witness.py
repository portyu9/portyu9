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
from datetime import datetime, timezone
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
WITNESS_WORKFLOW = ROOT / ".github/workflows/action-provenance-witness.yml"
WORKFLOW_NAME = "Action provenance witness"
WORKFLOW_PATH = ".github/workflows/action-provenance-witness.yml"
ARTIFACT_NAME = "action-provenance-witness-v1"
ALLOWED_PRODUCER_EVENTS = {"push", "schedule", "workflow_dispatch"}
MAX_DISCOVERY_RESULTS = 100
MAX_RECORDED_ATTEMPTS = 20
PRIOR_ATTEMPT_CONCLUSIONS = {
    "action_required", "cancelled", "failure", "neutral", "skipped",
    "stale", "startup_failure", "success", "timed_out",
}
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
    "retryHistory",
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
    # Builders below already define a closed-world deterministic key order that validators
    # intentionally re-prove after parsing. Sorting object keys here would destroy that
    # contract (including release-identity member order) and make emitted witness bytes
    # fail their own verifier after a disk/artifact round trip.
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n"


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


def _schema_const(schema: Mapping[str, Any], *path: str) -> Any:
    current: Any = schema
    for key in path:
        require(isinstance(current, dict) and key in current,
                "Action provenance witness schema binding path is missing: " + ".".join(path))
        current = current[key]
    return current


def validate_schema_contract() -> None:
    require(PREDICATE_SCHEMA.is_file() and not PREDICATE_SCHEMA.is_symlink(),
            "Action provenance witness predicate schema is missing or aliased")
    schema = strict_json(PREDICATE_SCHEMA.read_text(encoding="utf-8"))
    require(isinstance(schema, dict), "Action provenance witness schema root must be an object")
    require(schema.get("$id") == PREDICATE_TYPE,
            "Action provenance witness schema $id differs from predicate type")
    bindings = {
        ("properties", "schemaVersion", "const"): SCHEMA_VERSION,
        ("properties", "kind", "const"): KIND,
        ("properties", "repository", "const"): REPOSITORY,
        ("properties", "repositoryId", "const"): REPOSITORY_ID,
        ("properties", "source", "properties", "ref", "const"): SOURCE_REF,
        ("properties", "source", "properties", "workflowRef", "const"): WORKFLOW_REF,
        ("properties", "validity", "properties", "ttlSeconds", "const"): TTL_SECONDS,
        ("properties", "predicateSchema", "properties", "id", "const"): PREDICATE_TYPE,
        ("properties", "actionLock", "properties", "version", "const"): ACTION_LOCK_VERSION,
        ("properties", "authority", "properties", "preparation", "const"): "contents:read",
        ("properties", "authority", "properties", "attestation", "const"):
            "contents:read,id-token:write,attestations:write",
        ("properties", "authority", "properties", "separation", "const"): AUTHORITY_SEPARATION,
        ("properties", "claim", "const"): CLAIM,
    }
    for path, expected in bindings.items():
        require(_schema_const(schema, *path) == expected,
                "Action provenance witness executable constant differs from schema: "
                + ".".join(path))


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


def normalize_retry_history(
    value: Any, *, run_id: int, run_attempt: int, source_sha: str,
) -> list[dict[str, Any]]:
    run_id = _positive_int(run_id, "run ID")
    run_attempt = _positive_int(run_attempt, "run attempt")
    source_sha = _sha(source_sha, "source SHA")
    require(run_attempt <= MAX_RECORDED_ATTEMPTS,
            "Action provenance witness run attempt exceeds reviewed retry-history bound")
    require(isinstance(value, list), "Action provenance retry history input must be an array")
    require(len(value) == run_attempt - 1,
            "Action provenance retry history must contain every prior attempt exactly once")
    history: list[dict[str, Any]] = []
    for expected_attempt, raw in enumerate(value, start=1):
        require(isinstance(raw, Mapping), "Action provenance retry history contains a non-object")
        require(_positive_int(raw.get("id"), "prior attempt run ID") == run_id,
                "Action provenance prior attempt run ID changed")
        require(_positive_int(raw.get("run_attempt"), "prior attempt number") == expected_attempt,
                "Action provenance retry-history attempts are not contiguous")
        require(raw.get("name") == WORKFLOW_NAME and raw.get("path") == WORKFLOW_PATH,
                "Action provenance prior attempt workflow identity changed")
        require(raw.get("event") in ALLOWED_PRODUCER_EVENTS,
                "Action provenance prior attempt event changed")
        require(raw.get("head_branch") == "main"
                and _sha(raw.get("head_sha"), "prior attempt head SHA") == source_sha,
                "Action provenance prior attempt source identity changed")
        repository = raw.get("repository")
        head_repository = raw.get("head_repository")
        require(isinstance(repository, Mapping)
                and repository.get("id") == REPOSITORY_ID
                and repository.get("full_name") == REPOSITORY,
                "Action provenance prior attempt repository identity changed")
        require(isinstance(head_repository, Mapping)
                and head_repository.get("id") == REPOSITORY_ID
                and head_repository.get("full_name") == REPOSITORY,
                "Action provenance prior attempt head-repository identity changed")
        require(raw.get("status") == "completed",
                "Action provenance prior attempt is not terminal")
        conclusion = raw.get("conclusion")
        require(conclusion in PRIOR_ATTEMPT_CONCLUSIONS,
                "Action provenance prior attempt conclusion is invalid")
        actor = raw.get("actor")
        triggering_actor = raw.get("triggering_actor")
        actor_login = actor.get("login") if isinstance(actor, Mapping) else None
        triggering_login = triggering_actor.get("login") if isinstance(triggering_actor, Mapping) else None
        require(isinstance(actor_login, str) and actor_login
                and isinstance(triggering_login, str) and triggering_login,
                "Action provenance prior attempt actor identity is missing")
        history.append({
            "attempt": expected_attempt,
            "checkSuiteId": _positive_int(raw.get("check_suite_id"), "prior attempt check-suite ID"),
            "status": "completed",
            "conclusion": conclusion,
            "actor": actor_login,
            "triggeringActor": triggering_login,
        })
    return history


def build_predicate(
    *,
    source_sha: str,
    run_id: int,
    run_attempt: int,
    prior_attempts: Any,
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
        "retryHistory": normalize_retry_history(
            prior_attempts, run_id=run_id, run_attempt=run_attempt, source_sha=source_sha,
        ),
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
    run_attempt = _positive_int(source.get("runAttempt"), "source.runAttempt")
    require(run_attempt <= MAX_RECORDED_ATTEMPTS,
            "Action provenance witness run attempt exceeds reviewed retry-history bound")
    require(source.get("runUrl") == f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
            "Action provenance witness run URL changed")

    history = predicate.get("retryHistory")
    require(isinstance(history, list) and len(history) == run_attempt - 1,
            "Action provenance witness retryHistory must contain every prior attempt exactly once")
    for expected_attempt, item in enumerate(history, start=1):
        require(isinstance(item, dict)
                and list(item) == ["attempt", "checkSuiteId", "status", "conclusion", "actor", "triggeringActor"],
                "Action provenance witness retryHistory attempt shape/order changed")
        require(item.get("attempt") == expected_attempt,
                "Action provenance witness retryHistory attempts are not contiguous")
        _positive_int(item.get("checkSuiteId"), "retryHistory.checkSuiteId")
        require(item.get("status") == "completed",
                "Action provenance witness retryHistory contains a nonterminal attempt")
        require(item.get("conclusion") in PRIOR_ATTEMPT_CONCLUSIONS,
                "Action provenance witness retryHistory conclusion is invalid")
        require(isinstance(item.get("actor"), str) and item["actor"]
                and isinstance(item.get("triggeringActor"), str) and item["triggeringActor"],
                "Action provenance witness retryHistory actor identity is missing")

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



def _timestamp_epoch(value: Any, label: str) -> int:
    require(isinstance(value, str) and value.endswith("Z"),
            f"{label} must be one UTC GitHub timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} must be one UTC GitHub timestamp") from exc
    require(parsed.tzinfo is not None and parsed.utcoffset() is not None
            and parsed.utcoffset().total_seconds() == 0,
            f"{label} must be UTC")
    epoch = int(parsed.astimezone(timezone.utc).timestamp())
    return _positive_int(epoch, label)


def _repository_identity(value: Any, label: str) -> None:
    require(isinstance(value, Mapping), f"{label} must be an object")
    require(type(value.get("id")) is int and value["id"] == REPOSITORY_ID,
            f"{label} repository ID changed")
    require(value.get("full_name") == REPOSITORY,
            f"{label} repository name changed")


def normalize_producer_run(value: Any, *, label: str = "witness producer run") -> dict[str, Any]:
    require(isinstance(value, Mapping), f"{label} must be an object")
    run_id = _positive_int(value.get("id"), f"{label} id")
    run_attempt = _positive_int(value.get("run_attempt"), f"{label} run_attempt")
    require(value.get("name") == WORKFLOW_NAME, f"{label} workflow name changed")
    require(value.get("path") == WORKFLOW_PATH, f"{label} workflow path changed")
    require(value.get("event") in ALLOWED_PRODUCER_EVENTS, f"{label} event is not allowed")
    require(value.get("status") == "completed" and value.get("conclusion") == "success",
            f"{label} is not one completed successful run")
    require(value.get("head_branch") == "main", f"{label} head branch changed")
    head_sha = _sha(value.get("head_sha"), f"{label} head SHA")
    _repository_identity(value.get("repository"), f"{label} repository")
    _repository_identity(value.get("head_repository"), f"{label} head_repository")
    started_at = value.get("run_started_at")
    started_epoch = _timestamp_epoch(started_at, f"{label} run_started_at")
    return {
        "id": run_id,
        "runAttempt": run_attempt,
        "headSha": head_sha,
        "runStartedAt": started_at,
        "runStartedEpoch": started_epoch,
    }


def select_fresh_witness_run(value: Any, *, now_epoch: int) -> dict[str, Any]:
    now_epoch = _positive_int(now_epoch, "witness discovery current epoch")
    require(isinstance(value, Mapping), "witness run-list response must be an object")
    total_count = value.get("total_count")
    require(type(total_count) is int and total_count >= 0,
            "witness run-list total_count must be a nonnegative integer")
    runs = value.get("workflow_runs")
    require(isinstance(runs, list), "witness run-list response is missing workflow_runs")
    require(total_count == len(runs), "witness run-list response is incomplete")
    require(total_count <= MAX_DISCOVERY_RESULTS,
            "witness run-list exceeds one complete reviewed page")

    normalized = [
        normalize_producer_run(run, label=f"witness producer run[{index}]")
        for index, run in enumerate(runs)
    ]
    ids = [run["id"] for run in normalized]
    require(len(ids) == len(set(ids)), "witness run-list contains duplicate run IDs")

    fresh = [
        run for run in normalized
        if run["runStartedEpoch"] <= now_epoch < run["runStartedEpoch"] + TTL_SECONDS
    ]
    require(fresh, "witness run-list contains no fresh successful producer run")
    latest_epoch = max(run["runStartedEpoch"] for run in fresh)
    latest = [run for run in fresh if run["runStartedEpoch"] == latest_epoch]
    require(len(latest) == 1, "latest fresh witness producer run is ambiguous")
    return latest[0]


def validate_attempt_run(value: Any, selected: Mapping[str, Any]) -> dict[str, Any]:
    observed = normalize_producer_run(value, label="attempt-specific witness producer run")
    for key in ("id", "runAttempt", "headSha", "runStartedAt", "runStartedEpoch"):
        require(observed[key] == selected.get(key),
                f"attempt-specific witness producer run differs from selected run: {key}")
    return observed


def select_witness_artifact(value: Any, selected_run: Mapping[str, Any]) -> dict[str, Any]:
    require(isinstance(value, Mapping), "witness artifact-list response must be an object")
    total_count = value.get("total_count")
    require(type(total_count) is int and total_count >= 0,
            "witness artifact-list total_count must be a nonnegative integer")
    artifacts = value.get("artifacts")
    require(isinstance(artifacts, list), "witness artifact-list response is missing artifacts")
    require(total_count == len(artifacts), "witness artifact-list response is incomplete")
    require(total_count <= MAX_DISCOVERY_RESULTS,
            "witness artifact-list exceeds one complete reviewed page")
    require(total_count == 1, "expected exactly one witness artifact for selected run")

    artifact = artifacts[0]
    require(isinstance(artifact, Mapping), "witness artifact must be an object")
    artifact_id = _positive_int(artifact.get("id"), "witness artifact id")
    require(artifact.get("name") == ARTIFACT_NAME, "witness artifact name changed")
    require(type(artifact.get("expired")) is bool, "witness artifact expired must be a boolean")
    require(artifact["expired"] is False, "witness artifact is expired")
    digest = _digest(artifact.get("digest"), "witness artifact digest")
    created_epoch = _timestamp_epoch(artifact.get("created_at"), "witness artifact created_at")

    run_started = _positive_int(selected_run.get("runStartedEpoch"), "selected run start epoch")
    require(run_started <= created_epoch < run_started + 1800,
            "witness artifact creation is outside the selected producer attempt window")

    workflow_run = artifact.get("workflow_run")
    require(isinstance(workflow_run, Mapping), "witness artifact workflow_run must be an object")
    require(_positive_int(workflow_run.get("id"), "witness artifact workflow_run id")
            == selected_run.get("id"),
            "witness artifact belongs to another workflow run")
    require(type(workflow_run.get("repository_id")) is int
            and workflow_run["repository_id"] == REPOSITORY_ID,
            "witness artifact workflow_run repository ID changed")
    require(type(workflow_run.get("head_repository_id")) is int
            and workflow_run["head_repository_id"] == REPOSITORY_ID,
            "witness artifact workflow_run head repository ID changed")
    require(workflow_run.get("head_branch") == "main",
            "witness artifact workflow_run head branch changed")
    require(_sha(workflow_run.get("head_sha"), "witness artifact workflow_run head SHA")
            == selected_run.get("headSha"),
            "witness artifact workflow_run head SHA differs from selected run")
    return {
        "id": artifact_id,
        "name": ARTIFACT_NAME,
        "digest": digest,
        "createdEpoch": created_epoch,
    }


def attestation_verify_args(subject_path: str, source_sha: str) -> list[str]:
    require(isinstance(subject_path, str) and bool(subject_path)
            and "\x00" not in subject_path and "\n" not in subject_path,
            "attestation subject path is invalid")
    source_sha = _sha(source_sha, "attestation source SHA")
    return [
        "gh",
        "attestation",
        "verify",
        subject_path,
        "--repo",
        REPOSITORY,
        "--predicate-type",
        PREDICATE_TYPE,
        "--signer-workflow",
        f"{REPOSITORY}/{WORKFLOW_PATH}",
        "--signer-digest",
        source_sha,
        "--source-digest",
        source_sha,
        "--source-ref",
        SOURCE_REF,
        "--deny-self-hosted-runners",
        "--format",
        "json",
    ]


def validate_verified_attestation(value: Any, predicate: Any, subject: Any) -> None:
    predicate = validate_predicate(predicate)
    subject = validate_subject(subject, predicate)
    require(isinstance(value, list) and len(value) == 1,
            "witness attestation verification must return exactly one statement")
    entry = value[0]
    require(isinstance(entry, Mapping), "witness attestation verification entry must be an object")
    verification = entry.get("verificationResult")
    require(isinstance(verification, Mapping),
            "witness attestation verification result is missing")
    statement = verification.get("statement")
    require(isinstance(statement, Mapping), "witness attestation statement is missing")
    require(statement.get("predicateType") == PREDICATE_TYPE,
            "witness attestation predicate type changed")
    require(statement.get("predicate") == predicate,
            "witness attestation predicate differs from downloaded witness")

    subjects = statement.get("subject")
    require(isinstance(subjects, list) and len(subjects) == 1,
            "witness attestation statement must bind exactly one subject")
    attested_subject = subjects[0]
    require(isinstance(attested_subject, Mapping),
            "witness attestation subject entry must be an object")
    require(attested_subject.get("name") == "action-provenance-witness-subject.json",
            "witness attestation subject name changed")
    digests = attested_subject.get("digest")
    require(isinstance(digests, Mapping) and set(digests) == {"sha256"},
            "witness attestation subject digest shape changed")
    expected = hashlib.sha256(canonical_json(subject).encode("utf-8")).hexdigest()
    require(digests.get("sha256") == expected,
            "witness attestation subject digest differs from downloaded subject")


def validate_consumer_evidence(
    *,
    run_list: Any,
    attempt_run: Any,
    artifact_list: Any,
    predicate: Any,
    subject: Any,
    verified_attestation: Any,
    current_lock_bytes: bytes,
    current_policy_files: Mapping[str, bytes],
    now_epoch: int,
) -> dict[str, Any]:
    selected = select_fresh_witness_run(run_list, now_epoch=now_epoch)
    validate_attempt_run(attempt_run, selected)
    artifact = select_witness_artifact(artifact_list, selected)
    predicate = validate_predicate(predicate)
    subject = validate_subject(subject, predicate)

    source = predicate["source"]
    validity = predicate["validity"]
    require(source["runId"] == selected["id"], "witness predicate is bound to another run")
    require(source["runAttempt"] == selected["runAttempt"],
            "witness predicate is bound to another run attempt")
    require(source["sha"] == selected["headSha"], "witness predicate is bound to another source SHA")
    require(validity["issuedAtEpoch"] == selected["runStartedEpoch"],
            "witness issuance does not equal selected run start")

    validate_for_consumption(
        predicate=predicate,
        subject=subject,
        current_lock_bytes=current_lock_bytes,
        current_policy_files=current_policy_files,
        now_epoch=now_epoch,
    )
    validate_verified_attestation(verified_attestation, predicate, subject)
    return {
        "runId": selected["id"],
        "runAttempt": selected["runAttempt"],
        "sourceSha": selected["headSha"],
        "artifactId": artifact["id"],
        "artifactDigest": artifact["digest"],
        "expiresAtEpoch": validity["expiresAtEpoch"],
    }

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


def validate_signer_workflow_contract(text: str | None = None) -> None:
    if text is None:
        require(WITNESS_WORKFLOW.is_file() and not WITNESS_WORKFLOW.is_symlink(),
                "Action provenance witness workflow is missing or aliased")
        text = WITNESS_WORKFLOW.read_text(encoding="utf-8")

    marker = "  attest:\n"
    require(text.count(marker) == 1,
            "Action provenance witness signer job identity changed")
    signer = text[text.index(marker):]
    require(signer.startswith(
        "  attest:\n"
        "    name: attest-action-provenance-witness-write-only\n"
        "    needs: prepare\n"
        "    runs-on: ubuntu-24.04\n"
        "    timeout-minutes: 4\n"
        "    permissions:\n"
        "      contents: read\n"
        "      id-token: write\n"
        "      attestations: write\n"
    ), "Action provenance witness signer identity/authority changed")

    require(signer.count(
        "uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1"
    ) == 1, "Action provenance witness signer must download exactly one prepared artifact")
    require(signer.count(
        "uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2"
    ) == 1, "Action provenance witness signer must execute exactly one reviewed attestation action")
    require(
        "subject-path: witness-attestation-input/action-provenance-witness-subject.json" in signer
        and "predicate-path: witness-attestation-input/action-provenance-witness.json" in signer
        and (
            "predicate-type: https://raw.githubusercontent.com/portyu9/portyu9/main/"
            ".github/attestation/action-provenance-witness-v1.schema.json"
        ) in signer,
        "Action provenance witness signer subject/predicate identity changed",
    )
    require(signer.count("        run: |\n") == 1,
            "Action provenance witness signer authored shell surface changed")
    require(
        'test "$(sha256sum witness-attestation-input/action-provenance-witness.json | cut -d\' \' -f1)" = "$EXPECTED_PREDICATE_SHA256"' in signer
        and 'test "$(sha256sum witness-attestation-input/action-provenance-witness-subject.json | cut -d\' \' -f1)" = "$EXPECTED_SUBJECT_SHA256"' in signer,
        "Action provenance witness signer lost exact prepared-byte digest checks",
    )
    for forbidden in (
        "actions/checkout@",
        "actions/setup-python@",
        "python3 ",
        "git ",
        "gh ",
        "GITHUB_TOKEN:",
        "GH_TOKEN:",
        "contents: write",
        "actions: write",
        "pull-requests: write",
        "checks: write",
        "security-events: write",
        "packages: write",
        "repository_dispatch",
        "workflow_dispatch",
    ):
        require(forbidden not in signer,
                f"Action provenance witness signer acquired forbidden surface: {forbidden}")


def self_test() -> None:
    validate_schema_contract()
    validate_signer_workflow_contract()
    lock_bytes = _fixture_lock_bytes()
    policy_files = _fixture_policy_files()
    predicate = build_predicate(
        source_sha="d" * 40,
        run_id=123456,
        run_attempt=2,
        prior_attempts=[{
            "id": 123456,
            "run_attempt": 1,
            "name": WORKFLOW_NAME,
            "path": WORKFLOW_PATH,
            "event": "push",
            "status": "completed",
            "conclusion": "cancelled",
            "head_branch": "main",
            "head_sha": "d" * 40,
            "check_suite_id": 3001,
            "actor": {"login": "github-actions[bot]"},
            "triggering_actor": {"login": "github-actions[bot]"},
            "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
            "head_repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
        }],
        issued_at_epoch=1700000000,
        lock_bytes=lock_bytes,
        policy_files=policy_files,
    )
    validate_predicate(predicate)
    subject = build_subject(predicate)
    validate_subject(subject, predicate)

    # Exercise the actual artifact boundary: build writes canonical JSON bytes, and consumers
    # parse those bytes before validation. This must preserve every closed-world member order.
    serialized_predicate = strict_json(canonical_json(predicate))
    serialized_subject = strict_json(canonical_json(subject))
    validate_predicate(serialized_predicate)
    validate_subject(serialized_subject, serialized_predicate)
    validate_for_consumption(
        predicate=serialized_predicate,
        subject=serialized_subject,
        current_lock_bytes=lock_bytes,
        current_policy_files=policy_files,
        now_epoch=1700000000 + TTL_SECONDS - 1,
    )

    validate_for_consumption(
        predicate=predicate,
        subject=subject,
        current_lock_bytes=lock_bytes,
        current_policy_files=policy_files,
        now_epoch=1700000000 + TTL_SECONDS - 1,
    )
    require(not is_fresh(predicate, 1700000000 + TTL_SECONDS),
            "Action provenance witness self-test accepted exact-expiry replay")


    run = {
        "id": 123456,
        "run_attempt": 2,
        "name": WORKFLOW_NAME,
        "path": WORKFLOW_PATH,
        "event": "push",
        "status": "completed",
        "conclusion": "success",
        "head_branch": "main",
        "head_sha": "d" * 40,
        "run_started_at": "2023-11-14T22:13:20Z",
        "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
        "head_repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
    }
    older = copy.deepcopy(run)
    older["id"] = 123455
    older["run_attempt"] = 1
    older["run_started_at"] = "2023-11-14T21:56:40Z"
    run_list = {"total_count": 2, "workflow_runs": [older, run]}
    selected = select_fresh_witness_run(run_list, now_epoch=1700000001)
    require(selected["id"] == 123456 and selected["runAttempt"] == 2,
            "canonical consumer evidence self-test lost selected run")

    artifact = {
        "id": 91,
        "name": ARTIFACT_NAME,
        "expired": False,
        "digest": "sha256:" + "f" * 64,
        "created_at": "2023-11-14T22:14:00Z",
        "workflow_run": {
            "id": 123456,
            "repository_id": REPOSITORY_ID,
            "head_repository_id": REPOSITORY_ID,
            "head_branch": "main",
            "head_sha": "d" * 40,
        },
    }
    artifact_list = {"total_count": 1, "artifacts": [artifact]}
    selected_artifact = select_witness_artifact(artifact_list, selected)
    require(selected_artifact["id"] == 91,
            "canonical consumer evidence self-test lost selected artifact")

    subject_sha256 = hashlib.sha256(canonical_json(subject).encode("utf-8")).hexdigest()
    verified = [{
        "verificationResult": {
            "statement": {
                "predicateType": PREDICATE_TYPE,
                "predicate": copy.deepcopy(predicate),
                "subject": [{
                    "name": "action-provenance-witness-subject.json",
                    "digest": {"sha256": subject_sha256},
                }],
            }
        }
    }]
    evidence = validate_consumer_evidence(
        run_list=run_list,
        attempt_run=run,
        artifact_list=artifact_list,
        predicate=predicate,
        subject=subject,
        verified_attestation=verified,
        current_lock_bytes=lock_bytes,
        current_policy_files=policy_files,
        now_epoch=1700000001,
    )
    require(
        evidence == {
            "runId": 123456,
            "runAttempt": 2,
            "sourceSha": "d" * 40,
            "artifactId": 91,
            "artifactDigest": "sha256:" + "f" * 64,
            "expiresAtEpoch": 1700000000 + TTL_SECONDS,
        },
        "canonical consumer evidence result changed",
    )
    args = attestation_verify_args("witness/action-provenance-witness-subject.json", "d" * 40)
    require(args == [
        "gh", "attestation", "verify", "witness/action-provenance-witness-subject.json",
        "--repo", REPOSITORY,
        "--predicate-type", PREDICATE_TYPE,
        "--signer-workflow", f"{REPOSITORY}/{WORKFLOW_PATH}",
        "--signer-digest", "d" * 40,
        "--source-digest", "d" * 40,
        "--source-ref", SOURCE_REF,
        "--deny-self-hosted-runners",
        "--format", "json",
    ], "witness attestation verification command contract changed")

    _expect_failure(
        lambda: select_fresh_witness_run(
            {"total_count": 3, "workflow_runs": [older, run]},
            now_epoch=1700000001,
        ),
        "run-list response is incomplete",
    )
    _expect_failure(
        lambda: select_fresh_witness_run(
            {"total_count": 101, "workflow_runs": [copy.deepcopy(run) for _ in range(101)]},
            now_epoch=1700000001,
        ),
        "exceeds one complete reviewed page",
    )
    duplicate_run = copy.deepcopy(run)
    duplicate_run["run_started_at"] = "2023-11-14T22:13:19Z"
    _expect_failure(
        lambda: select_fresh_witness_run(
            {"total_count": 2, "workflow_runs": [run, duplicate_run]},
            now_epoch=1700000001,
        ),
        "duplicate run IDs",
    )
    ambiguous = copy.deepcopy(run)
    ambiguous["id"] = 123457
    _expect_failure(
        lambda: select_fresh_witness_run(
            {"total_count": 2, "workflow_runs": [run, ambiguous]},
            now_epoch=1700000001,
        ),
        "latest fresh witness producer run is ambiguous",
    )
    _expect_failure(
        lambda: select_fresh_witness_run(
            {"total_count": 1, "workflow_runs": [older]},
            now_epoch=1700000000 + TTL_SECONDS + 1,
        ),
        "no fresh successful producer run",
    )
    wrong_path_run = copy.deepcopy(run)
    wrong_path_run["path"] = ".github/workflows/other.yml"
    _expect_failure(
        lambda: select_fresh_witness_run(
            {"total_count": 1, "workflow_runs": [wrong_path_run]},
            now_epoch=1700000001,
        ),
        "workflow path changed",
    )
    wrong_attempt = copy.deepcopy(run)
    wrong_attempt["run_attempt"] = 3
    _expect_failure(
        lambda: validate_attempt_run(wrong_attempt, selected),
        "differs from selected run: runAttempt",
    )

    _expect_failure(
        lambda: select_witness_artifact({"total_count": 2, "artifacts": [artifact]}, selected),
        "artifact-list response is incomplete",
    )
    duplicate_artifact = copy.deepcopy(artifact)
    duplicate_artifact["id"] = 92
    _expect_failure(
        lambda: select_witness_artifact(
            {"total_count": 2, "artifacts": [artifact, duplicate_artifact]},
            selected,
        ),
        "exactly one witness artifact",
    )
    expired_artifact = copy.deepcopy(artifact)
    expired_artifact["expired"] = True
    _expect_failure(
        lambda: select_witness_artifact(
            {"total_count": 1, "artifacts": [expired_artifact]},
            selected,
        ),
        "artifact is expired",
    )
    wrong_artifact_run = copy.deepcopy(artifact)
    wrong_artifact_run["workflow_run"] = dict(artifact["workflow_run"])
    wrong_artifact_run["workflow_run"]["id"] = 999
    _expect_failure(
        lambda: select_witness_artifact(
            {"total_count": 1, "artifacts": [wrong_artifact_run]},
            selected,
        ),
        "belongs to another workflow run",
    )
    old_artifact = copy.deepcopy(artifact)
    old_artifact["created_at"] = "2023-11-14T20:00:00Z"
    _expect_failure(
        lambda: select_witness_artifact(
            {"total_count": 1, "artifacts": [old_artifact]},
            selected,
        ),
        "outside the selected producer attempt window",
    )

    wrong_type = copy.deepcopy(verified)
    wrong_type[0]["verificationResult"]["statement"]["predicateType"] = "https://example.invalid/predicate"
    _expect_failure(
        lambda: validate_verified_attestation(wrong_type, predicate, subject),
        "predicate type changed",
    )
    wrong_attested_predicate = copy.deepcopy(verified)
    wrong_attested_predicate[0]["verificationResult"]["statement"]["predicate"]["source"]["runId"] = 999
    _expect_failure(
        lambda: validate_verified_attestation(wrong_attested_predicate, predicate, subject),
        "predicate differs from downloaded witness",
    )
    wrong_attested_subject = copy.deepcopy(verified)
    wrong_attested_subject[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "e" * 64
    _expect_failure(
        lambda: validate_verified_attestation(wrong_attested_subject, predicate, subject),
        "subject digest differs from downloaded subject",
    )
    _expect_failure(
        lambda: validate_verified_attestation(verified + copy.deepcopy(verified), predicate, subject),
        "exactly one statement",
    )

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

    workflow_text = WITNESS_WORKFLOW.read_text(encoding="utf-8")
    _expect_failure(
        lambda: validate_signer_workflow_contract(
            workflow_text.replace("      contents: read\n      id-token: write", "      contents: write\n      id-token: write", 1)
        ),
        "signer identity/authority changed",
    )
    _expect_failure(
        lambda: validate_signer_workflow_contract(
            workflow_text.replace(
                "      - name: Download exact prepared witness bundle\n",
                "      - name: Forbidden checkout\n"
                "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n\n"
                "      - name: Download exact prepared witness bundle\n",
                1,
            )
        ),
        "forbidden surface: actions/checkout@",
    )
    _expect_failure(
        lambda: validate_signer_workflow_contract(
            workflow_text.replace(
                '          [[ "$EXPECTED_PREDICATE_SHA256" =~ ^[0-9a-f]{64}$ ]]\n',
                '          python3 scripts/action_provenance_witness.py self-test\n'
                '          [[ "$EXPECTED_PREDICATE_SHA256" =~ ^[0-9a-f]{64}$ ]]\n',
                1,
            )
        ),
        "forbidden surface: python3 ",
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
    build.add_argument("--attempt-history-file", type=Path, required=True)
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

    select_run = sub.add_parser("select-run")
    select_run.add_argument("--runs", type=Path, required=True)
    select_run.add_argument("--now", type=int, required=True)
    select_run.add_argument("--out", type=Path, required=True)

    select_artifact = sub.add_parser("select-artifact")
    select_artifact.add_argument("--artifacts", type=Path, required=True)
    select_artifact.add_argument("--selected-run", type=Path, required=True)
    select_artifact.add_argument("--out", type=Path, required=True)

    consume = sub.add_parser("consume-evidence")
    consume.add_argument("--run-list", type=Path, required=True)
    consume.add_argument("--attempt-run", type=Path, required=True)
    consume.add_argument("--artifact-list", type=Path, required=True)
    consume.add_argument("--predicate", type=Path, required=True)
    consume.add_argument("--subject", type=Path, required=True)
    consume.add_argument("--verified-attestation", type=Path, required=True)
    consume.add_argument("--lock", type=Path, required=True)
    consume.add_argument("--policy-root", type=Path, required=True)
    consume.add_argument("--now", type=int, required=True)
    consume.add_argument("--out", type=Path, required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        self_test()
        if args.command == "self-test":
            print(
                "Action provenance witness v1 self-test passed: exact lock/policy epoch, "
                "fixed TTL, run-attempt identity, deterministic release inventory, "
                "subject binding, freshness, bounded consumer selection, exact attestation matching, and mismatch rejection are fail-closed."
            )
            return 0

        if args.command == "build":
            lock_bytes = args.lock.read_bytes()
            predicate = build_predicate(
                source_sha=args.source_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                prior_attempts=strict_json(args.attempt_history_file.read_text(encoding="utf-8")),
                issued_at_epoch=args.issued_at,
                lock_bytes=lock_bytes,
                policy_files=policy_files_from_root(args.policy_root),
            )
            _write(args.predicate_out, predicate)
            _write(args.subject_out, build_subject(predicate))
            return 0

        if args.command == "select-run":
            selected = select_fresh_witness_run(
                strict_json(args.runs.read_text(encoding="utf-8")),
                now_epoch=args.now,
            )
            _write(args.out, selected)
            print(
                f"Selected fresh Action provenance witness run {selected['id']} "
                f"attempt {selected['runAttempt']} at {selected['headSha']}."
            )
            return 0

        if args.command == "select-artifact":
            selected_run = strict_json(args.selected_run.read_text(encoding="utf-8"))
            artifact = select_witness_artifact(
                strict_json(args.artifacts.read_text(encoding="utf-8")),
                selected_run,
            )
            _write(args.out, artifact)
            print(
                f"Selected exact Action provenance witness artifact {artifact['id']} "
                f"with digest {artifact['digest']}."
            )
            return 0

        if args.command == "consume-evidence":
            evidence = validate_consumer_evidence(
                run_list=strict_json(args.run_list.read_text(encoding="utf-8")),
                attempt_run=strict_json(args.attempt_run.read_text(encoding="utf-8")),
                artifact_list=strict_json(args.artifact_list.read_text(encoding="utf-8")),
                predicate=strict_json(args.predicate.read_text(encoding="utf-8")),
                subject=strict_json(args.subject.read_text(encoding="utf-8")),
                verified_attestation=strict_json(args.verified_attestation.read_text(encoding="utf-8")),
                current_lock_bytes=args.lock.read_bytes(),
                current_policy_files=policy_files_from_root(args.policy_root),
                now_epoch=args.now,
            )
            _write(args.out, evidence)
            print(
                f"Accepted cryptographically verified Action provenance witness "
                f"run {evidence['runId']} attempt {evidence['runAttempt']} "
                f"through epoch {evidence['expiresAtEpoch']}."
            )
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
