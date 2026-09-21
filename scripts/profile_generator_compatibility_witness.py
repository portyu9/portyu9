#!/usr/bin/env python3
"""Build and validate short-lived profile-generator compatibility witnesses.

This module is deliberately network-free and mutation-free. A future trusted-main
producer may build a witness only after the immutable pinned generator output has
passed the reviewed Signal Field compatibility pipeline. A consumer must revalidate
the exact captured raw bytes locally before treating them as a replacement for a
live generator invocation.
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
import tempfile
from typing import Any, Mapping

from action_identity_lock import parse_action_lock_json, validate_payload as validate_action_lock_payload

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "portyu9/portyu9"
REPOSITORY_ID = 1355082509
SCHEMA_VERSION = 1
KIND = "profile-generator-compatibility-witness"
SUBJECT_KIND = "profile-generator-compatibility-witness-subject"
SOURCE_REF = "refs/heads/main"
WORKFLOW_PATH = ".github/workflows/profile-generator-compatibility-witness.yml"
WORKFLOW_REF = f"{REPOSITORY}/{WORKFLOW_PATH}@{SOURCE_REF}"
WORKFLOW_NAME = "Profile generator compatibility witness"
TTL_SECONDS = 21600
GENERATOR = "shinpr/github-profile-stats"
GENERATOR_REPOSITORY_ID = 1306572938
GENERATOR_RELEASE_ID = 357958496
GENERATOR_SHA = "49b5f7091182a45f3ef93923505b660c6da5f835"
GENERATOR_TAG = "v0.2.0"
GENERATOR_TAG_REF_TYPE = "commit"
USERNAME = "portyu9"
PROFILE = "signal-field"
CREDENTIAL = "github.token"
PREDICATE_TYPE = "https://github.com/portyu9/portyu9/attestations/profile-generator-compatibility/v1"
PREDICATE_SCHEMA = ROOT / ".github/attestation/profile-generator-compatibility-witness-v1.schema.json"
WITNESS_WORKFLOW = ROOT / ".github/workflows/profile-generator-compatibility-witness.yml"
ARTIFACT_NAME = "profile-generator-compatibility-witness-v1"
ALLOWED_PRODUCER_EVENTS = frozenset({"push", "schedule", "workflow_dispatch"})
MAX_DISCOVERY_RESULTS = 100
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)
AUTHORITY_SEPARATION = (
    "Compatibility preparation executes the exact pinned generator and validates a copy "
    "under read-only authority; the isolated signer only attests the reviewed bundle and "
    "neither job grants repository mutation authority."
)
CLAIM = (
    "This witness proves only that the exact captured raw output of the immutable pinned "
    "profile generator was accepted by the exact compatibility-policy epoch during its "
    "bounded validity interval. Consumers must revalidate the captured bytes locally and "
    "may not use the witness for a different generator, invocation, compatibility epoch, "
    "or output bundle."
)

# Closed-world inputs that determine whether raw generator output is reusable. The future
# producer workflow will be added to this set in the authority-bearing producer unit before
# any production witness exists; this first unit intentionally changes no workflow bytes.
POLICY_PATHS = (
    ".github/action-lock.json",
    ".github/attestation/profile-generator-compatibility-witness-v1.schema.json",
    ".github/workflows/profile-generator-compatibility-witness.yml",
    ".github/workflows/profile-quality.yml",
    "scripts/action_identity_lock.py",
    "scripts/generate-profile-evidence.py",
    "scripts/profile-evidence-generation-v1.json",
    "scripts/profile_generator_compatibility_witness.py",
    "scripts/signal-field-pipeline-v2.json",
    "scripts/signal_field_pipeline.py",
    "scripts/validate-generated-signal-field.py",
    "scripts/validate-profile-upstream-retry.py",
    "scripts/validate-signal-field-v214.py",
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
TOP_LEVEL_KEYS = (
    "schemaVersion", "kind", "repository", "repositoryId", "source", "validity",
    "predicateSchema", "generator", "invocation", "compatibilityEpoch", "signalField",
    "authority", "claim",
)
SUBJECT_KEYS = (
    "schemaVersion", "kind", "repository", "generatorSha", "compatibilityEpochDigest",
    "signalFieldDigest", "predicateDigest", "sourceSha", "runId", "runAttempt",
    "issuedAtEpoch", "expiresAtEpoch",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"compatibility witness JSON contains duplicate object key: {key}")
        result[key] = value
    return result


def strict_json(text: str) -> Any:
    return json.loads(text, object_pairs_hook=unique_object)


def canonical_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True) + "\n"


def digest_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def positive_int(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be a positive integer")
    return value


def sha40(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None,
            f"{label} must be 40 lowercase hexadecimal characters")
    return value


def digest(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256.fullmatch(value) is not None,
            f"{label} must be one canonical sha256 digest")
    return value


def schema_identity() -> dict[str, str]:
    require(PREDICATE_SCHEMA.is_file() and not PREDICATE_SCHEMA.is_symlink(),
            "profile generator compatibility witness schema is missing or aliased")
    return {"id": PREDICATE_TYPE, "digest": digest_bytes(PREDICATE_SCHEMA.read_bytes())}


def schema_const(schema: Mapping[str, Any], *path: str) -> Any:
    current: Any = schema
    for key in path:
        require(isinstance(current, dict) and key in current,
                "compatibility witness schema binding path is missing: " + ".".join(path))
        current = current[key]
    return current


def validate_schema_contract() -> None:
    schema = strict_json(PREDICATE_SCHEMA.read_text(encoding="utf-8"))
    require(isinstance(schema, dict) and schema.get("$id") == PREDICATE_TYPE,
            "compatibility witness schema identity changed")
    bindings = {
        ("properties", "schemaVersion", "const"): SCHEMA_VERSION,
        ("properties", "kind", "const"): KIND,
        ("properties", "repository", "const"): REPOSITORY,
        ("properties", "repositoryId", "const"): REPOSITORY_ID,
        ("properties", "source", "properties", "ref", "const"): SOURCE_REF,
        ("properties", "source", "properties", "workflowRef", "const"): WORKFLOW_REF,
        ("properties", "validity", "properties", "ttlSeconds", "const"): TTL_SECONDS,
        ("properties", "predicateSchema", "properties", "id", "const"): PREDICATE_TYPE,
        ("properties", "generator", "properties", "repository", "const"): GENERATOR,
        ("properties", "generator", "properties", "repositoryId", "const"): GENERATOR_REPOSITORY_ID,
        ("properties", "generator", "properties", "releaseId", "const"): GENERATOR_RELEASE_ID,
        ("properties", "generator", "properties", "sha", "const"): GENERATOR_SHA,
        ("properties", "generator", "properties", "tag", "const"): GENERATOR_TAG,
        ("properties", "generator", "properties", "tagRefSha", "const"): GENERATOR_SHA,
        ("properties", "generator", "properties", "tagRefType", "const"): GENERATOR_TAG_REF_TYPE,
        ("properties", "invocation", "properties", "username", "const"): USERNAME,
        ("properties", "invocation", "properties", "profile", "const"): PROFILE,
        ("properties", "invocation", "properties", "credential", "const"): CREDENTIAL,
        ("properties", "authority", "properties", "preparation", "const"): "contents:read",
        ("properties", "authority", "properties", "attestation", "const"):
            "contents:read,id-token:write,attestations:write",
        ("properties", "authority", "properties", "separation", "const"): AUTHORITY_SEPARATION,
        ("properties", "claim", "const"): CLAIM,
    }
    for path, expected in bindings.items():
        require(schema_const(schema, *path) == expected,
                "compatibility witness executable constant differs from schema: " + ".".join(path))


def generator_identity(lock_bytes: bytes) -> dict[str, Any]:
    try:
        payload = parse_action_lock_json(lock_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ValueError(f"action-lock bytes are not UTF-8: {exc}") from exc
    actions = validate_action_lock_payload(payload)
    require(GENERATOR in actions, f"action-lock lost pinned generator identity: {GENERATOR}")
    identity = actions[GENERATOR]
    expected = {
        "repository": GENERATOR,
        "repositoryId": GENERATOR_REPOSITORY_ID,
        "releaseId": GENERATOR_RELEASE_ID,
        "sha": GENERATOR_SHA,
        "tag": GENERATOR_TAG,
        "tagRefSha": GENERATOR_SHA,
        "tagRefType": GENERATOR_TAG_REF_TYPE,
    }
    observed = {"repository": GENERATOR, **dict(identity)}
    require(observed == expected, f"pinned profile generator immutable identity changed: {observed!r}")
    return expected


def epoch_digest(entries: list[dict[str, str]]) -> str:
    return digest_bytes(canonical_json({"files": entries}).encode("utf-8"))


def compatibility_epoch(policy_files: Mapping[str, bytes]) -> dict[str, Any]:
    observed = set(policy_files)
    expected = set(POLICY_PATHS)
    require(observed == expected,
            "compatibility policy file inventory changed: "
            f"missing={sorted(expected-observed)} extra={sorted(observed-expected)}")
    files = [{"path": path, "digest": digest_bytes(policy_files[path])} for path in POLICY_PATHS]
    return {"digest": epoch_digest(files), "files": files}


def policy_files_from_root(root: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for relative in POLICY_PATHS:
        path = root / relative
        require(path.is_file() and not path.is_symlink(),
                f"compatibility policy input is missing or aliased: {relative}")
        result[relative] = path.read_bytes()
    return result


def signal_field_inventory(directory: Path) -> dict[str, Any]:
    require(directory.is_dir() and not directory.is_symlink(),
            f"raw Signal Field bundle must be a real directory: {directory}")
    observed = sorted(path.name for path in directory.iterdir())
    require(observed == sorted(EXPECTED_FILES),
            f"raw Signal Field file inventory changed: expected={sorted(EXPECTED_FILES)} observed={observed}")
    files: list[dict[str, Any]] = []
    for name in EXPECTED_FILES:
        path = directory / name
        require(path.is_file() and not path.is_symlink(),
                f"raw Signal Field entry must be a real file: {name}")
        data = path.read_bytes()
        require(data, f"raw Signal Field entry is empty: {name}")
        files.append({"name": name, "size": len(data), "digest": digest_bytes(data)})
    aggregate = digest_bytes(canonical_json({"files": files}).encode("utf-8"))
    return {"kind": "raw-pinned-generator-output", "aggregateDigest": aggregate, "files": files}


def build_predicate(
    *, source_sha: str, run_id: int, run_attempt: int, issued_at_epoch: int,
    lock_bytes: bytes, policy_files: Mapping[str, bytes], signal_field_dir: Path,
) -> dict[str, Any]:
    sha40(source_sha, "source SHA")
    run_id = positive_int(run_id, "run ID")
    run_attempt = positive_int(run_attempt, "run attempt")
    issued_at_epoch = positive_int(issued_at_epoch, "issuedAtEpoch")
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
            "expiresAtEpoch": issued_at_epoch + TTL_SECONDS,
            "ttlSeconds": TTL_SECONDS,
        },
        "predicateSchema": schema_identity(),
        "generator": generator_identity(lock_bytes),
        "invocation": {"username": USERNAME, "profile": PROFILE, "credential": CREDENTIAL},
        "compatibilityEpoch": compatibility_epoch(policy_files),
        "signalField": signal_field_inventory(signal_field_dir),
        "authority": {
            "preparation": "contents:read",
            "attestation": "contents:read,id-token:write,attestations:write",
            "separation": AUTHORITY_SEPARATION,
        },
        "claim": CLAIM,
    }


def validate_epoch(value: Any) -> None:
    require(isinstance(value, dict) and list(value) == ["digest", "files"],
            "compatibilityEpoch object shape/order changed")
    digest(value.get("digest"), "compatibilityEpoch.digest")
    files = value.get("files")
    require(isinstance(files, list) and len(files) == len(POLICY_PATHS),
            "compatibilityEpoch file count changed")
    rebuilt: list[dict[str, str]] = []
    for index, relative in enumerate(POLICY_PATHS):
        item = files[index]
        require(isinstance(item, dict) and list(item) == ["path", "digest"],
                f"compatibilityEpoch.files[{index}] shape/order changed")
        require(item.get("path") == relative,
                f"compatibilityEpoch.files[{index}] path changed from {relative}")
        rebuilt.append({"path": relative, "digest": digest(item.get("digest"), f"compatibilityEpoch.files[{index}].digest")})
    require(value["digest"] == epoch_digest(rebuilt),
            "compatibilityEpoch aggregate digest does not match exact file inventory")


def validate_signal_field(value: Any) -> None:
    require(isinstance(value, dict) and list(value) == ["kind", "aggregateDigest", "files"],
            "signalField object shape/order changed")
    require(value.get("kind") == "raw-pinned-generator-output", "signalField kind changed")
    digest(value.get("aggregateDigest"), "signalField.aggregateDigest")
    files = value.get("files")
    require(isinstance(files, list) and len(files) == len(EXPECTED_FILES),
            "signalField file count changed")
    rebuilt: list[dict[str, Any]] = []
    for index, name in enumerate(EXPECTED_FILES):
        item = files[index]
        require(isinstance(item, dict) and list(item) == ["name", "size", "digest"],
                f"signalField.files[{index}] shape/order changed")
        require(item.get("name") == name, f"signalField.files[{index}] filename changed")
        size = positive_int(item.get("size"), f"signalField.files[{index}].size")
        value_digest = digest(item.get("digest"), f"signalField.files[{index}].digest")
        rebuilt.append({"name": name, "size": size, "digest": value_digest})
    require(value["aggregateDigest"] == digest_bytes(canonical_json({"files": rebuilt}).encode("utf-8")),
            "signalField aggregate digest does not match exact file inventory")


def validate_predicate(predicate: Any) -> dict[str, Any]:
    require(isinstance(predicate, dict) and list(predicate) == list(TOP_LEVEL_KEYS),
            "compatibility witness root shape/order changed")
    require(predicate["schemaVersion"] == SCHEMA_VERSION and predicate["kind"] == KIND,
            "compatibility witness schema/kind changed")
    require(predicate["repository"] == REPOSITORY and predicate["repositoryId"] == REPOSITORY_ID,
            "compatibility witness repository identity changed")
    source = predicate["source"]
    require(isinstance(source, dict) and list(source) == ["sha", "ref", "workflowRef", "runId", "runAttempt", "runUrl"],
            "compatibility witness source shape/order changed")
    source_sha = sha40(source["sha"], "source.sha")
    run_id = positive_int(source["runId"], "source.runId")
    positive_int(source["runAttempt"], "source.runAttempt")
    require(source["ref"] == SOURCE_REF and source["workflowRef"] == WORKFLOW_REF,
            "compatibility witness trusted source identity changed")
    require(source["runUrl"] == f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
            "compatibility witness run URL is not canonical")
    validity = predicate["validity"]
    require(isinstance(validity, dict) and list(validity) == ["issuedAtEpoch", "expiresAtEpoch", "ttlSeconds"],
            "compatibility witness validity shape/order changed")
    issued = positive_int(validity["issuedAtEpoch"], "validity.issuedAtEpoch")
    expires = positive_int(validity["expiresAtEpoch"], "validity.expiresAtEpoch")
    require(validity["ttlSeconds"] == TTL_SECONDS and expires == issued + TTL_SECONDS,
            "compatibility witness validity interval changed")
    require(predicate["predicateSchema"] == schema_identity(), "compatibility witness predicate schema identity changed")
    require(predicate["generator"] == {
        "repository": GENERATOR, "repositoryId": GENERATOR_REPOSITORY_ID,
        "releaseId": GENERATOR_RELEASE_ID, "sha": GENERATOR_SHA, "tag": GENERATOR_TAG,
        "tagRefSha": GENERATOR_SHA, "tagRefType": GENERATOR_TAG_REF_TYPE,
    }, "compatibility witness generator identity changed")
    require(predicate["invocation"] == {"username": USERNAME, "profile": PROFILE, "credential": CREDENTIAL},
            "compatibility witness invocation changed")
    validate_epoch(predicate["compatibilityEpoch"])
    validate_signal_field(predicate["signalField"])
    require(predicate["authority"] == {
        "preparation": "contents:read",
        "attestation": "contents:read,id-token:write,attestations:write",
        "separation": AUTHORITY_SEPARATION,
    }, "compatibility witness authority statement changed")
    require(predicate["claim"] == CLAIM, "compatibility witness claim changed")
    sha40(source_sha, "source.sha")
    return predicate


def build_subject(predicate: Mapping[str, Any]) -> dict[str, Any]:
    validated = validate_predicate(dict(predicate))
    predicate_digest = digest_bytes(canonical_json(validated).encode("utf-8"))
    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": SUBJECT_KIND,
        "repository": REPOSITORY,
        "generatorSha": GENERATOR_SHA,
        "compatibilityEpochDigest": validated["compatibilityEpoch"]["digest"],
        "signalFieldDigest": validated["signalField"]["aggregateDigest"],
        "predicateDigest": predicate_digest,
        "sourceSha": validated["source"]["sha"],
        "runId": validated["source"]["runId"],
        "runAttempt": validated["source"]["runAttempt"],
        "issuedAtEpoch": validated["validity"]["issuedAtEpoch"],
        "expiresAtEpoch": validated["validity"]["expiresAtEpoch"],
    }


def validate_subject(subject: Any, predicate: Mapping[str, Any]) -> dict[str, Any]:
    require(isinstance(subject, dict) and list(subject) == list(SUBJECT_KEYS),
            "compatibility witness subject shape/order changed")
    expected = build_subject(predicate)
    require(subject == expected, "compatibility witness subject does not match exact predicate identity")
    return subject


def consume(
    *, predicate: Mapping[str, Any], subject: Mapping[str, Any], lock_bytes: bytes,
    policy_files: Mapping[str, bytes], signal_field_dir: Path, now_epoch: int,
    source_sha: str, run_id: int, run_attempt: int,
) -> dict[str, Any]:
    value = validate_predicate(dict(predicate))
    validate_subject(dict(subject), value)
    now_epoch = positive_int(now_epoch, "consumer now epoch")
    require(value["validity"]["issuedAtEpoch"] <= now_epoch < value["validity"]["expiresAtEpoch"],
            "compatibility witness is not currently valid")
    require(value["source"]["sha"] == sha40(source_sha, "expected source SHA"),
            "compatibility witness source SHA changed")
    require(value["source"]["runId"] == positive_int(run_id, "expected run ID"),
            "compatibility witness run ID changed")
    require(value["source"]["runAttempt"] == positive_int(run_attempt, "expected run attempt"),
            "compatibility witness run attempt changed")
    require(value["generator"] == generator_identity(lock_bytes),
            "compatibility witness was minted for a different generator identity")
    current_epoch = compatibility_epoch(policy_files)
    require(value["compatibilityEpoch"] == current_epoch,
            "compatibility witness was minted for a different compatibility-policy epoch")
    current_signal = signal_field_inventory(signal_field_dir)
    require(value["signalField"] == current_signal,
            "compatibility witness Signal Field bytes differ from the downloaded raw bundle")
    return value



def timestamp_epoch(value: Any, label: str) -> int:
    require(isinstance(value, str) and value.endswith("Z"),
            f"{label} must be one UTC GitHub timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} must be one UTC GitHub timestamp") from exc
    require(parsed.tzinfo is not None and parsed.utcoffset() is not None
            and parsed.utcoffset().total_seconds() == 0,
            f"{label} must be UTC")
    return positive_int(int(parsed.astimezone(timezone.utc).timestamp()), label)


def repository_identity(value: Any, label: str) -> None:
    require(isinstance(value, Mapping), f"{label} must be an object")
    require(type(value.get("id")) is int and value["id"] == REPOSITORY_ID,
            f"{label} repository ID changed")
    require(value.get("full_name") == REPOSITORY,
            f"{label} repository name changed")


def normalize_producer_run(value: Any, *, label: str = "compatibility witness producer run") -> dict[str, Any]:
    require(isinstance(value, Mapping), f"{label} must be an object")
    run_id = positive_int(value.get("id"), f"{label} id")
    run_attempt = positive_int(value.get("run_attempt"), f"{label} run_attempt")
    require(value.get("name") == WORKFLOW_NAME, f"{label} workflow name changed")
    require(value.get("path") == WORKFLOW_PATH, f"{label} workflow path changed")
    require(value.get("event") in ALLOWED_PRODUCER_EVENTS, f"{label} event is not allowed")
    require(value.get("status") == "completed" and value.get("conclusion") == "success",
            f"{label} is not one completed successful run")
    require(value.get("head_branch") == "main", f"{label} head branch changed")
    head_sha = sha40(value.get("head_sha"), f"{label} head SHA")
    repository_identity(value.get("repository"), f"{label} repository")
    repository_identity(value.get("head_repository"), f"{label} head_repository")
    started_at = value.get("run_started_at")
    started_epoch = timestamp_epoch(started_at, f"{label} run_started_at")
    return {
        "id": run_id,
        "runAttempt": run_attempt,
        "headSha": head_sha,
        "runStartedAt": started_at,
        "runStartedEpoch": started_epoch,
    }


def select_fresh_witness_run(value: Any, *, now_epoch: int) -> dict[str, Any]:
    now_epoch = positive_int(now_epoch, "compatibility witness discovery current epoch")
    require(isinstance(value, Mapping), "compatibility witness run-list response must be an object")
    total_count = value.get("total_count")
    require(type(total_count) is int and total_count >= 0,
            "compatibility witness run-list total_count must be a nonnegative integer")
    runs = value.get("workflow_runs")
    require(isinstance(runs, list),
            "compatibility witness run-list response is missing workflow_runs")
    require(total_count == len(runs), "compatibility witness run-list response is incomplete")
    require(total_count <= MAX_DISCOVERY_RESULTS,
            "compatibility witness run-list exceeds one complete reviewed page")

    normalized = [
        normalize_producer_run(run, label=f"compatibility witness producer run[{index}]")
        for index, run in enumerate(runs)
    ]
    ids = [run["id"] for run in normalized]
    require(len(ids) == len(set(ids)),
            "compatibility witness run-list contains duplicate run IDs")
    fresh = [
        run for run in normalized
        if run["runStartedEpoch"] <= now_epoch < run["runStartedEpoch"] + TTL_SECONDS
    ]
    require(fresh, "compatibility witness run-list contains no fresh successful producer run")
    latest_epoch = max(run["runStartedEpoch"] for run in fresh)
    latest = [run for run in fresh if run["runStartedEpoch"] == latest_epoch]
    require(len(latest) == 1,
            "latest fresh compatibility witness producer run is ambiguous")
    return latest[0]


def validate_attempt_run(value: Any, selected: Mapping[str, Any]) -> dict[str, Any]:
    observed = normalize_producer_run(
        value, label="attempt-specific compatibility witness producer run"
    )
    for key in ("id", "runAttempt", "headSha", "runStartedAt", "runStartedEpoch"):
        require(observed[key] == selected.get(key),
                f"attempt-specific compatibility witness producer run differs from selected run: {key}")
    return observed


def select_witness_artifact(value: Any, selected_run: Mapping[str, Any]) -> dict[str, Any]:
    require(isinstance(value, Mapping),
            "compatibility witness artifact-list response must be an object")
    total_count = value.get("total_count")
    require(type(total_count) is int and total_count >= 0,
            "compatibility witness artifact-list total_count must be a nonnegative integer")
    artifacts = value.get("artifacts")
    require(isinstance(artifacts, list),
            "compatibility witness artifact-list response is missing artifacts")
    require(total_count == len(artifacts),
            "compatibility witness artifact-list response is incomplete")
    require(total_count <= MAX_DISCOVERY_RESULTS,
            "compatibility witness artifact-list exceeds one complete reviewed page")
    require(total_count == 1,
            "expected exactly one compatibility witness artifact for selected run")

    artifact = artifacts[0]
    require(isinstance(artifact, Mapping), "compatibility witness artifact must be an object")
    artifact_id = positive_int(artifact.get("id"), "compatibility witness artifact id")
    require(artifact.get("name") == ARTIFACT_NAME,
            "compatibility witness artifact name changed")
    require(type(artifact.get("expired")) is bool,
            "compatibility witness artifact expired must be a boolean")
    require(artifact["expired"] is False, "compatibility witness artifact is expired")
    artifact_digest = digest(artifact.get("digest"), "compatibility witness artifact digest")
    created_epoch = timestamp_epoch(
        artifact.get("created_at"), "compatibility witness artifact created_at"
    )

    run_started = positive_int(
        selected_run.get("runStartedEpoch"), "selected compatibility witness run start epoch"
    )
    require(run_started <= created_epoch < run_started + 1800,
            "compatibility witness artifact creation is outside the selected producer attempt window")

    workflow_run = artifact.get("workflow_run")
    require(isinstance(workflow_run, Mapping),
            "compatibility witness artifact workflow_run must be an object")
    require(
        positive_int(workflow_run.get("id"), "compatibility witness artifact workflow_run id")
        == selected_run.get("id"),
        "compatibility witness artifact belongs to another workflow run",
    )
    require(type(workflow_run.get("repository_id")) is int
            and workflow_run["repository_id"] == REPOSITORY_ID,
            "compatibility witness artifact workflow_run repository ID changed")
    require(type(workflow_run.get("head_repository_id")) is int
            and workflow_run["head_repository_id"] == REPOSITORY_ID,
            "compatibility witness artifact workflow_run head repository ID changed")
    require(workflow_run.get("head_branch") == "main",
            "compatibility witness artifact workflow_run head branch changed")
    require(
        sha40(workflow_run.get("head_sha"), "compatibility witness artifact workflow_run head SHA")
        == selected_run.get("headSha"),
        "compatibility witness artifact workflow_run head SHA differs from selected run",
    )
    return {
        "id": artifact_id,
        "name": ARTIFACT_NAME,
        "digest": artifact_digest,
        "createdEpoch": created_epoch,
    }


def attestation_verify_args(subject_path: str, source_sha: str) -> list[str]:
    require(isinstance(subject_path, str) and bool(subject_path)
            and "\x00" not in subject_path and "\n" not in subject_path,
            "compatibility witness attestation subject path is invalid")
    source_sha = sha40(source_sha, "compatibility witness attestation source SHA")
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
            "compatibility witness attestation verification must return exactly one statement")
    entry = value[0]
    require(isinstance(entry, Mapping),
            "compatibility witness attestation verification entry must be an object")
    verification = entry.get("verificationResult")
    require(isinstance(verification, Mapping),
            "compatibility witness attestation verification result is missing")
    statement = verification.get("statement")
    require(isinstance(statement, Mapping),
            "compatibility witness attestation statement is missing")
    require(statement.get("predicateType") == PREDICATE_TYPE,
            "compatibility witness attestation predicate type changed")
    require(statement.get("predicate") == predicate,
            "compatibility witness attestation predicate differs from downloaded witness")

    subjects = statement.get("subject")
    require(isinstance(subjects, list) and len(subjects) == 1,
            "compatibility witness attestation statement must bind exactly one subject")
    attested_subject = subjects[0]
    require(isinstance(attested_subject, Mapping),
            "compatibility witness attestation subject entry must be an object")
    require(
        attested_subject.get("name") == "profile-generator-compatibility-witness-subject.json",
        "compatibility witness attestation subject name changed",
    )
    digests = attested_subject.get("digest")
    require(isinstance(digests, Mapping) and set(digests) == {"sha256"},
            "compatibility witness attestation subject digest shape changed")
    expected = hashlib.sha256(canonical_json(subject).encode("utf-8")).hexdigest()
    require(digests.get("sha256") == expected,
            "compatibility witness attestation subject digest differs from downloaded subject")


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
    signal_field_dir: Path,
    now_epoch: int,
) -> dict[str, Any]:
    selected = select_fresh_witness_run(run_list, now_epoch=now_epoch)
    validate_attempt_run(attempt_run, selected)
    artifact = select_witness_artifact(artifact_list, selected)
    predicate = validate_predicate(predicate)
    subject = validate_subject(subject, predicate)

    source = predicate["source"]
    validity = predicate["validity"]
    require(source["runId"] == selected["id"],
            "compatibility witness predicate is bound to another run")
    require(source["runAttempt"] == selected["runAttempt"],
            "compatibility witness predicate is bound to another run attempt")
    require(source["sha"] == selected["headSha"],
            "compatibility witness predicate is bound to another source SHA")
    require(validity["issuedAtEpoch"] == selected["runStartedEpoch"],
            "compatibility witness issuance does not equal selected run start")

    consume(
        predicate=predicate,
        subject=subject,
        lock_bytes=current_lock_bytes,
        policy_files=current_policy_files,
        signal_field_dir=signal_field_dir,
        now_epoch=now_epoch,
        source_sha=selected["headSha"],
        run_id=selected["id"],
        run_attempt=selected["runAttempt"],
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

def expect_failure(callable_obj, expected: str) -> None:
    try:
        callable_obj()
    except (ValueError, json.JSONDecodeError) as exc:
        require(expected in str(exc), f"compatibility witness self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"compatibility witness self-test accepted forbidden drift: {expected}")



def validate_signer_workflow_contract(text: str | None = None) -> None:
    if text is None:
        require(WITNESS_WORKFLOW.is_file() and not WITNESS_WORKFLOW.is_symlink(),
                "profile generator compatibility witness workflow is missing or aliased")
        text = WITNESS_WORKFLOW.read_text(encoding="utf-8")

    marker = "  attest:\n"
    require(text.count(marker) == 1,
            "profile generator compatibility witness signer job identity changed")
    signer = text[text.index(marker):]
    require(signer.startswith(
        "  attest:\n"
        "    name: attest-profile-generator-compatibility-witness-write-only\n"
        "    needs: prepare\n"
        "    runs-on: ubuntu-24.04\n"
        "    timeout-minutes: 4\n"
        "    permissions:\n"
        "      contents: read\n"
        "      id-token: write\n"
        "      attestations: write\n"
    ), "profile generator compatibility witness signer identity/authority changed")

    require(signer.count(
        "uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1"
    ) == 1, "profile generator compatibility witness signer must download exactly one prepared artifact")
    require(signer.count(
        "uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2"
    ) == 1, "profile generator compatibility witness signer must execute exactly one reviewed attestation action")
    for required in (
        "subject-path: compatibility-witness-attestation-input/profile-generator-compatibility-witness-subject.json",
        "predicate-path: compatibility-witness-attestation-input/profile-generator-compatibility-witness.json",
        "predicate-type: https://github.com/portyu9/portyu9/attestations/profile-generator-compatibility/v1",
        "profile-generator-compatibility-witness-subject.json",
        "profile-generator-compatibility-witness.json",
        "raw-signal-field",
        "signal-field-wide-light.svg",
        "signal-field-wide-dark.svg",
        "signal-field-compact-light.svg",
        "signal-field-compact-dark.svg",
        "EXPECTED_PREDICATE_SHA256",
        "EXPECTED_SUBJECT_SHA256",
    ):
        require(required in signer,
                f"profile generator compatibility witness signer lost required identity: {required}")
    require(signer.count("        run: |\n") == 1,
            "profile generator compatibility witness signer authored shell surface changed")
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
                f"profile generator compatibility witness signer acquired forbidden surface: {forbidden}")

def self_test() -> None:
    validate_schema_contract()
    validate_signer_workflow_contract()
    lock_path = ROOT / ".github/action-lock.json"
    require(lock_path.is_file() and not lock_path.is_symlink(), "action-lock is missing or aliased")
    lock_bytes = lock_path.read_bytes()
    policy = policy_files_from_root(ROOT)
    generator_identity(lock_bytes)
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        for index, name in enumerate(EXPECTED_FILES, start=1):
            (directory / name).write_text(f"<svg data-fixture=\"{index}\"/>\n", encoding="utf-8")
        predicate = build_predicate(
            source_sha="a" * 40, run_id=123, run_attempt=2, issued_at_epoch=1_790_000_000,
            lock_bytes=lock_bytes, policy_files=policy, signal_field_dir=directory,
        )
        subject = build_subject(predicate)
        consume(
            predicate=predicate, subject=subject, lock_bytes=lock_bytes, policy_files=policy,
            signal_field_dir=directory, now_epoch=1_790_000_001,
            source_sha="a" * 40, run_id=123, run_attempt=2,
        )

        run = {
            "id": 123,
            "run_attempt": 2,
            "name": WORKFLOW_NAME,
            "path": WORKFLOW_PATH,
            "event": "push",
            "status": "completed",
            "conclusion": "success",
            "head_branch": "main",
            "head_sha": "a" * 40,
            "run_started_at": "2026-09-21T14:13:20Z",
            "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
            "head_repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
        }
        older = copy.deepcopy(run)
        older["id"] = 122
        older["run_attempt"] = 1
        older["run_started_at"] = "2026-09-21T13:56:40Z"
        run_list = {"total_count": 2, "workflow_runs": [older, run]}
        selected = select_fresh_witness_run(run_list, now_epoch=1_790_000_001)
        require(selected["id"] == 123 and selected["runAttempt"] == 2,
                "canonical compatibility consumer evidence self-test lost selected run")

        artifact = {
            "id": 91,
            "name": ARTIFACT_NAME,
            "expired": False,
            "digest": "sha256:" + "f" * 64,
            "created_at": "2026-09-21T14:14:20Z",
            "workflow_run": {
                "id": 123,
                "repository_id": REPOSITORY_ID,
                "head_repository_id": REPOSITORY_ID,
                "head_branch": "main",
                "head_sha": "a" * 40,
            },
        }
        artifact_list = {"total_count": 1, "artifacts": [artifact]}
        selected_artifact = select_witness_artifact(artifact_list, selected)
        require(selected_artifact["id"] == 91,
                "canonical compatibility consumer evidence self-test lost selected artifact")

        subject_sha256 = hashlib.sha256(canonical_json(subject).encode("utf-8")).hexdigest()
        verified = [{
            "verificationResult": {
                "statement": {
                    "predicateType": PREDICATE_TYPE,
                    "predicate": copy.deepcopy(predicate),
                    "subject": [{
                        "name": "profile-generator-compatibility-witness-subject.json",
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
            current_policy_files=policy,
            signal_field_dir=directory,
            now_epoch=1_790_000_001,
        )
        require(
            evidence == {
                "runId": 123,
                "runAttempt": 2,
                "sourceSha": "a" * 40,
                "artifactId": 91,
                "artifactDigest": "sha256:" + "f" * 64,
                "expiresAtEpoch": 1_790_000_000 + TTL_SECONDS,
            },
            "canonical compatibility consumer evidence result changed",
        )
        args = attestation_verify_args(
            "compatibility/profile-generator-compatibility-witness-subject.json",
            "a" * 40,
        )
        require(args == [
            "gh", "attestation", "verify",
            "compatibility/profile-generator-compatibility-witness-subject.json",
            "--repo", REPOSITORY,
            "--predicate-type", PREDICATE_TYPE,
            "--signer-workflow", f"{REPOSITORY}/{WORKFLOW_PATH}",
            "--signer-digest", "a" * 40,
            "--source-digest", "a" * 40,
            "--source-ref", SOURCE_REF,
            "--deny-self-hosted-runners",
            "--format", "json",
        ], "compatibility witness attestation verification command contract changed")

        expect_failure(
            lambda: select_fresh_witness_run(
                {"total_count": 3, "workflow_runs": [older, run]},
                now_epoch=1_790_000_001,
            ),
            "run-list response is incomplete",
        )
        expect_failure(
            lambda: select_fresh_witness_run(
                {"total_count": 101, "workflow_runs": [copy.deepcopy(run) for _ in range(101)]},
                now_epoch=1_790_000_001,
            ),
            "exceeds one complete reviewed page",
        )
        duplicate_run = copy.deepcopy(run)
        duplicate_run["run_started_at"] = "2026-09-21T14:13:19Z"
        expect_failure(
            lambda: select_fresh_witness_run(
                {"total_count": 2, "workflow_runs": [run, duplicate_run]},
                now_epoch=1_790_000_001,
            ),
            "duplicate run IDs",
        )
        ambiguous_run = copy.deepcopy(run)
        ambiguous_run["id"] = 124
        expect_failure(
            lambda: select_fresh_witness_run(
                {"total_count": 2, "workflow_runs": [run, ambiguous_run]},
                now_epoch=1_790_000_001,
            ),
            "latest fresh compatibility witness producer run is ambiguous",
        )
        expect_failure(
            lambda: select_fresh_witness_run(
                {"total_count": 1, "workflow_runs": [run]},
                now_epoch=1_790_000_000 + TTL_SECONDS,
            ),
            "no fresh successful producer run",
        )
        wrong_path_run = copy.deepcopy(run)
        wrong_path_run["path"] = ".github/workflows/other.yml"
        expect_failure(
            lambda: select_fresh_witness_run(
                {"total_count": 1, "workflow_runs": [wrong_path_run]},
                now_epoch=1_790_000_001,
            ),
            "workflow path changed",
        )
        wrong_attempt = copy.deepcopy(run)
        wrong_attempt["run_attempt"] = 3
        expect_failure(
            lambda: validate_attempt_run(wrong_attempt, selected),
            "differs from selected run: runAttempt",
        )

        expect_failure(
            lambda: select_witness_artifact(
                {"total_count": 2, "artifacts": [artifact]}, selected
            ),
            "artifact-list response is incomplete",
        )
        duplicate_artifact = copy.deepcopy(artifact)
        duplicate_artifact["id"] = 92
        expect_failure(
            lambda: select_witness_artifact(
                {"total_count": 2, "artifacts": [artifact, duplicate_artifact]}, selected
            ),
            "exactly one compatibility witness artifact",
        )
        expired_artifact = copy.deepcopy(artifact)
        expired_artifact["expired"] = True
        expect_failure(
            lambda: select_witness_artifact(
                {"total_count": 1, "artifacts": [expired_artifact]}, selected
            ),
            "artifact is expired",
        )
        wrong_artifact_run = copy.deepcopy(artifact)
        wrong_artifact_run["workflow_run"] = dict(artifact["workflow_run"])
        wrong_artifact_run["workflow_run"]["id"] = 999
        expect_failure(
            lambda: select_witness_artifact(
                {"total_count": 1, "artifacts": [wrong_artifact_run]}, selected
            ),
            "belongs to another workflow run",
        )
        old_artifact = copy.deepcopy(artifact)
        old_artifact["created_at"] = "2026-09-21T13:00:00Z"
        expect_failure(
            lambda: select_witness_artifact(
                {"total_count": 1, "artifacts": [old_artifact]}, selected
            ),
            "outside the selected producer attempt window",
        )

        wrong_type = copy.deepcopy(verified)
        wrong_type[0]["verificationResult"]["statement"]["predicateType"] = (
            "https://example.invalid/predicate"
        )
        expect_failure(
            lambda: validate_verified_attestation(wrong_type, predicate, subject),
            "predicate type changed",
        )
        wrong_attested_predicate = copy.deepcopy(verified)
        wrong_attested_predicate[0]["verificationResult"]["statement"]["predicate"]["source"]["runId"] = 999
        expect_failure(
            lambda: validate_verified_attestation(
                wrong_attested_predicate, predicate, subject
            ),
            "predicate differs from downloaded witness",
        )
        wrong_attested_subject = copy.deepcopy(verified)
        wrong_attested_subject[0]["verificationResult"]["statement"]["subject"][0]["digest"]["sha256"] = "e" * 64
        expect_failure(
            lambda: validate_verified_attestation(
                wrong_attested_subject, predicate, subject
            ),
            "subject digest differs from downloaded subject",
        )
        expect_failure(
            lambda: validate_verified_attestation(
                verified + copy.deepcopy(verified), predicate, subject
            ),
            "exactly one statement",
        )
        expect_failure(lambda: consume(
            predicate=predicate, subject=subject, lock_bytes=lock_bytes, policy_files=policy,
            signal_field_dir=directory, now_epoch=predicate["validity"]["expiresAtEpoch"],
            source_sha="a" * 40, run_id=123, run_attempt=2,
        ), "not currently valid")
        expect_failure(lambda: consume(
            predicate=predicate, subject=subject, lock_bytes=lock_bytes, policy_files=policy,
            signal_field_dir=directory, now_epoch=1_790_000_001,
            source_sha="b" * 40, run_id=123, run_attempt=2,
        ), "source SHA changed")
        expect_failure(lambda: consume(
            predicate=predicate, subject=subject, lock_bytes=lock_bytes, policy_files=policy,
            signal_field_dir=directory, now_epoch=1_790_000_001,
            source_sha="a" * 40, run_id=123, run_attempt=3,
        ), "run attempt changed")
        changed_policy = dict(policy)
        changed_policy["scripts/signal-field-pipeline-v2.json"] += b"\n"
        expect_failure(lambda: consume(
            predicate=predicate, subject=subject, lock_bytes=lock_bytes, policy_files=changed_policy,
            signal_field_dir=directory, now_epoch=1_790_000_001,
            source_sha="a" * 40, run_id=123, run_attempt=2,
        ), "different compatibility-policy epoch")
        original = (directory / EXPECTED_FILES[0]).read_bytes()
        (directory / EXPECTED_FILES[0]).write_bytes(original + b" ")
        expect_failure(lambda: consume(
            predicate=predicate, subject=subject, lock_bytes=lock_bytes, policy_files=policy,
            signal_field_dir=directory, now_epoch=1_790_000_001,
            source_sha="a" * 40, run_id=123, run_attempt=2,
        ), "Signal Field bytes differ")
        (directory / EXPECTED_FILES[0]).write_bytes(original)
        bad = copy.deepcopy(predicate)
        bad["invocation"]["profile"] = "other"
        expect_failure(lambda: validate_predicate(bad), "invocation changed")
        expect_failure(lambda: strict_json('{"x":1,"x":2}'), "duplicate object key")
        extra = directory / "extra.svg"
        extra.write_text("<svg/>\n", encoding="utf-8")
        expect_failure(lambda: signal_field_inventory(directory), "file inventory changed")

    workflow_text = WITNESS_WORKFLOW.read_text(encoding="utf-8")
    expect_failure(
        lambda: validate_signer_workflow_contract(
            workflow_text.replace("      contents: read\n      id-token: write",
                                  "      contents: write\n      id-token: write", 1)
        ),
        "signer identity/authority changed",
    )
    expect_failure(
        lambda: validate_signer_workflow_contract(
            workflow_text.replace(
                "      - name: Download exact prepared compatibility witness bundle\n",
                "      - name: Forbidden checkout\n"
                "        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n\n"
                "      - name: Download exact prepared compatibility witness bundle\n",
                1,
            )
        ),
        "forbidden surface: actions/checkout@",
    )
    expect_failure(
        lambda: validate_signer_workflow_contract(
            workflow_text.replace(
                '          [[ "$EXPECTED_PREDICATE_SHA256" =~ ^[0-9a-f]{64}$ ]]\n',
                "          python3 scripts/profile_generator_compatibility_witness.py self-test\n"
                '          [[ "$EXPECTED_PREDICATE_SHA256" =~ ^[0-9a-f]{64}$ ]]\n',
                1,
            )
        ),
        "forbidden surface: python3 ",
    )
    print(
        "Profile generator compatibility witness contract passed: exact immutable generator + invocation, "
        "six-hour validity, closed compatibility epoch, four-file raw Signal Field identity, duplicate-safe "
        "canonical predicate/subject binding, stale/mismatch rejection, and no network or mutation authority."
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("self-test")
    build = sub.add_parser("build")
    build.add_argument("--source-sha", required=True)
    build.add_argument("--run-id", type=int, required=True)
    build.add_argument("--run-attempt", type=int, required=True)
    build.add_argument("--issued-at", type=int, required=True)
    build.add_argument("--signal-field-dir", type=Path, required=True)
    build.add_argument("--lock", type=Path, required=True)
    build.add_argument("--policy-root", type=Path, default=ROOT)
    build.add_argument("--predicate-out", type=Path, required=True)
    build.add_argument("--subject-out", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--predicate", type=Path, required=True)
    verify.add_argument("--subject", type=Path, required=True)
    verify.add_argument("--signal-field-dir", type=Path, required=True)
    verify.add_argument("--lock", type=Path, required=True)
    verify.add_argument("--policy-root", type=Path, default=ROOT)
    verify.add_argument("--now", type=int, required=True)
    verify.add_argument("--source-sha", required=True)
    verify.add_argument("--run-id", type=int, required=True)
    verify.add_argument("--run-attempt", type=int, required=True)

    select_run = sub.add_parser("select-run")
    select_run.add_argument("--runs", type=Path, required=True)
    select_run.add_argument("--now", type=int, required=True)
    select_run.add_argument("--out", type=Path, required=True)

    select_artifact = sub.add_parser("select-artifact")
    select_artifact.add_argument("--artifacts", type=Path, required=True)
    select_artifact.add_argument("--selected-run", type=Path, required=True)
    select_artifact.add_argument("--out", type=Path, required=True)

    consume_evidence = sub.add_parser("consume-evidence")
    consume_evidence.add_argument("--run-list", type=Path, required=True)
    consume_evidence.add_argument("--attempt-run", type=Path, required=True)
    consume_evidence.add_argument("--artifact-list", type=Path, required=True)
    consume_evidence.add_argument("--predicate", type=Path, required=True)
    consume_evidence.add_argument("--subject", type=Path, required=True)
    consume_evidence.add_argument("--verified-attestation", type=Path, required=True)
    consume_evidence.add_argument("--signal-field-dir", type=Path, required=True)
    consume_evidence.add_argument("--lock", type=Path, required=True)
    consume_evidence.add_argument("--policy-root", type=Path, default=ROOT)
    consume_evidence.add_argument("--now", type=int, required=True)
    consume_evidence.add_argument("--out", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    try:
        args = parse_args()
        if args.command == "self-test":
            self_test()
            return 0
        if args.command == "select-run":
            selected = select_fresh_witness_run(
                strict_json(args.runs.read_text(encoding="utf-8")),
                now_epoch=args.now,
            )
            args.out.write_text(canonical_json(selected), encoding="utf-8")
            print(
                f"Selected fresh profile generator compatibility witness run "
                f"{selected['id']} attempt {selected['runAttempt']} at {selected['headSha']}."
            )
            return 0
        if args.command == "select-artifact":
            selected_run = strict_json(args.selected_run.read_text(encoding="utf-8"))
            artifact = select_witness_artifact(
                strict_json(args.artifacts.read_text(encoding="utf-8")),
                selected_run,
            )
            args.out.write_text(canonical_json(artifact), encoding="utf-8")
            print(
                f"Selected exact profile generator compatibility witness artifact "
                f"{artifact['id']} with digest {artifact['digest']}."
            )
            return 0

        lock_bytes = args.lock.read_bytes()
        policy = policy_files_from_root(args.policy_root)
        if args.command == "build":
            predicate = build_predicate(
                source_sha=args.source_sha, run_id=args.run_id, run_attempt=args.run_attempt,
                issued_at_epoch=args.issued_at, lock_bytes=lock_bytes, policy_files=policy,
                signal_field_dir=args.signal_field_dir,
            )
            subject = build_subject(predicate)
            args.predicate_out.write_text(canonical_json(predicate), encoding="utf-8")
            args.subject_out.write_text(canonical_json(subject), encoding="utf-8")
            return 0
        if args.command == "consume-evidence":
            evidence = validate_consumer_evidence(
                run_list=strict_json(args.run_list.read_text(encoding="utf-8")),
                attempt_run=strict_json(args.attempt_run.read_text(encoding="utf-8")),
                artifact_list=strict_json(args.artifact_list.read_text(encoding="utf-8")),
                predicate=strict_json(args.predicate.read_text(encoding="utf-8")),
                subject=strict_json(args.subject.read_text(encoding="utf-8")),
                verified_attestation=strict_json(
                    args.verified_attestation.read_text(encoding="utf-8")
                ),
                current_lock_bytes=lock_bytes,
                current_policy_files=policy,
                signal_field_dir=args.signal_field_dir,
                now_epoch=args.now,
            )
            args.out.write_text(canonical_json(evidence), encoding="utf-8")
            print(
                f"Accepted cryptographically verified profile generator compatibility witness "
                f"run {evidence['runId']} attempt {evidence['runAttempt']} "
                f"through epoch {evidence['expiresAtEpoch']}."
            )
            return 0

        predicate = strict_json(args.predicate.read_text(encoding="utf-8"))
        subject = strict_json(args.subject.read_text(encoding="utf-8"))
        consume(
            predicate=predicate, subject=subject, lock_bytes=lock_bytes, policy_files=policy,
            signal_field_dir=args.signal_field_dir, now_epoch=args.now, source_sha=args.source_sha,
            run_id=args.run_id, run_attempt=args.run_attempt,
        )
        print("Profile generator compatibility witness accepted.")
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: profile generator compatibility witness failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
