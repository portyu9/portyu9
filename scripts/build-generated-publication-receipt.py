#!/usr/bin/env python3
"""Build and validate the post-publication generated-commit receipt predicate."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any

import profile_evidence_subjects as subjects

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "portyu9/portyu9"
WORKFLOW_REF = f"{REPOSITORY}/.github/workflows/profile-stats.yml@refs/heads/main"
KIND = "generated-publication-receipt"
SCHEMA_VERSION = 1
PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "generated-publication-receipt-v1.schema.json"
)
PREDICATE_SCHEMA = ROOT / ".github/attestation/generated-publication-receipt-v1.schema.json"
SOURCE_EPOCH = ROOT / "scripts/profile-stats-source-epoch-v1.json"
SOURCE_EPOCH_VERSION = "profile-stats-source-epoch-v1"
SOURCE_EPOCH_ALGORITHM = "sha256-sorted-path-nul-git-blob-oid-lf-v1"
PROFILE_PREDICATE_KIND = "profile-evidence-attestation"
PROFILE_PREDICATE_SCHEMA_VERSION = 3
CLAIM = (
    "This receipt binds the actual published generated Git commit and parent to the exact "
    "validated evidence bytes, production source epoch, workflow run, and leased transaction "
    "that produced the publication."
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"publication receipt JSON contains duplicate key: {key}")
        result[key] = value
    return result


def strict_json(path: Path, label: str) -> dict[str, Any]:
    subjects.require_regular_file(path, label)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    require(isinstance(payload, dict), f"{label} root must be an object")
    return payload


def required_env(name: str, env: dict[str, str]) -> str:
    value = env.get(name, "").strip()
    require(bool(value), f"required environment variable is missing: {name}")
    return value


def canonical_positive_decimal(name: str, value: str) -> str:
    require(POSITIVE_DECIMAL.fullmatch(value) is not None,
            f"{name} must be one canonical positive decimal string")
    return value


def schema_identity() -> dict[str, str]:
    subjects.require_regular_file(PREDICATE_SCHEMA, "publication receipt predicate schema")
    return {
        "id": PREDICATE_TYPE,
        "digest": f"sha256:{hashlib.sha256(PREDICATE_SCHEMA.read_bytes()).hexdigest()}",
    }


def source_epoch() -> dict[str, Any]:
    payload = strict_json(SOURCE_EPOCH, "Profile Stats source epoch")
    require(set(payload) == {"version", "algorithm", "file_count", "closure_sha256"},
            "Profile Stats source epoch keys changed")
    require(payload["version"] == SOURCE_EPOCH_VERSION, "Profile Stats source epoch version changed")
    require(payload["algorithm"] == SOURCE_EPOCH_ALGORITHM, "Profile Stats source epoch algorithm changed")
    file_count = payload["file_count"]
    require(type(file_count) is int and file_count > 0, "Profile Stats source epoch file_count must be positive")
    closure = payload["closure_sha256"]
    require(isinstance(closure, str) and SHA64.fullmatch(closure) is not None,
            "Profile Stats source epoch closure_sha256 is malformed")
    return {
        "version": SOURCE_EPOCH_VERSION,
        "algorithm": SOURCE_EPOCH_ALGORITHM,
        "fileCount": file_count,
        "closureSha256": closure,
    }


def profile_predicate_identity(path: Path, env: dict[str, str]) -> tuple[str, dict[str, Any]]:
    payload = strict_json(path, "reviewed profile evidence attestation predicate")
    source_sha = required_env("GITHUB_SHA", env)
    run_id = canonical_positive_decimal("GITHUB_RUN_ID", required_env("GITHUB_RUN_ID", env))
    run_attempt = canonical_positive_decimal(
        "GITHUB_RUN_ATTEMPT", required_env("GITHUB_RUN_ATTEMPT", env)
    )
    require(payload.get("schemaVersion") == PROFILE_PREDICATE_SCHEMA_VERSION,
            "profile evidence predicate schemaVersion changed")
    require(payload.get("kind") == PROFILE_PREDICATE_KIND,
            "profile evidence predicate kind changed")
    require(payload.get("repository") == REPOSITORY,
            "profile evidence predicate repository changed")
    require(payload.get("sourceRevision") == source_sha,
            "profile evidence predicate source revision differs from publication source")
    require(payload.get("workflowRef") == WORKFLOW_REF,
            "profile evidence predicate workflow identity changed")
    run = payload.get("run")
    require(isinstance(run, dict) and run.get("id") == run_id and run.get("attempt") == run_attempt,
            "profile evidence predicate run identity differs from publication run")
    subject_set = payload.get("subjectSet")
    require(
        isinstance(subject_set, dict)
        and subject_set.get("name") == subjects.NAME
        and subject_set.get("publishedPaths") == list(subjects.published_paths()),
        "profile evidence predicate subject-set identity changed",
    )
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    return digest, payload


def evidence_subjects(published_root: Path) -> list[dict[str, str]]:
    subjects.validate_published_root(published_root)
    result: list[dict[str, str]] = []
    for relative in subjects.published_paths():
        path = published_root / relative
        subjects.require_regular_file(path, "published receipt evidence subject")
        result.append({"path": relative, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()})
    require(len(result) == 11, "publication receipt subject set must contain exactly eleven files")
    return result


def build_receipt(env: dict[str, str], published_root: Path, profile_predicate: Path) -> dict[str, Any]:
    repository = required_env("GITHUB_REPOSITORY", env)
    source_sha = required_env("GITHUB_SHA", env)
    workflow_ref = required_env("GITHUB_WORKFLOW_REF", env)
    run_id = canonical_positive_decimal("GITHUB_RUN_ID", required_env("GITHUB_RUN_ID", env))
    run_attempt = canonical_positive_decimal(
        "GITHUB_RUN_ATTEMPT", required_env("GITHUB_RUN_ATTEMPT", env)
    )
    server = required_env("GITHUB_SERVER_URL", env).rstrip("/")
    published_sha = required_env("PUBLISHED_SHA", env)
    parent_sha = required_env("PUBLISHED_PARENT_SHA", env)
    git_object_sha256 = required_env("GIT_OBJECT_SHA256", env)
    lease_id = required_env("LEASE_ID", env)
    candidate_id = required_env("CANDIDATE_ID", env)

    require(repository == REPOSITORY, f"unexpected receipt repository: {repository!r}")
    require(workflow_ref == WORKFLOW_REF, f"unexpected receipt workflow identity: {workflow_ref!r}")
    require(server == "https://github.com", f"unexpected GitHub server URL: {server!r}")
    for label, value in (("GITHUB_SHA", source_sha), ("PUBLISHED_SHA", published_sha),
                         ("PUBLISHED_PARENT_SHA", parent_sha)):
        require(SHA40.fullmatch(value) is not None, f"{label} must be one lowercase 40-character Git SHA")
    require(published_sha != parent_sha, "published commit must differ from its parent")
    for label, value in (("GIT_OBJECT_SHA256", git_object_sha256), ("LEASE_ID", lease_id),
                         ("CANDIDATE_ID", candidate_id)):
        require(SHA64.fullmatch(value) is not None, f"{label} must be one lowercase SHA-256 hex digest")

    profile_digest, _ = profile_predicate_identity(profile_predicate, env)
    expected_candidate = hashlib.sha256(
        f"{source_sha}\n{parent_sha}\n{profile_digest}\n".encode("ascii")
    ).hexdigest()
    require(candidate_id == expected_candidate,
            "publication receipt candidate identity is not the exact leased Profile Stats candidate")

    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": KIND,
        "repository": REPOSITORY,
        "workflowRef": WORKFLOW_REF,
        "run": {
            "id": run_id,
            "attempt": run_attempt,
            "url": f"{server}/{REPOSITORY}/actions/runs/{run_id}",
        },
        "predicateSchema": schema_identity(),
        "source": {"mainSha": source_sha, "epoch": source_epoch()},
        "transaction": {"leaseId": lease_id, "candidateId": candidate_id},
        "publication": {
            "branch": "generated",
            "commitSha": published_sha,
            "parentSha": parent_sha,
            "gitObjectSha256": git_object_sha256,
        },
        "evidence": {
            "profileEvidencePredicateSha256": profile_digest,
            "subjectSet": subjects.NAME,
            "subjects": evidence_subjects(published_root),
        },
        "claim": CLAIM,
    }


def validate_receipt(receipt: dict[str, Any]) -> None:
    require(set(receipt) == {
        "schemaVersion", "kind", "repository", "workflowRef", "run", "predicateSchema",
        "source", "transaction", "publication", "evidence", "claim",
    }, "publication receipt top-level keys changed")
    require(receipt["schemaVersion"] == SCHEMA_VERSION and receipt["kind"] == KIND,
            "publication receipt schema/kind changed")
    require(receipt["repository"] == REPOSITORY and receipt["workflowRef"] == WORKFLOW_REF,
            "publication receipt repository/workflow identity changed")
    run = receipt["run"]
    require(isinstance(run, dict) and set(run) == {"id", "attempt", "url"},
            "publication receipt run block changed")
    run_id = str(run.get("id", ""))
    run_attempt = str(run.get("attempt", ""))
    canonical_positive_decimal("receipt run.id", run_id)
    canonical_positive_decimal("receipt run.attempt", run_attempt)
    require(run["url"] == f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
            "publication receipt run URL changed")
    require(receipt["predicateSchema"] == schema_identity(),
            "publication receipt predicate schema identity changed")

    source = receipt["source"]
    require(isinstance(source, dict) and set(source) == {"mainSha", "epoch"},
            "publication receipt source block changed")
    require(isinstance(source["mainSha"], str) and SHA40.fullmatch(source["mainSha"]) is not None,
            "publication receipt source main SHA is malformed")
    require(source["epoch"] == source_epoch(), "publication receipt source epoch changed")

    transaction = receipt["transaction"]
    require(isinstance(transaction, dict) and set(transaction) == {"leaseId", "candidateId"},
            "publication receipt transaction block changed")
    require(all(isinstance(transaction[key], str) and SHA64.fullmatch(transaction[key]) is not None
                for key in ("leaseId", "candidateId")),
            "publication receipt transaction digest is malformed")

    publication = receipt["publication"]
    require(isinstance(publication, dict) and set(publication) == {
        "branch", "commitSha", "parentSha", "gitObjectSha256",
    }, "publication receipt publication block changed")
    require(publication["branch"] == "generated", "publication receipt branch changed")
    require(all(isinstance(publication[key], str) and SHA40.fullmatch(publication[key]) is not None
                for key in ("commitSha", "parentSha")),
            "publication receipt Git identity is malformed")
    require(publication["commitSha"] != publication["parentSha"],
            "publication receipt commit cannot equal parent")
    require(isinstance(publication["gitObjectSha256"], str)
            and SHA64.fullmatch(publication["gitObjectSha256"]) is not None,
            "publication receipt Git object SHA-256 is malformed")

    evidence = receipt["evidence"]
    require(isinstance(evidence, dict) and set(evidence) == {
        "profileEvidencePredicateSha256", "subjectSet", "subjects",
    }, "publication receipt evidence block changed")
    require(isinstance(evidence["profileEvidencePredicateSha256"], str)
            and SHA64.fullmatch(evidence["profileEvidencePredicateSha256"]) is not None,
            "publication receipt profile predicate digest is malformed")
    require(evidence["subjectSet"] == subjects.NAME,
            "publication receipt subject-set name changed")
    subject_values = evidence["subjects"]
    require(isinstance(subject_values, list) and len(subject_values) == 11,
            "publication receipt evidence subjects must contain exactly eleven entries")
    require([item.get("path") if isinstance(item, dict) else None for item in subject_values]
            == list(subjects.published_paths()),
            "publication receipt evidence subject order/inventory changed")
    for item in subject_values:
        require(isinstance(item, dict) and set(item) == {"path", "sha256"},
                "publication receipt evidence subject shape changed")
        require(isinstance(item["sha256"], str) and SHA64.fullmatch(item["sha256"]) is not None,
                "publication receipt evidence subject digest is malformed")
    require(receipt["claim"] == CLAIM, "publication receipt claim boundary changed")


def fixture_env() -> dict[str, str]:
    predicate_digest = hashlib.sha256(b"fixture-profile-predicate").hexdigest()
    source_sha = "a" * 40
    parent_sha = "b" * 40
    return {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_SHA": source_sha,
        "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
        "GITHUB_RUN_ID": "123456789",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SERVER_URL": "https://github.com",
        "PUBLISHED_SHA": "c" * 40,
        "PUBLISHED_PARENT_SHA": parent_sha,
        "GIT_OBJECT_SHA256": "d" * 64,
        "LEASE_ID": "e" * 64,
        "CANDIDATE_ID": hashlib.sha256(
            f"{source_sha}\n{parent_sha}\n{predicate_digest}\n".encode("ascii")
        ).hexdigest(),
    }


def write_fixture_profile_predicate(path: Path, env: dict[str, str]) -> None:
    payload = {
        "schemaVersion": PROFILE_PREDICATE_SCHEMA_VERSION,
        "kind": PROFILE_PREDICATE_KIND,
        "repository": REPOSITORY,
        "sourceRevision": env["GITHUB_SHA"],
        "workflowRef": WORKFLOW_REF,
        "run": {"id": env["GITHUB_RUN_ID"], "attempt": env["GITHUB_RUN_ATTEMPT"]},
        "subjectSet": {"name": subjects.NAME, "publishedPaths": list(subjects.published_paths())},
    }
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def expect_failure(env: dict[str, str], published: Path, predicate: Path, expected: str) -> None:
    try:
        build_receipt(env, published, predicate)
    except ValueError as exc:
        require(expected in str(exc), f"publication receipt self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"publication receipt self-test accepted forbidden drift: {expected}")


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        published = root / "published"
        published.mkdir()
        subjects.fixture_published_root(published)
        predicate = root / "attestation-predicate.json"
        env = fixture_env()
        write_fixture_profile_predicate(predicate, env)
        # fixture_env derives the candidate from a stable fixture predicate marker;
        # replace it with the real fixture predicate digest before building.
        env["CANDIDATE_ID"] = hashlib.sha256(
            f"{env['GITHUB_SHA']}\n{env['PUBLISHED_PARENT_SHA']}\n{hashlib.sha256(predicate.read_bytes()).hexdigest()}\n".encode("ascii")
        ).hexdigest()
        receipt = build_receipt(env, published, predicate)
        validate_receipt(receipt)

        wrong_parent = dict(env)
        wrong_parent["PUBLISHED_PARENT_SHA"] = "f" * 40
        expect_failure(wrong_parent, published, predicate, "candidate identity")

        wrong_run = dict(env)
        wrong_run["GITHUB_RUN_ATTEMPT"] = "2"
        expect_failure(wrong_run, published, predicate, "run identity")

        subject = published / subjects.published_paths()[0]
        original = subject.read_bytes()
        subject.write_bytes(original + b"drift")
        drifted = build_receipt(env, published, predicate)
        validate_receipt(drifted)
        require(drifted["evidence"]["subjects"][0]["sha256"] != receipt["evidence"]["subjects"][0]["sha256"],
                "publication receipt self-test did not bind evidence bytes")

        malformed = dict(receipt)
        malformed["publication"] = dict(receipt["publication"])
        malformed["publication"]["gitObjectSha256"] = "bad"
        try:
            validate_receipt(malformed)
        except ValueError as exc:
            require("Git object SHA-256" in str(exc),
                    f"publication receipt validator self-test failed for wrong reason: {exc}")
        else:
            raise ValueError("publication receipt validator accepted malformed Git object digest")


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            "usage: build-generated-publication-receipt.py <published-root> "
            "<profile-evidence-predicate.json> <output.json>",
            file=sys.stderr,
        )
        return 2
    try:
        published = Path(argv[1])
        predicate = Path(argv[2])
        output = Path(argv[3])
        receipt = build_receipt(dict(os.environ), published, predicate)
        validate_receipt(receipt)
        output.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
