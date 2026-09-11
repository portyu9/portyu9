#!/usr/bin/env python3
"""Build and validate the post-publication generated-profile receipt predicate."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import Any

import profile_evidence_subjects as subjects

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "portyu9/portyu9"
WORKFLOW_PATH = ".github/workflows/profile-stats.yml"
WORKFLOW_REF = f"{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main"
GENERATED_REF = "refs/heads/generated"
KIND = "profile-publication-receipt"
SCHEMA_VERSION = 1
PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "profile-publication-receipt-v1.schema.json"
)
PREDICATE_SCHEMA = ROOT / ".github/attestation/profile-publication-receipt-v1.schema.json"
SOURCE_EPOCH = ROOT / "scripts/profile-stats-source-epoch-v1.json"
SOURCE_EPOCH_VERSION = "profile-stats-source-epoch-v1"
SOURCE_EPOCH_ALGORITHM = "sha256-sorted-path-nul-git-blob-oid-lf-v1"
SUBJECT_NAME = "generated-publication-subject.json"
COMMIT_MESSAGE = "chore: publish validated profile evidence [skip ci]"
BOT_IDENTITY = "github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>"
AUTHORITY = {
    "preparation": "contents:read",
    "attestation": "id-token:write,attestations:write",
    "publication": "contents:write",
    "separation": (
        "Publication completes before receipt preparation; the receipt signer cannot write "
        "repository contents and executes no repository-authored code."
    ),
}
CLAIM = (
    "The actual generated branch commit and parent were revalidated after publication and are "
    "bound to the exact published evidence digests and trusted source epoch; this attests "
    "repository-defined publication provenance, not universal correctness."
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE_DECIMAL = re.compile(r"^[1-9][0-9]*$")
PUBLISHED_PATHS = subjects.published_paths()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"publication receipt JSON contains duplicate object key: {key}")
        result[key] = value
    return result


def strict_json_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        payload = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{label} is invalid JSON: {exc}") from exc
    require(isinstance(payload, dict), f"{label} root must be an object")
    return payload


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return (json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def required_env(name: str, env: dict[str, str]) -> str:
    value = env.get(name, "").strip()
    require(bool(value), f"required environment variable is missing: {name}")
    return value


def git(root: Path, *args: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(root), *args],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "LC_ALL": "C"},
    )
    require(completed.returncode == 0,
            f"read-only git command failed ({' '.join(args)}): {completed.stderr.strip()}")
    return completed.stdout.rstrip("\n")


def schema_identity() -> dict[str, str]:
    subjects.require_regular_file(PREDICATE_SCHEMA, "publication receipt predicate schema")
    return {"id": PREDICATE_TYPE, "digest": f"sha256:{sha256_bytes(PREDICATE_SCHEMA.read_bytes())}"}


def source_epoch_identity(source_revision: str) -> dict[str, Any]:
    subjects.require_regular_file(SOURCE_EPOCH, "profile source epoch")
    payload = strict_json_bytes(SOURCE_EPOCH.read_bytes(), "profile source epoch")
    require(set(payload) == {"version", "algorithm", "file_count", "closure_sha256"},
            "profile source epoch keys changed")
    require(payload.get("version") == SOURCE_EPOCH_VERSION, "profile source epoch version changed")
    require(payload.get("algorithm") == SOURCE_EPOCH_ALGORITHM, "profile source epoch algorithm changed")
    file_count = payload.get("file_count")
    require(type(file_count) is int and file_count > 0, "profile source epoch file_count is invalid")
    closure = payload.get("closure_sha256")
    require(isinstance(closure, str) and SHA64.fullmatch(closure) is not None,
            "profile source epoch closure digest is malformed")
    require(SHA40.fullmatch(source_revision) is not None, "source revision is malformed")
    return {
        "sourceRevision": source_revision,
        "version": SOURCE_EPOCH_VERSION,
        "algorithm": SOURCE_EPOCH_ALGORITHM,
        "fileCount": file_count,
        "closureSha256": closure,
    }


def publication_identity(root: Path, expected_commit: str, expected_parent: str) -> dict[str, str]:
    require(SHA40.fullmatch(expected_commit) is not None, "expected generated commit is malformed")
    require(SHA40.fullmatch(expected_parent) is not None, "expected generated parent is malformed")
    require(expected_commit != expected_parent, "generated commit and parent must differ")
    subjects.validate_published_root(root)

    commit = git(root, "rev-parse", "HEAD")
    parent = git(root, "rev-parse", "HEAD^")
    require(commit == expected_commit, "published generated HEAD differs from sealed candidate")
    require(parent == expected_parent, "published generated parent differs from sealed base")
    require(len(git(root, "rev-list", "--parents", "-n", "1", "HEAD").split()) == 2,
            "published generated commit must have exactly one parent")

    tree = git(root, "show", "-s", "--format=%T", "HEAD")
    message = git(root, "show", "-s", "--format=%s", "HEAD")
    author = git(root, "show", "-s", "--format=%an <%ae>", "HEAD")
    committer = git(root, "show", "-s", "--format=%cn <%ce>", "HEAD")
    require(SHA40.fullmatch(tree) is not None, "published generated tree identity is malformed")
    require(message == COMMIT_MESSAGE, "published generated commit message changed")
    require(author == BOT_IDENTITY, "published generated author identity changed")
    require(committer == BOT_IDENTITY, "published generated committer identity changed")

    observed: list[tuple[str, str]] = []
    for line in git(root, "ls-tree", "-r", "HEAD").splitlines():
        metadata, path = line.split("\t", 1)
        mode, object_type, _object_id = metadata.split()
        require(object_type == "blob", f"published generated tree contains non-blob subject: {path}")
        observed.append((mode, path))
    require([path for _mode, path in observed] == list(PUBLISHED_PATHS),
            "published generated tree paths differ from the canonical eleven subjects")
    require(all(mode == "100644" for mode, _path in observed),
            "published generated tree contains non-100644 subject mode")

    return {
        "ref": GENERATED_REF,
        "commit": commit,
        "parent": parent,
        "tree": tree,
        "message": message,
        "author": author,
        "committer": committer,
    }


def evidence_digests(root: Path) -> list[dict[str, str]]:
    subjects.validate_published_root(root)
    result: list[dict[str, str]] = []
    for relative in PUBLISHED_PATHS:
        path = root / relative
        subjects.require_regular_file(path, "published receipt subject")
        result.append({"path": relative, "digest": f"sha256:{sha256_bytes(path.read_bytes())}"})
    return result


def build_subject_descriptor(publication: dict[str, str]) -> dict[str, str]:
    return {
        "kind": "generated-publication",
        "repository": REPOSITORY,
        "ref": GENERATED_REF,
        "commit": publication["commit"],
        "parent": publication["parent"],
        "tree": publication["tree"],
    }


def build_predicate(env: dict[str, str], published_root: Path) -> tuple[dict[str, Any], bytes]:
    repository = required_env("GITHUB_REPOSITORY", env)
    source_revision = required_env("GITHUB_SHA", env)
    workflow_ref = required_env("GITHUB_WORKFLOW_REF", env)
    workflow_sha = required_env("GITHUB_WORKFLOW_SHA", env)
    run_id = required_env("GITHUB_RUN_ID", env)
    run_attempt = required_env("GITHUB_RUN_ATTEMPT", env)
    server = required_env("GITHUB_SERVER_URL", env).rstrip("/")
    expected_commit = required_env("EXPECTED_GENERATED_SHA", env)
    expected_parent = required_env("EXPECTED_GENERATED_PARENT_SHA", env)
    candidate_id = required_env("TRANSACTION_CANDIDATE_ID", env)
    lease_id = required_env("MUTATION_LEASE_ID", env)

    require(repository == REPOSITORY, f"unexpected receipt repository: {repository!r}")
    require(SHA40.fullmatch(source_revision) is not None, "GITHUB_SHA is malformed")
    require(workflow_ref == WORKFLOW_REF, "publication receipt workflow ref changed")
    require(workflow_sha == source_revision, "publication receipt workflow SHA must equal source revision")
    require(POSITIVE_DECIMAL.fullmatch(run_id) is not None, "publication receipt run id is malformed")
    require(POSITIVE_DECIMAL.fullmatch(run_attempt) is not None, "publication receipt run attempt is malformed")
    require(server == "https://github.com", "publication receipt server identity changed")
    require(SHA64.fullmatch(candidate_id) is not None, "transaction candidate id is malformed")
    require(SHA64.fullmatch(lease_id) is not None, "mutation lease id is malformed")

    publication = publication_identity(published_root, expected_commit, expected_parent)
    descriptor = build_subject_descriptor(publication)
    descriptor_bytes = canonical_json_bytes(descriptor)
    predicate: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": KIND,
        "repository": REPOSITORY,
        "workflow": {"path": WORKFLOW_PATH, "ref": WORKFLOW_REF, "sha": workflow_sha},
        "run": {"id": run_id, "attempt": run_attempt, "url": f"{server}/{REPOSITORY}/actions/runs/{run_id}"},
        "predicateSchema": schema_identity(),
        "transaction": {"candidateId": candidate_id, "leaseId": lease_id},
        "sourceEpoch": source_epoch_identity(source_revision),
        "publication": publication,
        "subjectDescriptor": {"name": SUBJECT_NAME, "digest": f"sha256:{sha256_bytes(descriptor_bytes)}"},
        "evidenceSubjects": evidence_digests(published_root),
        "authority": dict(AUTHORITY),
        "claim": CLAIM,
    }
    validate_receipt(predicate, descriptor_bytes, published_root)
    return predicate, descriptor_bytes


def validate_receipt(predicate: dict[str, Any], descriptor_bytes: bytes, published_root: Path) -> None:
    require(set(predicate) == {
        "schemaVersion", "kind", "repository", "workflow", "run", "predicateSchema", "transaction",
        "sourceEpoch", "publication", "subjectDescriptor", "evidenceSubjects", "authority", "claim"
    }, "publication receipt predicate keys changed")
    require(type(predicate.get("schemaVersion")) is int and predicate["schemaVersion"] == SCHEMA_VERSION,
            "publication receipt schemaVersion changed")
    require(predicate.get("kind") == KIND and predicate.get("repository") == REPOSITORY,
            "publication receipt predicate identity changed")
    workflow = predicate.get("workflow")
    require(workflow == {"path": WORKFLOW_PATH, "ref": WORKFLOW_REF, "sha": workflow.get("sha") if isinstance(workflow, dict) else None},
            "publication receipt workflow block changed")
    require(isinstance(workflow, dict) and isinstance(workflow.get("sha"), str) and
            SHA40.fullmatch(workflow["sha"]) is not None, "publication receipt workflow SHA is malformed")

    run = predicate.get("run")
    require(isinstance(run, dict) and set(run) == {"id", "attempt", "url"}, "publication receipt run block changed")
    require(isinstance(run.get("id"), str) and POSITIVE_DECIMAL.fullmatch(run["id"]) is not None,
            "publication receipt run id is malformed")
    require(isinstance(run.get("attempt"), str) and POSITIVE_DECIMAL.fullmatch(run["attempt"]) is not None,
            "publication receipt run attempt is malformed")
    require(run.get("url") == f"https://github.com/{REPOSITORY}/actions/runs/{run['id']}",
            "publication receipt run URL changed")
    require(predicate.get("predicateSchema") == schema_identity(), "publication receipt schema identity changed")

    transaction = predicate.get("transaction")
    require(isinstance(transaction, dict) and set(transaction) == {"candidateId", "leaseId"},
            "publication receipt transaction block changed")
    require(all(isinstance(transaction.get(key), str) and SHA64.fullmatch(transaction[key]) is not None
                for key in ("candidateId", "leaseId")), "publication receipt transaction identity is malformed")

    source_epoch = predicate.get("sourceEpoch")
    require(isinstance(source_epoch, dict), "publication receipt source epoch is missing")
    require(source_epoch == source_epoch_identity(source_epoch.get("sourceRevision", "")),
            "publication receipt source epoch changed")
    require(workflow["sha"] == source_epoch["sourceRevision"],
            "publication receipt source/workflow revision binding changed")

    publication = predicate.get("publication")
    require(isinstance(publication, dict), "publication receipt publication block is missing")
    observed_publication = publication_identity(published_root, publication.get("commit", ""), publication.get("parent", ""))
    require(publication == observed_publication, "publication receipt commit topology changed")

    descriptor = strict_json_bytes(descriptor_bytes, "publication subject descriptor")
    require(descriptor == build_subject_descriptor(publication), "publication subject descriptor changed")
    expected_descriptor = {"name": SUBJECT_NAME, "digest": f"sha256:{sha256_bytes(descriptor_bytes)}"}
    require(predicate.get("subjectDescriptor") == expected_descriptor,
            "publication receipt subject descriptor digest changed")
    require(predicate.get("evidenceSubjects") == evidence_digests(published_root),
            "publication receipt evidence digests differ from actual generated bytes")
    require(predicate.get("authority") == AUTHORITY, "publication receipt authority contract changed")
    require(predicate.get("claim") == CLAIM, "publication receipt claim boundary changed")


def write_receipt(env: dict[str, str], published_root: Path, subject_output: Path, predicate_output: Path) -> None:
    predicate, descriptor_bytes = build_predicate(env, published_root)
    require(subject_output.parent == Path(".") or subject_output.parent.is_dir(), "receipt subject output parent is missing")
    require(predicate_output.parent == Path(".") or predicate_output.parent.is_dir(), "receipt predicate output parent is missing")
    subject_output.write_bytes(descriptor_bytes)
    predicate_output.write_bytes(canonical_json_bytes(predicate))


def fixture_env(commit: str, parent: str) -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_SHA": "a" * 40,
        "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
        "GITHUB_WORKFLOW_SHA": "a" * 40,
        "GITHUB_RUN_ID": "123456789",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SERVER_URL": "https://github.com",
        "EXPECTED_GENERATED_SHA": commit,
        "EXPECTED_GENERATED_PARENT_SHA": parent,
        "TRANSACTION_CANDIDATE_ID": "b" * 64,
        "MUTATION_LEASE_ID": "c" * 64,
    }


def git_write(root: Path, *args: str) -> None:
    completed = subprocess.run(["git", "-C", str(root), *args], check=False, capture_output=True, text=True)
    require(completed.returncode == 0, f"receipt fixture git command failed: {completed.stderr.strip()}")


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "published"
        root.mkdir()
        subjects.fixture_published_root(root)
        git_write(root, "init", "-q")
        git_write(root, "config", "user.name", "github-actions[bot]")
        git_write(root, "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com")
        git_write(root, "add", ".")
        git_write(root, "commit", "-q", "-m", "fixture parent")
        parent = git(root, "rev-parse", "HEAD")
        first = root / PUBLISHED_PATHS[0]
        first.write_bytes(first.read_bytes() + b"published\n")
        git_write(root, "add", ".")
        git_write(root, "commit", "-q", "-m", COMMIT_MESSAGE)
        commit = git(root, "rev-parse", "HEAD")
        env = fixture_env(commit, parent)
        predicate, descriptor_bytes = build_predicate(env, root)
        validate_receipt(predicate, descriptor_bytes, root)

        wrong_parent = dict(env)
        wrong_parent["EXPECTED_GENERATED_PARENT_SHA"] = "d" * 40
        try:
            build_predicate(wrong_parent, root)
        except ValueError as exc:
            require("parent differs" in str(exc), f"wrong-parent self-test failed for wrong reason: {exc}")
        else:
            raise ValueError("publication receipt self-test accepted wrong generated parent")

        drifted = json.loads(json.dumps(predicate))
        drifted["subjectDescriptor"]["digest"] = "sha256:" + "0" * 64
        try:
            validate_receipt(drifted, descriptor_bytes, root)
        except ValueError as exc:
            require("descriptor digest" in str(exc), f"descriptor-drift self-test failed for wrong reason: {exc}")
        else:
            raise ValueError("publication receipt self-test accepted subject descriptor drift")

        evidence_drift = json.loads(json.dumps(predicate))
        evidence_drift["evidenceSubjects"][0]["digest"] = "sha256:" + "0" * 64
        try:
            validate_receipt(evidence_drift, descriptor_bytes, root)
        except ValueError as exc:
            require("evidence digests" in str(exc), f"evidence-drift self-test failed for wrong reason: {exc}")
        else:
            raise ValueError("publication receipt self-test accepted evidence digest drift")

        extra = root / "unexpected.txt"
        extra.write_text("unexpected\n", encoding="utf-8")
        try:
            build_predicate(env, root)
        except ValueError as exc:
            require("inventory mismatch" in str(exc), f"extra-subject self-test failed for wrong reason: {exc}")
        else:
            raise ValueError("publication receipt self-test accepted extra generated subject")

    epoch = source_epoch_identity("a" * 40)
    malformed_epoch = dict(epoch)
    malformed_epoch["closureSha256"] = "bad"
    require(not SHA64.fullmatch(str(malformed_epoch["closureSha256"])),
            "publication receipt source-epoch malformed-digest self-test fixture failed")
    print(
        f"Profile publication receipt builder self-test passed: {KIND}-v{SCHEMA_VERSION} · "
        f"{len(PUBLISHED_PATHS)} actual published subject digests · generated commit/parent/source epoch bound"
    )


def main(argv: list[str]) -> int:
    try:
        if argv == ["--self-test"]:
            self_test()
            return 0
        if len(argv) != 3:
            raise ValueError(
                "usage: build-profile-publication-receipt.py <published-root> <subject-output> <predicate-output>"
            )
        write_receipt(os.environ, Path(argv[0]), Path(argv[1]), Path(argv[2]))
        print(f"Profile publication receipt built: {argv[1]} + {argv[2]}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
