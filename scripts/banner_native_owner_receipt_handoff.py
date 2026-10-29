#!/usr/bin/env python3
"""Native same-run owner receipt provenance for the separate banner App merger.

This is a read-only, fail-closed source component. A credential-free JSON
receipt alone is not a credential and cannot certify its own origin. Before
the App job may import it, prove the real trusted-main workflow_run, completed
successful owner job, native one-day artifact metadata and SHA256-bound bounded
ZIP. The App terminal writer MUST separately reobserve the current owner
APPROVED review, vetoes, native checks and exact main/head before any merge.
No workflow currently invokes this module. No mutation is possible here.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Callable
import zipfile

import banner_native_app_origin_envelope as envelope
import banner_native_observer_cli as observer
import banner_native_owner_review_transaction_contract as owner_contract
import banner_native_transaction_artifact_cli as transaction
from banner_native_authenticated_app_source import FixedOriginRead, REPOSITORY
from banner_native_publisher_run_artifact import unique_object

WORKFLOW = "Approved banner rotation"
WORKFLOW_PATH = ".github/workflows/approved-banner-rotation.yml"
OWNER_JOB = "review-authenticated-banner-owner"
OWNER_APPROVE_STEP = "Approve exact current-day banner as owner"
OWNER_UPLOAD_STEP = "Upload exact owner receipt"
ARTIFACT_NAME = "approved-banner-owner-receipt"
ARTIFACT_FILE = "owner-review.json"
MAX_ARCHIVE = 2_097_152
MAX_JSON = 1_048_576
MAX_ITEMS = 29
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
OWNER_KEYS = frozenset({
    "initial", "appIdentity", "ownerIdentity", "reviewed",
    "ownerStatus", "ownerResponse",
})


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def utc(value: Any) -> datetime:
    require(type(value) is str and value.endswith("Z"),
            "same-run owner source timestamp is not UTC Z")
    try:
        moment = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("same-run owner source time malformed") from exc
    require(moment.utcoffset() == timedelta(), "owner source clock drift")
    return moment


def authenticated_owner_source(*, run: Any, jobs: Any,
                               artifacts: Any, main_sha: str,
                               repository_id: int, run_id: int,
                               observed_at: datetime) -> dict[str, Any]:
    """Select one genuine completed owner job and its same-run ZIP by ID."""
    require(type(observed_at) is datetime and observed_at.tzinfo is not None
            and observed_at.utcoffset() == timedelta(),
            "owner receipt verifier needs a UTC observation")
    require(type(main_sha) is str and SHA.fullmatch(main_sha) is not None
            and type(repository_id) is int and repository_id > 0
            and type(run_id) is int and run_id > 0,
            "owner handoff needs exact main/repository/run IDs")
    require(type(run) is dict
            and run.get("id") == run_id
            and run.get("name") == WORKFLOW
            and run.get("path") == WORKFLOW_PATH
            and run.get("event") == "workflow_run"
            and run.get("head_branch") == "main"
            and run.get("head_sha") == main_sha
            and run.get("status") == "in_progress"
            and run.get("conclusion") is None
            and type(run.get("run_attempt")) is int
            and run["run_attempt"] == 1
            and type(run.get("repository")) is dict
            and run["repository"].get("full_name") == "portyu9/portyu9"
            and run["repository"].get("id") == repository_id
            and type(run.get("head_repository")) is dict
            and run["head_repository"].get("full_name") == "portyu9/portyu9",
            "owner receipt does not originate in exact native trusted-main workflow")
    launched = utc(run.get("created_at"))
    require(launched.date() == observed_at.date()
            and launched <= observed_at
            and observed_at - launched <= timedelta(hours=6),
            "native owner run expired, crossed UTC day or is from the future")
    require(type(jobs) is dict and type(jobs.get("total_count")) is int
            and type(jobs.get("jobs")) is list
            and jobs["total_count"] == len(jobs["jobs"])
            and len(jobs["jobs"]) <= MAX_ITEMS
            and all(type(x) is dict and type(x.get("id")) is int
                    and x["id"] > 0 for x in jobs["jobs"])
            and len({x["id"] for x in jobs["jobs"]}) == len(jobs["jobs"]),
            "owner jobs inventory truncated or duplicate")
    chosen = [job for job in jobs["jobs"] if job.get("name") == OWNER_JOB]
    require(len(chosen) == 1, "missing or ambiguous exact owner job")
    owner = chosen[0]
    started = utc(owner.get("started_at"))
    completed = utc(owner.get("completed_at"))
    require(type(owner.get("run_id")) is int
            and owner["run_id"] == run_id
            and owner.get("head_sha") == main_sha
            and owner.get("status") == "completed"
            and owner.get("conclusion") == "success"
            and launched <= started <= completed <= observed_at
            and type(owner.get("steps")) is list,
            "owner job was not a successful current-run exact-main completion")
    steps = owner["steps"]
    require(len(steps) <= 50 and
            all(type(step) is dict for step in steps),
            "native owner steps are malformed")
    for required in (OWNER_APPROVE_STEP, OWNER_UPLOAD_STEP):
        matching = [step for step in steps if step.get("name") == required]
        require(len(matching) == 1
                and matching[0].get("status") == "completed"
                and matching[0].get("conclusion") == "success",
                "native owner job lacks successful exact reviewer/artifact step")
    require(type(artifacts) is dict
            and type(artifacts.get("total_count")) is int
            and type(artifacts.get("artifacts")) is list
            and artifacts["total_count"] == len(artifacts["artifacts"])
            and len(artifacts["artifacts"]) <= MAX_ITEMS
            and all(type(x) is dict and type(x.get("id")) is int
                    and x["id"] > 0 for x in artifacts["artifacts"])
            and len({x["id"] for x in artifacts["artifacts"]}) ==
                len(artifacts["artifacts"]),
            "owner receipt artifact inventory incomplete or ambiguous")
    chosen_artifacts = [a for a in artifacts["artifacts"]
                        if a.get("name") == ARTIFACT_NAME]
    require(len(chosen_artifacts) == 1,
            "same-run owner receipt artifact missing or ambiguous")
    artifact = chosen_artifacts[0]
    emitted = utc(artifact.get("created_at"))
    expiry = utc(artifact.get("expires_at"))
    identity = artifact.get("workflow_run")
    digest = artifact.get("digest")
    require(type(identity) is dict
            and identity.get("id") == run_id
            and identity.get("head_sha") == main_sha
            and identity.get("head_branch") == "main"
            and identity.get("repository_id") == repository_id
            and identity.get("head_repository_id") == repository_id
            and type(digest) is str and DIGEST.fullmatch(digest) is not None
            and type(artifact.get("size_in_bytes")) is int
            and 0 < artifact["size_in_bytes"] <= MAX_ARCHIVE
            and artifact.get("expired") is False
            and artifact.get("archive_download_url") ==
                f"https://api.github.com/repos/portyu9/portyu9/actions/artifacts/{artifact['id']}/zip"
            and started <= emitted <= completed
            and emitted < expiry <= emitted + timedelta(days=2)
            and observed_at < expiry,
            "owner handoff artifact not from exact successful owner job")
    return {
        "runId": run_id, "ownerJobId": owner["id"],
        "artifactId": artifact["id"], "sha256": digest[7:],
        "mainSha": main_sha, "repositoryId": repository_id,
        "utcDay": observed_at.date().isoformat(),
    }


def unpack_receipt(archive: bytes) -> dict[str, Any]:
    """Never extract ZIP paths to the filesystem or admit extra members."""
    require(type(archive) is bytes and 0 < len(archive) <= MAX_ARCHIVE,
            "owner receipt ZIP missing or oversized")
    try:
        with zipfile.ZipFile(io.BytesIO(archive), "r") as source:
            members = source.infolist()
            require(source.comment == b"" and len(members) == 1,
                    "owner receipt ZIP contains extra members or comments")
            item = members[0]
            mode = item.external_attr >> 16
            require(item.filename == ARTIFACT_FILE
                    and not item.is_dir()
                    and stat.S_IFMT(mode) != stat.S_IFLNK
                    and not (item.flag_bits & 1)
                    and item.compress_type in (
                        zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED,
                    )
                    and 0 < item.file_size <= MAX_JSON
                    and item.compress_size > 0
                    and item.file_size <= item.compress_size * 50,
                    "owner ZIP member type, size or path is untrusted")
            raw = source.read(item)
            require(len(raw) == item.file_size,
                    "owner ZIP decompression size changed")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, ValueError, zipfile.BadZipFile, EOFError,
            RuntimeError, json.JSONDecodeError) as exc:
        raise ValueError("owner ZIP contains malformed or ambiguous JSON") from exc
    require(type(value) is dict and set(value) == OWNER_KEYS,
            "owner receipt fields were expanded or omitted")
    envelope.no_credentials(value)
    # This authenticates the receipt's *structure*, not its producer.
    # The native completed owner job + SHA256 attest the producer; the
    # isolated App terminal MUST observe a fresh current GitHub review.
    transaction.compile_transaction("authenticated-review-receipt", value)
    return value


def attest(*, proof: Any, archive: bytes, observed_at: datetime) -> dict[str, Any]:
    require(type(proof) is dict and set(proof) == {
        "runId", "ownerJobId", "artifactId", "sha256",
        "mainSha", "repositoryId", "utcDay",
    } and type(proof["sha256"]) is str
            and re.fullmatch(r"[0-9a-f]{64}", proof["sha256"]) is not None
            and proof["utcDay"] == observed_at.date().isoformat()
            and hashlib.sha256(archive).hexdigest() == proof["sha256"],
            "owner handoff archive does not match native same-run digest")
    value = unpack_receipt(archive)
    require(value["initial"]["mainSha"] == proof["mainSha"]
            and value["appIdentity"]["expected_repository_id"] ==
                proof["repositoryId"],
            "owner receipt does not bind current main and repository")
    return value


def collect(*, read: Callable[[str], Any], repository_id: int,
            run_id: int, observed_at: datetime) -> dict[str, Any]:
    root = f"{REPOSITORY}/actions/runs/{run_id}"
    main = read(f"{REPOSITORY}/git/ref/heads/main")
    require(type(main) is dict and main.get("ref") == "refs/heads/main"
            and type(main.get("object")) is dict
            and main["object"].get("type") == "commit",
            "owner bridge cannot verify immutable accepted main")
    sha = main["object"].get("sha")
    proof = authenticated_owner_source(
        run=read(root), jobs=read(root + "/jobs"),
        artifacts=read(root + "/artifacts"),
        main_sha=sha, repository_id=repository_id,
        run_id=run_id, observed_at=observed_at,
    )
    require(read(f"{REPOSITORY}/git/ref/heads/main") == main,
            "main changed while native owner receipt was collected")
    return proof


def self_test() -> None:
    import banner_native_live_admission as admission
    original = admission.fixture()
    clock = utc(original["observedAt"]) + timedelta(minutes=8)
    stamp = lambda moment: moment.isoformat(timespec="seconds").replace("+00:00", "Z")
    now = clock
    earlier = clock - timedelta(minutes=6)
    finish = clock - timedelta(minutes=1)
    rid = 91122
    owner_request = transaction.compile_transaction(
        "review-request", {"initial": original})
    approval = {
        "id": 103, "user": {"login": owner_contract.REVIEW_LOGIN, "id": 9922},
        "state": "APPROVED", "commit_id": owner_request["headSha"],
        "body": owner_request["request"]["body"],
        "submitted_at": stamp(earlier + timedelta(minutes=2)),
    }
    reviewed = copy.deepcopy(original)
    reviewed["observedAt"] = stamp(earlier + timedelta(minutes=4))
    reviewed["reviews"].append(copy.deepcopy(approval))
    reviewed["completeness"]["reviews"]["totalCount"] = 1
    docs = {
        "initial": original, "appIdentity": original["nativeApp"],
        "ownerIdentity": {
            "login": owner_contract.REVIEW_LOGIN, "userId": 9922,
            "repositoryId": original["nativeApp"]["expected_repository_id"],
            "repository": "portyu9/portyu9", "defaultBranch": "main",
        },
        "reviewed": reviewed, "ownerStatus": "HTTP/1.1 200 OK",
        "ownerResponse": approval,
    }
    transaction.compile_transaction("authenticated-review-receipt", docs)
    raw = json.dumps(docs, separators=(",", ":")).encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(ARTIFACT_FILE, raw)
    archive = output.getvalue()
    sha = original["mainSha"]
    repository_id = docs["ownerIdentity"]["repositoryId"]
    run = {
        "id": rid, "name": WORKFLOW, "path": WORKFLOW_PATH,
        "event": "workflow_run", "head_branch": "main", "head_sha": sha,
        "status": "in_progress", "conclusion": None, "run_attempt": 1,
        "created_at": stamp(earlier - timedelta(minutes=1)),
        "repository": {"id": repository_id, "full_name": "portyu9/portyu9"},
        "head_repository": {"full_name": "portyu9/portyu9"},
    }
    owner = {
        "id": 89, "name": OWNER_JOB, "run_id": rid, "head_sha": sha,
        "status": "completed", "conclusion": "success",
        "started_at": stamp(earlier), "completed_at": stamp(finish),
        "steps": [
            {"name": OWNER_APPROVE_STEP, "status": "completed",
             "conclusion": "success"},
            {"name": OWNER_UPLOAD_STEP, "status": "completed",
             "conclusion": "success"},
        ],
    }
    meta = {
        "id": 90, "name": ARTIFACT_NAME, "expired": False,
        "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
        "size_in_bytes": len(archive),
        "created_at": stamp(earlier + timedelta(minutes=5)),
        "expires_at": stamp(earlier + timedelta(days=1)),
        "workflow_run": {
            "id": rid, "head_sha": sha, "head_branch": "main",
            "repository_id": repository_id, "head_repository_id": repository_id,
        },
        "archive_download_url":
            "https://api.github.com/repos/portyu9/portyu9/actions/artifacts/90/zip",
    }
    good = {
        "run": run, "jobs": {"total_count": 1, "jobs": [owner]},
        "artifacts": {"total_count": 1, "artifacts": [meta]},
        "main_sha": sha, "repository_id": repository_id, "run_id": rid,
        "observed_at": now,
    }
    proof = authenticated_owner_source(**good)
    require(proof["artifactId"] == 90
            and attest(proof=proof, archive=archive, observed_at=now) == docs,
            "native same-run owner attestation did not verify real receipt")
    def reject(label: str, mutate: Callable[[dict[str, Any]], None]) -> None:
        bad = copy.deepcopy(good)
        mutate(bad)
        try:
            authenticated_owner_source(**bad)
        except (ValueError, TypeError, KeyError):
            return
        raise AssertionError("untrusted native owner handoff accepted " + label)
    reject("wrong workflow", lambda x: x["run"].update(name="forged"))
    reject("wrong event", lambda x: x["run"].update(event="workflow_dispatch"))
    reject("changed main", lambda x: x["run"].update(head_sha="f"*40))
    reject("manual rerun", lambda x: x["run"].update(run_attempt=2))
    reject("completed entire run", lambda x: x["run"].update(
        status="completed", conclusion="success"))
    reject("foreign repository", lambda x: x["run"]["repository"].update(id=3))
    reject("truncated job list", lambda x: x["jobs"].update(total_count=2))
    reject("owner job failed", lambda x: x["jobs"]["jobs"][0].update(
        conclusion="failure"))
    reject("absent review step", lambda x: x["jobs"]["jobs"][0]["steps"].pop())
    reject("duplicate owner job", lambda x: (
        x["jobs"].update(total_count=2),
        x["jobs"]["jobs"].append({**owner, "id": 91})))
    reject("missing artifact", lambda x: x["artifacts"].update(
        total_count=0, artifacts=[]))
    reject("wrong digest", lambda x: x["artifacts"]["artifacts"][0].update(
        digest="sha256:" + "z"*64))
    reject("other run source", lambda x:
           x["artifacts"]["artifacts"][0]["workflow_run"].update(id=42))
    reject("expired artifact", lambda x:
           x["artifacts"]["artifacts"][0].update(expired=True))
    reject("extra artifact", lambda x: (
        x["artifacts"].update(total_count=2),
        x["artifacts"]["artifacts"].append({**meta, "id": 91})))
    try:
        attest(proof=proof, archive=b"forged", observed_at=now)
    except (ValueError, TypeError, KeyError):
        pass
    else:
        raise AssertionError("forged native owner archive accepted")
    tampered = copy.deepcopy(docs)
    tampered["token"] = "forbidden"
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(ARTIFACT_FILE, json.dumps(tampered))
    try:
        unpack_receipt(out.getvalue())
    except (ValueError, TypeError, KeyError):
        pass
    else:
        raise AssertionError("credential-bearing owner receipt accepted")
    print("native banner owner handoff: same-run real owner successful job, "
          "artifact digest/ZIP and 17 adversarial veto probes PASS")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--selection-out", type=Path)
    mode.add_argument("--owner-receipt-out", type=Path)
    parser.add_argument("--repository-id", type=int)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    if args.self_test:
        require(args.selection_out is None and args.owner_receipt_out is None
                and args.repository_id is None and args.archive is None,
                "owner handoff self-test may not access credentials/files")
        self_test()
        return 0
    require(type(args.repository_id) is int and args.repository_id > 0
            and os.environ.get("GITHUB_REPOSITORY") == "portyu9/portyu9"
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_run"
            and type(os.environ.get("GITHUB_RUN_ID")) is str
            and os.environ["GITHUB_RUN_ID"].isdigit(),
            "owner artifact handoff requires exact trusted-main workflow_run")
    run_id = int(os.environ["GITHUB_RUN_ID"])
    token = os.environ.get("GH_TOKEN")
    require(type(token) is str and len(token) >= 8
            and os.environ.get("BANNER_OWNER_TOKEN") is None,
            "App handoff must use read-only token and no owner credential")
    root = f"{REPOSITORY}/actions/runs/{run_id}"
    reader = FixedOriginRead(token, frozenset({
        f"{REPOSITORY}/git/ref/heads/main", root,
        root + "/jobs", root + "/artifacts",
    }))
    now = datetime.now(timezone.utc).replace(microsecond=0)
    proof = collect(read=reader.get, repository_id=args.repository_id,
                    run_id=run_id, observed_at=now)
    if args.selection_out is not None:
        require(args.archive is None and args.owner_receipt_out is None,
                "owner handoff selection must not accept archive input")
        observer.write_exclusive(args.selection_out, proof)
        return 0
    require(args.owner_receipt_out is not None and args.archive is not None
            and args.selection_out is None,
            "owner receipt import requires only exact downloaded ZIP")
    from banner_native_owner_review_writer import read_bounded_source_zip
    archive = read_bounded_source_zip(args.archive)
    documents = attest(proof=proof, archive=archive, observed_at=now)
    observer.write_exclusive(args.owner_receipt_out, documents)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
