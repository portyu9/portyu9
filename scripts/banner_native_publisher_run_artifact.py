#!/usr/bin/env python3
"""Attest one scheduled, immutable native GitHub App banner-origin ZIP.

This is a DATA-ONLY bridge from the isolated selected-App publisher to a
future owner-only reviewer. The caller MUST obtain the *real* completed
GitHub Actions run and complete artifact inventory over authenticated HTTPS,
download the actual GitHub archive, and independently collect a fresh exact
native banner snapshot. An artifact/JSON string alone never proves provenance,
grants review or authorizes a merge.

No GitHub credential, App JWT, owner token, status, review or ref mutation.
The existing publisher does not yet emit this artifact; its future upload and
reviewer workflow require separately measured and pre-accepted capability/TCB
authorization before deployment.
"""
from __future__ import annotations

import copy
from datetime import date, datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import stat
from typing import Any
import zipfile

import banner_native_app_origin_envelope as origin
import banner_native_live_admission as admission
import independent_banner_candidate_contract as contract
from banner_native_authenticated_app_source import unique_object

WORKFLOW = "Rotate approved profile banners independently"
WORKFLOW_PATH = ".github/workflows/approved-banner-rotation.yml"
ARTIFACT_NAME = "approved-banner-app-origin"
ARTIFACT_FILE = "app-origin.json"
REPOSITORY = "portyu9/portyu9"
MAX_ARCHIVE = 131_072
MAX_JSON = 32_768
MAX_ARTIFACTS = 99
TTL = timedelta(hours=2)
ARCHIVE_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
KEYS = frozenset({
    "schemaVersion", "repository", "producerWorkflow", "producerRunId",
    "producerRunAttempt", "producerEvent", "observedAt", "utcDay",
    "prNumber", "baseSha", "headSha", "headRef", "appEvidence",
})


def require(valid: bool, reason: str) -> None:
    if not valid:
        raise ValueError(reason)


def at_utc(value: Any) -> datetime:
    require(type(value) is str and value.endswith("Z"),
            "native publisher timestamp must be canonical UTC")
    return admission.exact_utc(value)


def build(*, app_evidence: Any, pr: Any, base_sha: str, run_id: int,
          observed_at: datetime) -> dict[str, Any]:
    """Build the credential-free producer statement AFTER a real App PR POST."""
    require(type(observed_at) is datetime and observed_at.tzinfo is not None
            and observed_at.utcoffset() == timedelta(),
            "publisher source clock is not UTC")
    require(type(run_id) is int and run_id > 0,
            "publisher source run ID is invalid")
    require(type(base_sha) is str
            and contract.HEX40.fullmatch(base_sha) is not None,
            "publisher source accepted-main SHA malformed")
    require(type(app_evidence) is dict
            and set(app_evidence) == origin.INPUT - {"repository"},
            "publisher source App identity not normalized")
    producer = contract.verified_native_banner_app_identity(**app_evidence)
    require(type(pr) is dict and type(pr.get("number")) is int
            and pr["number"] > 0
            and type(pr.get("head")) is dict
            and type(pr.get("base")) is dict
            and type(pr.get("user")) is dict
            and pr["user"].get("id") == producer["userId"]
            and pr["user"].get("login") == producer["login"]
            and pr.get("state") == "open"
            and pr.get("draft") is False
            and pr["base"].get("ref") == "main"
            and pr["base"].get("sha") == base_sha
            and pr["head"].get("repo", {}).get("full_name") == REPOSITORY,
            "native App publisher source PR is absent or not exact")
    head = pr["head"].get("sha")
    ref = pr["head"].get("ref")
    require(type(head) is str
            and contract.HEX40.fullmatch(head) is not None
            and head != base_sha
            and type(ref) is str
            and ref == contract.expected_branch(observed_at.date(), base_sha),
            "App-origin PR ref/head not the current UTC candidate")
    data = {
        "schemaVersion": 1,
        "repository": REPOSITORY,
        "producerWorkflow": WORKFLOW,
        "producerRunId": run_id,
        "producerRunAttempt": 1,
        "producerEvent": "schedule",
        "observedAt": observed_at.isoformat(timespec="seconds").replace(
            "+00:00", "Z",
        ),
        "utcDay": observed_at.date().isoformat(),
        "prNumber": pr["number"],
        "baseSha": base_sha,
        "headSha": head,
        "headRef": ref,
        "appEvidence": copy.deepcopy(app_evidence),
    }
    origin.no_credentials(data)
    require(set(data) == KEYS
            and len(json.dumps(data, sort_keys=True).encode("utf-8")) <= MAX_JSON,
            "publisher source envelope expanded beyond closed schema")
    return data


def unpack_exact(archive: Any) -> dict[str, Any]:
    """Parse a single bounded in-memory GitHub ZIP without extracting paths."""
    require(type(archive) is bytes and 0 < len(archive) <= MAX_ARCHIVE,
            "publisher artifact archive missing or too large")
    try:
        with zipfile.ZipFile(io.BytesIO(archive), mode="r") as source:
            entries = source.infolist()
            require(source.comment == b""
                    and len(entries) == 1,
                    "publisher ZIP contains extra entries or comments")
            entry = entries[0]
            mode = entry.external_attr >> 16
            require(entry.filename == ARTIFACT_FILE
                    and not entry.is_dir()
                    and stat.S_IFMT(mode) != stat.S_IFLNK
                    and not (entry.flag_bits & 1)
                    and entry.compress_type in (
                        zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED,
                    )
                    and 0 < entry.file_size <= MAX_JSON
                    and entry.compress_size > 0
                    and entry.file_size <= entry.compress_size * 50,
                    "untrusted ZIP member type/name/encryption/size")
            raw = source.read(entry)
            require(len(raw) == entry.file_size,
                    "publisher ZIP member decompression size changed")
        packet = json.loads(
            raw.decode("utf-8"), object_pairs_hook=unique_object,
        )
    except (zipfile.BadZipFile, RuntimeError, UnicodeError,
            json.JSONDecodeError, EOFError) as exc:
        raise ValueError("publisher artifact invalid ZIP or unique-key JSON") from exc
    require(type(packet) is dict and set(packet) == KEYS,
            "publisher artifact JSON schema missing or expanded")
    origin.no_credentials(packet)
    return packet


def attest(*, source_run: Any, artifact_inventory: Any,
           archive: bytes, snapshot: Any, observed_now: datetime,
           expected_repository_id: int) -> dict[str, str | int]:
    """Bind immutable GitHub-origin ZIP metadata to CURRENT native banner."""
    require(type(observed_now) is datetime
            and observed_now.tzinfo is not None
            and observed_now.utcoffset() == timedelta(),
            "publisher review observation must be UTC aware")
    require(type(expected_repository_id) is int and expected_repository_id > 0,
            "expected immutable repository ID not trusted")
    require(type(source_run) is dict and type(artifact_inventory) is dict,
            "authenticated run/artifact HTTP documents missing")
    require(type(snapshot) is dict
            and admission.decide(snapshot).get("decision")
                == "exact-native-banner-owner-review-ready-read-only",
            "reviewer lacks current exact green unreviewed App candidate")
    run = source_run
    require(type(run.get("id")) is int and run["id"] > 0
            and run.get("name") == WORKFLOW
            and run.get("path") == WORKFLOW_PATH
            and run.get("event") == "schedule"
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and type(run.get("run_attempt")) is int
            and run["run_attempt"] == 1
            and run.get("head_branch") == "main"
            and run.get("head_sha") == snapshot["mainSha"]
            and type(run.get("repository")) is dict
            and run["repository"].get("full_name") == REPOSITORY
            and type(run.get("head_repository")) is dict
            and run["head_repository"].get("full_name") == REPOSITORY
            and type(run.get("actor")) is dict
            and run["actor"].get("login") == "portyu9"
            and type(run.get("triggering_actor")) is dict
            and run["triggering_actor"].get("login") == "portyu9",
            "publisher source was not one genuine successful unattended main schedule")
    created = at_utc(run.get("created_at"))
    completed = at_utc(run.get("updated_at"))
    require(created <= completed <= observed_now
            and timedelta() <= observed_now - created <= TTL
            and created.date() == completed.date() == observed_now.date(),
            "publisher source run stale, future, cross-day or incomplete")
    items = artifact_inventory.get("artifacts")
    count = artifact_inventory.get("total_count")
    require(type(items) is list and type(count) is int
            and count == len(items) and 0 < count <= MAX_ARTIFACTS
            and all(type(item) is dict for item in items),
            "publisher run artifact inventory incomplete or over limit")
    selected = [a for a in items if a.get("name") == ARTIFACT_NAME]
    require(len(selected) == 1
            and len({a.get("id") for a in items}) == len(items),
            "publisher origin artifact duplicated or absent")
    metadata = selected[0]
    identity = metadata.get("workflow_run")
    artifact_id = metadata.get("id")
    digest = metadata.get("digest")
    require(type(artifact_id) is int and artifact_id > 0
            and type(metadata.get("size_in_bytes")) is int
            and 0 < metadata["size_in_bytes"] <= MAX_ARCHIVE
            and metadata.get("expired") is False
            and type(digest) is str
            and ARCHIVE_SHA.fullmatch(digest) is not None
            and metadata.get("archive_download_url") ==
                f"https://api.github.com/repos/{REPOSITORY}"
                f"/actions/artifacts/{artifact_id}/zip"
            and type(identity) is dict
            and identity.get("id") == run["id"]
            and identity.get("repository_id") == expected_repository_id
            and identity.get("head_repository_id") == expected_repository_id
            and identity.get("head_branch") == "main"
            and identity.get("head_sha") == snapshot["mainSha"],
            "artifact did not originate from the exact authenticated schedule run")
    artifact_time = at_utc(metadata.get("created_at"))
    expiry = at_utc(metadata.get("expires_at"))
    require(created <= artifact_time <= completed
            and timedelta() < expiry - artifact_time <= timedelta(days=2)
            and observed_now < expiry,
            "publisher origin artifact lifetime is invalid or expired")
    require(hashlib.sha256(archive).hexdigest() == digest[7:],
            "downloaded archive SHA256 differs from native GitHub artifact")
    packet = unpack_exact(archive)
    produced = at_utc(packet.get("observedAt"))
    require(packet.get("schemaVersion") == 1
            and packet.get("repository") == REPOSITORY
            and packet.get("producerWorkflow") == WORKFLOW
            and packet.get("producerEvent") == "schedule"
            and type(packet.get("producerRunId")) is int
            and packet["producerRunId"] == run["id"]
            and type(packet.get("producerRunAttempt")) is int
            and packet["producerRunAttempt"] == 1
            and packet.get("utcDay") == observed_now.date().isoformat()
            and created <= produced <= completed
            and produced.date() == observed_now.date()
            and packet.get("prNumber") == snapshot["pr"]["number"]
            and packet.get("baseSha") == snapshot["mainSha"]
            and packet.get("headSha") == snapshot["pr"]["head"]["sha"]
            and packet.get("headRef") == snapshot["pr"]["head"]["ref"]
            and packet.get("appEvidence") == snapshot["nativeApp"],
            "publisher package does not attest exact current accepted candidate")
    native_app = packet["appEvidence"]
    require(type(native_app) is dict and
            native_app.get("expected_repository_id") == expected_repository_id,
            "publisher App installation not bound to exact repository ID")
    verified = contract.verified_native_banner_app_identity(**native_app)
    require(verified["repositoryId"] == expected_repository_id,
            "publisher App identity changed from approved selected installation")
    return {
        "decision": "authenticated-native-banner-schedule-app-origin-data-only",
        "producerRunId": run["id"],
        "producerArtifactId": artifact_id,
        "prNumber": snapshot["pr"]["number"],
        "baseSha": snapshot["mainSha"],
        "headSha": snapshot["pr"]["head"]["sha"],
        "ownerEligibleDay": observed_now.date().isoformat(),
        "appId": verified["appId"],
        "installationId": verified["installationId"],
        "repositoryId": expected_repository_id,
    }


def self_test() -> None:
    import banner_native_live_admission as fixture_source

    snapshot = fixture_source.fixture()
    time = at_utc(snapshot["observedAt"])
    run_id = 77
    start = time - timedelta(minutes=4)
    finish = time - timedelta(minutes=1)
    manifest = build(
        app_evidence=snapshot["nativeApp"], pr=snapshot["pr"],
        base_sha=snapshot["mainSha"], run_id=run_id,
        observed_at=time - timedelta(minutes=2),
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr(ARTIFACT_FILE, json.dumps(
            manifest, sort_keys=True, separators=(",", ":"),
        ))
    archive = buffer.getvalue()
    assert unpack_exact(archive) == manifest
    def stamp(d: datetime) -> str:
        return d.isoformat(timespec="seconds").replace("+00:00", "Z")
    run = {
        "id": run_id, "name": WORKFLOW, "path": WORKFLOW_PATH,
        "event": "schedule", "status": "completed", "conclusion": "success",
        "run_attempt": 1, "head_branch": "main",
        "head_sha": snapshot["mainSha"],
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
        "actor": {"login": "portyu9"},
        "triggering_actor": {"login": "portyu9"},
        "created_at": stamp(start), "updated_at": stamp(finish),
    }
    id_ = 88
    artifact = {
        "id": id_, "name": ARTIFACT_NAME,
        "size_in_bytes": len(archive), "expired": False,
        "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
        "archive_download_url": (
            f"https://api.github.com/repos/{REPOSITORY}"
            f"/actions/artifacts/{id_}/zip"
        ),
        "created_at": stamp(time - timedelta(minutes=2)),
        "expires_at": stamp(time + timedelta(days=1)),
        "workflow_run": {
            "id": run_id, "repository_id": 14, "head_repository_id": 14,
            "head_branch": "main", "head_sha": snapshot["mainSha"],
        },
    }
    collection = {"total_count": 1, "artifacts": [artifact]}
    arguments = {
        "source_run": run, "artifact_inventory": collection,
        "archive": archive, "snapshot": snapshot,
        "observed_now": time, "expected_repository_id": 14,
    }
    good = attest(**arguments)
    require(good["prNumber"] == snapshot["pr"]["number"]
            and good["producerRunId"] == run_id
            and good["decision"] ==
                "authenticated-native-banner-schedule-app-origin-data-only",
            "positive native publisher schedule artifact rejected")

    def reject(label: str, mutate: Any) -> None:
        case = copy.deepcopy(arguments)
        mutate(case)
        try:
            attest(**case)
        except (KeyError, TypeError, ValueError):
            return
        raise AssertionError("forged publisher provenance accepted: " + label)

    tests = [
        ("manual workflow dispatch",
         lambda a: a["source_run"].update(event="workflow_dispatch")),
        ("skipped scheduler",
         lambda a: a["source_run"].update(conclusion="skipped")),
        ("replayed run attempt",
         lambda a: a["source_run"].update(run_attempt=2)),
        ("different workflow source",
         lambda a: a["source_run"].update(path=".github/workflows/other.yml")),
        ("different scheduled SHA",
         lambda a: a["source_run"].update(head_sha="f" * 40)),
        ("untrusted trigger actor",
         lambda a: a["source_run"]["actor"].update(login="attacker")),
        ("UTC day changed",
         lambda a: a.update(observed_now=time + timedelta(days=1))),
        ("stale completed run",
         lambda a: a.update(observed_now=time + timedelta(hours=3))),
        ("duplicate artifact",
         lambda a: a["artifact_inventory"]["artifacts"].append(
             copy.deepcopy(a["artifact_inventory"]["artifacts"][0]))),
        ("truncated artifact inventory",
         lambda a: a["artifact_inventory"].update(total_count=2)),
        ("wrong artifact run",
         lambda a: a["artifact_inventory"]["artifacts"][0]["workflow_run"]
             .update(id=111)),
        ("wrong repository ID",
         lambda a: a["artifact_inventory"]["artifacts"][0]["workflow_run"]
             .update(repository_id=91)),
        ("different archive digest",
         lambda a: a["artifact_inventory"]["artifacts"][0].update(
             digest="sha256:" + "0" * 64)),
        ("wrong archive URL",
         lambda a: a["artifact_inventory"]["artifacts"][0].update(
             archive_download_url="https://attacker.invalid/zip")),
        ("expired artifact",
         lambda a: a["artifact_inventory"]["artifacts"][0]
             .update(expired=True)),
        ("wrong current snapshot head",
         lambda a: a["snapshot"]["pr"]["head"].update(sha="f" * 40)),
        ("wrong live candidate app",
         lambda a: a["snapshot"]["nativeApp"]["installation"]
             .update(app_id=999)),
    ]
    for label, mutate in tests:
        reject(label, mutate)
    def invalid_zip(label: str, raw: bytes) -> None:
        try:
            unpack_exact(raw)
        except (ValueError, TypeError):
            return
        raise AssertionError("malicious ZIP admitted: " + label)
    invalid_zip("not a zip", b"not-a-zip")
    with io.BytesIO() as bad:
        with zipfile.ZipFile(bad, "w") as z:
            z.writestr("../escape.json", json.dumps(manifest))
        invalid_zip("path traversal", bad.getvalue())
    with io.BytesIO() as bad:
        with zipfile.ZipFile(bad, "w") as z:
            z.writestr(ARTIFACT_FILE, json.dumps(manifest))
            z.writestr("evil.json", "{}")
        invalid_zip("extra ZIP entries", bad.getvalue())
    with io.BytesIO() as bad:
        with zipfile.ZipFile(bad, "w") as z:
            z.writestr(ARTIFACT_FILE, '{"id":1,"id":2}')
        invalid_zip("duplicate JSON keys", bad.getvalue())
    print("native banner scheduled App provenance: exact authentic run, "
          "immutable archive SHA256, no-extra-entry ZIP, selected App/current "
          "UTC PR and 21 adversarial negatives PASS; no network/writes")


if __name__ == "__main__":
    self_test()
