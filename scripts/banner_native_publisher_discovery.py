#!/usr/bin/env python3
"""Read-only discovery of the unique same-day native App banner publisher.

No supplied run ID or ZIP can authorize an owner review. Discover an exact
completed first-attempt scheduled run using GitHub's authenticated native run
and COMPLETE artifact inventories, pin current main and preserve the native
archive digest. The independent owner writer must still re-read both endpoints,
verify the downloaded ZIP SHA256, the exact candidate and genuine CI wake
before it may POST a review. This module never issues a mutation.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Callable

import banner_native_observer_cli as observer
import banner_native_publisher_run_artifact as producer
from banner_native_rest_transport import ReadOnlyGitHub

REPOSITORY = "/repos/portyu9/portyu9"
RUNS = REPOSITORY + "/actions/workflows/approved-banner-rotation.yml/runs"
MAIN = REPOSITORY + "/git/ref/heads/main"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MAX_RUNS = 32
MAX_ARTIFACTS = 99
TTL = timedelta(hours=6)


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def utc(value: Any) -> datetime:
    require(type(value) is str and value.endswith("Z"),
            "native publisher timestamp is not canonical UTC")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid native publisher timestamp") from exc
    require(result.utcoffset() == timedelta(), "publisher clock offset drifted")
    return result


def select(*, listing: Any, artifacts: dict[int, Any], main_sha: str,
           observed_at: datetime, repository_id: int) -> dict[str, Any]:
    """Reject truncation, forged actors, replay, ambiguity and stale main."""
    require(type(observed_at) is datetime
            and observed_at.tzinfo is not None
            and observed_at.utcoffset() == timedelta(),
            "discovery clock must be UTC aware")
    require(type(main_sha) is str and SHA.fullmatch(main_sha) is not None
            and type(repository_id) is int and repository_id > 0,
            "discovery requires immutable current main and repository ID")
    require(type(listing) is dict
            and type(listing.get("total_count")) is int
            and type(listing.get("workflow_runs")) is list,
            "scheduled run collection is not a native complete inventory")
    runs = listing["workflow_runs"]
    require(listing["total_count"] == len(runs)
            and len(runs) <= MAX_RUNS
            and len({run.get("id") for run in runs if type(run) is dict}) == len(runs)
            and all(type(run) is dict for run in runs),
            "scheduled run inventory truncated, duplicated or excessive")
    require(type(artifacts) is dict
            and set(artifacts) == {run["id"] for run in runs}
            and all(type(run["id"]) is int and run["id"] > 0 for run in runs),
            "native artifact inventory does not cover every scheduled run")
    now_day = observed_at.date().isoformat()
    candidates: list[dict[str, Any]] = []
    for run in runs:
        created = utc(run.get("created_at"))
        require(created.date().isoformat() == now_day
                and created <= observed_at
                and observed_at - created <= TTL
                and run.get("name") == producer.WORKFLOW
                and run.get("path") == producer.WORKFLOW_PATH
                and run.get("event") == "schedule"
                and run.get("head_branch") == "main"
                and type(run.get("repository")) is dict
                and run["repository"].get("full_name") == "portyu9/portyu9"
                and run["repository"].get("id") == repository_id,
                "untrusted scheduled publisher run entered current-day inventory")
        inventory = artifacts[run["id"]]
        require(type(inventory) is dict
                and type(inventory.get("total_count")) is int
                and type(inventory.get("artifacts")) is list,
                "native run artifacts missing or malformed")
        entries = inventory["artifacts"]
        require(inventory["total_count"] == len(entries)
                and len(entries) <= MAX_ARTIFACTS
                and all(type(x) is dict and type(x.get("id")) is int
                        and x["id"] > 0 for x in entries)
                and len({x["id"] for x in entries}) == len(entries),
                "native artifact list incomplete or ambiguous")
        matching = [x for x in entries if x.get("name") == producer.ARTIFACT_NAME]
        require(len(matching) <= 1, "duplicated native App-origin artifacts")
        if not matching:
            continue
        item = matching[0]
        changed = utc(run.get("updated_at"))
        made = utc(item.get("created_at"))
        expires = utc(item.get("expires_at"))
        identity = item.get("workflow_run")
        digest = item.get("digest")
        require(run.get("status") == "completed"
                and run.get("conclusion") == "success"
                and type(run.get("run_attempt")) is int
                and run["run_attempt"] == 1
                and run.get("head_sha") == main_sha
                and type(run.get("head_repository")) is dict
                and run["head_repository"].get("full_name") == "portyu9/portyu9"
                and type(run.get("actor")) is dict
                and run["actor"].get("login") == "portyu9"
                and type(run.get("triggering_actor")) is dict
                and run["triggering_actor"].get("login") == "portyu9"
                and created <= made <= changed <= observed_at
                and made < expires <= made + timedelta(days=2)
                and observed_at < expires
                and type(identity) is dict
                and identity.get("id") == run["id"]
                and identity.get("head_sha") == main_sha
                and identity.get("head_branch") == "main"
                and identity.get("repository_id") == repository_id
                and identity.get("head_repository_id") == repository_id
                and item.get("expired") is False
                and type(item.get("size_in_bytes")) is int
                and 0 < item["size_in_bytes"] <= producer.MAX_ARCHIVE
                and type(digest) is str and DIGEST.fullmatch(digest) is not None
                and item.get("archive_download_url") ==
                    f"https://api.github.com/repos/portyu9/portyu9/actions/artifacts/{item['id']}/zip",
                "publisher artifact was not a genuine current-main first-attempt schedule")
        candidates.append({
            "producerRunId": run["id"],
            "artifactId": item["id"],
            "sha256": digest[7:],
            "mainSha": main_sha,
            "utcDay": now_day,
        })
    require(len(candidates) == 1,
            "zero or multiple genuine current-day App publisher artifacts")
    return candidates[0]


def discover(*, token: str, repository_id: int,
             observed_at: datetime) -> dict[str, Any]:
    """Use HTTPS GET only, complete one-day collection and main double-read."""
    reader = ReadOnlyGitHub(token)
    main, link = reader.get(MAIN)
    require(link is None and main.get("ref") == "refs/heads/main"
            and type(main.get("object")) is dict
            and main["object"].get("type") == "commit",
            "current main could not be authenticated")
    sha = main["object"].get("sha")
    day = observed_at.date().isoformat()
    query = f"{RUNS}?created={day}&event=schedule&per_page=100"
    listing, link = reader.get(query)
    require(link is None, "scheduled run list has an unreviewed next page")
    require(type(listing) is dict
            and type(listing.get("workflow_runs")) is list
            and len(listing["workflow_runs"]) <= MAX_RUNS,
            "native same-day run inventory is excessive")
    inventories: dict[int, Any] = {}
    for run in listing["workflow_runs"]:
        require(type(run) is dict
                and type(run.get("id")) is int and run["id"] > 0,
                "publisher run ID is not a native positive integer")
        path = f"{REPOSITORY}/actions/runs/{run['id']}/artifacts"
        inventory, link = reader.get(path)
        require(link is None, "publisher artifact list has unreviewed pages")
        require(run["id"] not in inventories, "duplicate source run in inventory")
        inventories[run["id"]] = inventory
    proof = select(
        listing=listing, artifacts=inventories, main_sha=sha,
        observed_at=observed_at, repository_id=repository_id,
    )
    again, link = reader.get(MAIN)
    require(link is None and again == main,
            "current main changed during read-only producer discovery")
    return proof


def extract(selection: Any, archive: bytes, now: datetime) -> dict[str, Any]:
    """Expose only credential-free App identity; owner must re-attest archive."""
    require(type(selection) is dict
            and set(selection) ==
                {"producerRunId", "artifactId", "sha256", "mainSha", "utcDay"}
            and type(selection["producerRunId"]) is int
            and selection["producerRunId"] > 0
            and type(selection["artifactId"]) is int
            and selection["artifactId"] > 0
            and SHA.fullmatch(selection["mainSha"]) is not None
            and re.fullmatch(r"[0-9a-f]{64}", selection["sha256"]) is not None
            and selection["utcDay"] == now.date().isoformat()
            and hashlib.sha256(archive).hexdigest() == selection["sha256"],
            "downloaded producer ZIP differs from selected native digest")
    packet = producer.unpack_exact(archive)
    require(packet["producerRunId"] == selection["producerRunId"]
            and packet["baseSha"] == selection["mainSha"]
            and packet["utcDay"] == selection["utcDay"],
            "producer ZIP packet does not match selected authenticated source")
    return packet["appEvidence"]


def self_test() -> None:
    moment = datetime(2026, 10, 29, 12, 5, tzinfo=timezone.utc)
    main = "a" * 40
    rid = 12345
    run = {
        "id": 812, "name": producer.WORKFLOW, "path": producer.WORKFLOW_PATH,
        "event": "schedule", "run_attempt": 1, "head_branch": "main",
        "head_sha": main, "status": "completed", "conclusion": "success",
        "created_at": "2026-10-29T12:00:00Z",
        "updated_at": "2026-10-29T12:03:00Z",
        "repository": {"id": rid, "full_name": "portyu9/portyu9"},
        "head_repository": {"full_name": "portyu9/portyu9"},
        "actor": {"login": "portyu9"},
        "triggering_actor": {"login": "portyu9"},
    }
    item = {
        "id": 702, "name": producer.ARTIFACT_NAME,
        "size_in_bytes": 200, "digest": "sha256:" + "b" * 64,
        "expired": False, "created_at": "2026-10-29T12:02:00Z",
        "expires_at": "2026-10-30T12:02:00Z",
        "archive_download_url":
            "https://api.github.com/repos/portyu9/portyu9/actions/artifacts/702/zip",
        "workflow_run": {
            "id": 812, "repository_id": rid, "head_repository_id": rid,
            "head_branch": "main", "head_sha": main,
        },
    }
    good = {"listing": {"total_count": 1, "workflow_runs": [run]},
            "artifacts": {812: {"total_count": 1, "artifacts": [item]}},
            "main_sha": main, "observed_at": moment, "repository_id": rid}
    proof = select(**good)
    require(proof == {
        "producerRunId": 812, "artifactId": 702,
        "sha256": "b" * 64, "mainSha": main, "utcDay": "2026-10-29",
    }, "native producer discovery lost immutable source binding")
    def reject(label: str, mutation: Callable[[dict[str, Any]], None]) -> None:
        bad = copy.deepcopy(good)
        mutation(bad)
        try:
            select(**bad)
        except (ValueError, TypeError, KeyError):
            return
        raise AssertionError("native scheduled discovery accepted " + label)
    reject("missing source", lambda x: x["artifacts"][812].update(
        artifacts=[], total_count=0))
    reject("truncated run list", lambda x: x["listing"].update(total_count=2))
    reject("second source", lambda x: (
        x["listing"].update(total_count=2),
        x["listing"]["workflow_runs"].append({**run, "id": 813}),
        x["artifacts"].update({813: {"total_count": 1, "artifacts": [
            {**item, "id": 703,
             "archive_download_url":
               "https://api.github.com/repos/portyu9/portyu9/actions/artifacts/703/zip",
             "workflow_run": {**item["workflow_run"], "id": 813}}]}})))
    reject("replayed attempt", lambda x:
           x["listing"]["workflow_runs"][0].update(run_attempt=2))
    reject("manual event", lambda x:
           x["listing"]["workflow_runs"][0].update(event="workflow_dispatch"))
    reject("foreign actor", lambda x:
           x["listing"]["workflow_runs"][0]["actor"].update(login="attacker"))
    reject("stale main", lambda x:
           x["listing"]["workflow_runs"][0].update(head_sha="f" * 40))
    reject("bad source repository", lambda x:
           x["listing"]["workflow_runs"][0]["repository"].update(id=55))
    reject("failed publisher", lambda x:
           x["listing"]["workflow_runs"][0].update(conclusion="failure"))
    reject("wrong publisher branch", lambda x:
           x["listing"]["workflow_runs"][0].update(head_branch="off-main"))
    reject("ambiguous artifact", lambda x: (
        x["artifacts"][812].update(total_count=2),
        x["artifacts"][812]["artifacts"].append({**item, "id": 703})))
    reject("artifact other run", lambda x:
           x["artifacts"][812]["artifacts"][0]["workflow_run"].update(id=99))
    reject("unbound ZIP digest", lambda x:
           x["artifacts"][812]["artifacts"][0].update(digest="sha256:"+"z"*64))
    reject("expired source", lambda x:
           x["artifacts"][812]["artifacts"][0].update(expired=True))
    reject("moving clock", lambda x:
           x.update(observed_at=moment + timedelta(days=1)))
    reject("boolean repo", lambda x: x.update(repository_id=True))
    try:
        extract(proof, b"forged ZIP", moment)
    except (ValueError, TypeError, KeyError):
        pass
    else:
        raise AssertionError("untrusted ZIP passed native source extraction")
    print("native banner scheduled discovery: unique first-attempt run, "
          "complete immutable artifact and 16 adversarial veto probes PASS")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--self-test", action="store_true")
    choice.add_argument("--selection-out", type=Path)
    choice.add_argument("--app-evidence-out", type=Path)
    parser.add_argument("--repository-id", type=int)
    parser.add_argument("--selection", type=Path)
    parser.add_argument("--archive", type=Path)
    args = parser.parse_args()
    if args.self_test:
        require(all(getattr(args, x) is None for x in (
            "selection_out", "app_evidence_out", "repository_id",
            "selection", "archive")), "self-test cannot accept live paths")
        self_test()
        return 0
    now = datetime.now(timezone.utc).replace(microsecond=0)
    require(os.environ.get("GITHUB_REPOSITORY") == "portyu9/portyu9"
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_run",
            "publisher discovery only allowed on trusted-main native wake")
    if args.selection_out is not None:
        require(args.repository_id is not None
                and args.selection is None and args.archive is None
                and args.app_evidence_out is None,
                "discovery requires only exact repository ID and output path")
        token = os.environ.get("GH_TOKEN")
        require(type(token) is str and len(token) >= 8,
                "read-only trusted-main GitHub credential missing")
        observer.write_exclusive(
            args.selection_out, discover(
                token=token, repository_id=args.repository_id, observed_at=now))
        return 0
    require(args.app_evidence_out is not None
            and args.repository_id is None
            and args.selection is not None and args.archive is not None,
            "archive extraction requires exact selected run and native ZIP")
    from banner_native_owner_review_writer import read_bounded_source_zip
    selected = observer.read_bounded(args.selection)
    archive = read_bounded_source_zip(args.archive)
    observer.write_exclusive(args.app_evidence_out, extract(selected, archive, now))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
