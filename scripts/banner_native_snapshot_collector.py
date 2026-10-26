#!/usr/bin/env python3
"""Compose authenticated native banner REST/GraphQL evidence without mutation.

This is an observer, NOT a credential issuer or an authority to review/merge.
The future trusted caller must independently authenticate the fixed App identity,
supply a read-scoped token, and re-prove fresh native refs before ANY write.
Injected clients/thread readers exist only for deterministic adversarial tests.
"""
from __future__ import annotations

import base64
import binascii
import copy
from datetime import datetime, timedelta, timezone
import json
from typing import Any, Callable
import urllib.parse

import banner_native_live_admission as admission
import banner_native_rest_transport as rest
import banner_native_review_threads_transport as graphql
import independent_banner_candidate_contract as contract

REPOSITORY = "portyu9/portyu9"
PREFIX = "/repos/portyu9/portyu9/"
README_LIMIT = 100_000


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def read_object(client: Any, endpoint: str) -> dict[str, Any]:
    value, link = client.get(PREFIX + endpoint)
    require(type(value) is dict and link is None,
            f"banner native object endpoint must have one complete response: {endpoint}")
    return value


def read_ref(client: Any, branch: str) -> dict[str, Any]:
    require(branch == "main" or (
        type(branch) is str
        and branch.startswith("automation/banner-rotation/")
        and len(branch) <= 110
        and all(char in "abcdefghijklmnopqrstuvwxyz0123456789/-" for char in branch)
    ), "banner ref request escaped exact reviewed lane")
    value = read_object(client, "git/ref/heads/" + branch)
    require(value.get("ref") == "refs/heads/" + branch
            and type(value.get("object")) is dict
            and value["object"].get("type") == "commit"
            and type(value["object"].get("sha")) is str
            and contract.HEX40.fullmatch(value["object"]["sha"]) is not None,
            "banner native ref response is malformed")
    return value


def read_readme(client: Any, commit_sha: str) -> str:
    require(type(commit_sha) is str
            and contract.HEX40.fullmatch(commit_sha) is not None,
            "banner README request is not bound to an exact commit")
    value = read_object(client, "contents/README.md?ref=" + commit_sha)
    require(value.get("name") == "README.md" and value.get("path") == "README.md"
            and value.get("type") == "file" and value.get("encoding") == "base64"
            and type(value.get("content")) is str
            and type(value.get("size")) is int
            and 0 < value["size"] <= README_LIMIT
            and type(value.get("sha")) is str
            and contract.HEX40.fullmatch(value["sha"]) is not None,
            "banner README native Contents envelope is malformed")
    source = value["content"].replace("\n", "")
    try:
        decoded = base64.b64decode(source, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("banner README Contents base64 is malformed") from exc
    require(len(decoded) == value["size"]
            and contract.blob_sha(decoded.decode("utf-8")) == value["sha"],
            "banner README Contents native byte length / Git blob diverged")
    return decoded.decode("utf-8")


def observed_utc(value: datetime) -> str:
    require(type(value) is datetime and value.tzinfo is not None
            and value.utcoffset() == timedelta()
            and value.microsecond == 0,
            "banner collector clock requires an exact second-resolution UTC datetime")
    return value.isoformat(timespec="seconds").replace("+00:00", "Z")


def collect(
    *, native_app: dict[str, Any], observed_now: datetime,
    client: Any, token: str | None = None,
    threads_reader: Callable[[str, int], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Read all native evidence before composing a non-authoritative snapshot.

    Native App identity input MUST already be authenticated by a future trusted
    caller. A synthetic native_app dictionary is not an App credential or
    ownership proof; this module cannot grant a review, merge, or write.
    """
    now = observed_utc(observed_now)
    require(type(native_app) is dict and set(native_app) == {
        "installation", "bot_user", "expected_app_id",
        "expected_installation_id", "expected_repository_id",
    }, "banner native App observation has incomplete trust inputs")
    contract.verified_native_banner_app_identity(**native_app)
    require(client is not None,
            "native REST collector requires independently authenticated client")
    if threads_reader is None:
        require(token is not None, "native GraphQL collector requires caller-scoped token")
        def threads_reader(repository: str, number: int) -> dict[str, Any]:
            return graphql.fetch_connection(repository, number, token=token)

    main_ref = read_ref(client, "main")
    main_sha = main_ref["object"]["sha"]
    open_prs, open_witness = rest.inventory(
        client, PREFIX + "pulls?state=open&base=main", limit=99,
    )
    counts = {"openPrs": open_witness}
    selected = contract.select_read_only_banner_candidate(
        open_prs, current_main_sha=main_sha,
        utc_day=observed_now.date(), native_app=native_app,
    )
    snapshot: dict[str, Any] = {
        "schemaVersion": 1, "repository": REPOSITORY,
        "observedAt": now, "mainSha": main_sha,
        "nativeApp": copy.deepcopy(native_app),
        "openPrs": open_prs, "completeness": counts,
    }
    state = selected["decision"]
    if state != "current-banner-candidate-requires-proof":
        require(state in {"no-open-banner-candidate",
                          "stale-banner-candidate-requires-proof"},
                "unrecognized banner selection state")
        require(read_ref(client, "main") == main_ref,
                "banner main advanced during read-only candidate observation")
        admission.decide(snapshot)
        return snapshot

    number = selected["prNumber"]
    head_sha = selected["headSha"]
    head_ref = selected["headRef"]
    pr = read_object(client, f"pulls/{number}")
    commit = read_object(client, f"commits/{head_sha}")
    files, counts["files"] = rest.inventory(
        client, PREFIX + f"pulls/{number}/files",
        uniqueness="filename", limit=1,
    )
    checks, counts["checkRuns"] = rest.inventory(
        client, PREFIX + f"commits/{head_sha}/check-runs",
        field="check_runs", limit=100,
    )
    # This is an exhaustive, authenticated list of all runs at the exact head.
    # Filter the four approved workflows *after* total_count/Link proof; any
    # duplicate native run from a reattempt will force a fail-closed decision.
    all_runs, _native_run_witness = rest.inventory(
        client, PREFIX + f"actions/runs?head_sha={head_sha}",
        field="workflow_runs", limit=100,
    )
    runs = [row for row in all_runs
            if row.get("name") in contract.EXPECTED_PROTECTED_WORKFLOWS]
    require(len(runs) == len(contract.EXPECTED_PROTECTED_WORKFLOWS)
            and len({row.get("name") for row in runs}) == len(runs),
            "banner protected workflow-run evidence is incomplete or duplicated")
    counts["workflowRuns"] = {
        "totalCount": len(runs), "hasNextPage": False,
    }
    reviews, counts["reviews"] = rest.inventory(
        client, PREFIX + f"pulls/{number}/reviews", limit=100,
    )
    threads = threads_reader(REPOSITORY, number)
    contract.verified_review_thread_connection(threads)
    accepted_readme = read_readme(client, main_sha)
    proposed_readme = read_readme(client, head_sha)
    candidate_ref = read_ref(client, head_ref)
    require(read_ref(client, "main") == main_ref
            and read_ref(client, head_ref) == candidate_ref,
            "banner main/candidate native refs changed during collector reads")
    snapshot.update({
        "pr": pr, "commit": commit, "files": files,
        "acceptedReadme": accepted_readme,
        "proposedReadme": proposed_readme,
        "checkRuns": checks, "workflowRuns": runs,
        "reviews": reviews, "reviewThreads": threads,
        "mainRef": main_ref, "candidateRef": candidate_ref,
    })
    admission.decide(snapshot)
    return snapshot


class _FixtureClient:
    """Test-only native REST endpoints. No network or sensitive authorization."""

    def __init__(self, sample: dict[str, Any]) -> None:
        self.sample = copy.deepcopy(sample)
        self.calls: list[str] = []
        self.main_advanced = False
        self.bad_contents = False
        self.duplicate_run = False

    def get(self, path: str) -> tuple[Any, None]:
        self.calls.append(path)
        parsed = urllib.parse.urlsplit(path)
        require(parsed.path.startswith(PREFIX)
                and not parsed.scheme and not parsed.netloc,
                "collector fixture observed an off-repository REST read")
        suffix = parsed.path[len(PREFIX):]
        params = urllib.parse.parse_qs(parsed.query)
        is_page = params.get("page") == ["1"]
        if suffix == "git/ref/heads/main":
            answer = copy.deepcopy(self.sample["mainRef"])
            if self.main_advanced and self.calls.count(path) > 1:
                answer["object"]["sha"] = "e" * 40
            return answer, None
        if suffix == "pulls":
            require(is_page and params.get("state") == ["open"]
                    and params.get("base") == ["main"],
                    "open PR inventory filter drifted")
            return copy.deepcopy(self.sample["openPrs"]), None
        if self.sample.get("pr") is None:
            raise ValueError("collector read candidate detail in no-candidate fixture")
        number = self.sample["pr"]["number"]
        sha = self.sample["pr"]["head"]["sha"]
        ref = self.sample["pr"]["head"]["ref"]
        if suffix == f"pulls/{number}":
            return copy.deepcopy(self.sample["pr"]), None
        if suffix == f"commits/{sha}":
            return copy.deepcopy(self.sample["commit"]), None
        if suffix == f"pulls/{number}/files":
            require(is_page, "banner file inventory lost pagination")
            return copy.deepcopy(self.sample["files"]), None
        if suffix == f"commits/{sha}/check-runs":
            require(is_page, "banner check-run inventory lost pagination")
            checks = self.sample["checkRuns"]
            return {"total_count": len(checks),
                    "check_runs": copy.deepcopy(checks)}, None
        if suffix == "actions/runs":
            require(is_page and params.get("head_sha") == [sha],
                    "banner workflow run inventory lost exact head")
            runs = copy.deepcopy(self.sample["workflowRuns"])
            if self.duplicate_run:
                replica = copy.deepcopy(runs[0])
                replica["id"] += 5_000
                runs.append(replica)
            runs.append({"id": 90001, "name": "Unrelated"} )
            return {"total_count": len(runs), "workflow_runs": runs}, None
        if suffix == f"pulls/{number}/reviews":
            require(is_page, "banner review inventory lost pagination")
            return copy.deepcopy(self.sample["reviews"]), None
        if suffix == "contents/README.md":
            ref_sha = params.get("ref")
            require(ref_sha in ([self.sample["mainSha"]], [sha]),
                    "banner README request did not pin a native commit")
            source = (self.sample["acceptedReadme"]
                      if ref_sha == [self.sample["mainSha"]]
                      else self.sample["proposedReadme"])
            encoded = base64.b64encode(source.encode("utf-8")).decode("ascii")
            return {"name": "README.md", "path": "README.md", "type": "file",
                    "encoding": "base64", "size": len(source.encode("utf-8")),
                    "sha": ("f" * 40 if self.bad_contents
                            else contract.blob_sha(source)),
                    "content": encoded}, None
        if suffix == "git/ref/heads/" + ref:
            return copy.deepcopy(self.sample["candidateRef"]), None
        raise ValueError(f"fixture received unexpected native endpoint: {suffix}")


def self_test() -> None:
    sample = admission.fixture()
    clock = datetime.fromisoformat(
        sample["observedAt"].replace("Z", "+00:00"),
    )
    client = _FixtureClient(sample)
    def fixed_threads(_repository: str, _number: int) -> dict[str, Any]:
        return copy.deepcopy(sample["reviewThreads"])
    observed = collect(
        native_app=sample["nativeApp"], observed_now=clock,
        client=client, threads_reader=fixed_threads,
    )
    require(admission.decide(observed)["decision"]
            == "exact-native-banner-owner-review-ready-read-only"
            and len([path for path in client.calls if "actions/runs?" in path]) == 1,
            "authentic-complete synthetic banner observation rejected")

    no_candidate = copy.deepcopy(sample)
    no_candidate["openPrs"] = []
    del no_candidate["pr"]
    idle = collect(
        native_app=no_candidate["nativeApp"], observed_now=clock,
        client=_FixtureClient(no_candidate), threads_reader=fixed_threads,
    )
    require(set(idle) == admission.BASIC
            and admission.decide(idle)["decision"] == "no-candidate-read-only",
            "complete no-candidate native inventory was not an idle no-op")

    def expect_failure(label: str, changed: _FixtureClient,
                       app: dict[str, Any] | None = None,
                       thread_fn: Callable[[str, int], dict[str, Any]] = fixed_threads) -> None:
        try:
            collect(native_app=sample["nativeApp"] if app is None else app,
                    observed_now=clock, client=changed, threads_reader=thread_fn)
        except (ValueError, TypeError, KeyError):
            return
        raise AssertionError(f"collector accepted unsafe native input: {label}")

    advanced = _FixtureClient(sample)
    advanced.main_advanced = True
    expect_failure("main advanced during observation", advanced)
    corrupt = _FixtureClient(sample)
    corrupt.bad_contents = True
    expect_failure("README Git blob mismatch", corrupt)
    duplicate = _FixtureClient(sample)
    duplicate.duplicate_run = True
    expect_failure("duplicate reviewed workflow rerun", duplicate)
    missing = _FixtureClient(sample)
    missing.sample["checkRuns"].pop()
    expect_failure("missing required native check", missing)
    unresolved = copy.deepcopy(sample["reviewThreads"])
    unresolved["nodes"].append({"id": "THREAD", "isResolved": False})
    expect_failure(
        "unresolved native GraphQL thread", _FixtureClient(sample),
        thread_fn=lambda _repo, _number: unresolved,
    )
    invalid_app = copy.deepcopy(sample["nativeApp"])
    invalid_app["expected_installation_id"] += 1
    expect_failure("unverified App identity", _FixtureClient(sample), invalid_app)
    oversized = _FixtureClient(sample)
    oversized.sample["openPrs"] = [copy.deepcopy(sample["openPrs"][0])
                                   for _ in range(100)]
    expect_failure("unbounded PR inventory", oversized)
    require(REPOSITORY == contract.REPOSITORY
            and PREFIX == rest.PREFIX and README_LIMIT == 100_000,
            "native snapshot collector repository/source constants changed")
    print("banner read-only collector: complete REST/GraphQL snapshot, ref lease, App identity and adversarial no-action PASS")
