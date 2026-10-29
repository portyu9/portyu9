#!/usr/bin/env python3
"""Pure protected native banner merge-result contract: NO merge/write capability.

Separate owner identity and scoped App terminal merger remain mandatory. This
module consumes independently authenticated, exact-head native evidence from
the trusted caller. It cannot authenticate bearer tokens or request an HTTP
mutation itself. An HTTP-200 merge acknowledgement is not accepted until the
actual accepted-main Git ref, merged PR and ordinary two-parent merge commit
all bind the same exact reviewed banner head and unchanged prior main.
"""
from __future__ import annotations

import copy
from datetime import timedelta
import re
from typing import Any

import banner_native_live_admission as admission
import banner_native_owner_review_transaction_contract as owner

REPOSITORY = "portyu9/portyu9"
SHA = re.compile(r"^[0-9a-f]{40}$")
HTTP_OK = re.compile(r"^HTTP/(?:1\.[01]|2(?:\.0)?) 200(?: [^\r\n]*)?$")
TTL = timedelta(minutes=10)


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def exact_merge_request(*, initial: Any, reviewed: Any,
                        owner_status: str, owner_response: Any) -> dict[str, Any]:
    """Derive ONLY a normal exact-head merge request from actual owner proof."""
    attested = owner.verify_submission(
        initial=initial, status_line=owner_status,
        response=owner_response, after=reviewed,
    )
    now = admission.decide(reviewed)
    require(now.get("decision")
            == "exact-owner-reviewed-banner-terminal-ready-read-only"
            and now.get("prNumber") == attested["prNumber"]
            and now.get("baseSha") == attested["baseSha"]
            and now.get("headSha") == attested["headSha"],
            "banner merge subject is not exact owner-reviewed terminal-ready")
    return {
        "method": "PUT",
        "endpoint": (f"repos/{REPOSITORY}/pulls/"
                     f"{attested['prNumber']}/merge"),
        "request": {"sha": attested["headSha"], "merge_method": "merge"},
        "prNumber": attested["prNumber"],
        "baseSha": attested["baseSha"],
        "headSha": attested["headSha"],
        "ownerReviewId": attested["ownerReviewId"],
    }


def verify_merge(*, initial: Any, reviewed: Any,
                 owner_status: str, owner_response: Any,
                 merge_status: Any, merge_response: Any,
                 merged_pr: Any, merge_commit: Any,
                 final_main_ref: Any, observed_at: Any) -> dict[str, Any]:
    """Prove a native protected merge actually reached main, not only an API 200."""
    request = exact_merge_request(
        initial=initial, reviewed=reviewed, owner_status=owner_status,
        owner_response=owner_response,
    )
    require(type(merge_status) is str
            and HTTP_OK.fullmatch(merge_status.rstrip("\r")) is not None,
            "banner native merge response must be HTTP 200")
    require(type(merge_response) is dict
            and merge_response.get("merged") is True
            and type(merge_response.get("sha")) is str
            and SHA.fullmatch(merge_response["sha"]) is not None
            and merge_response["sha"] not in {
                request["baseSha"], request["headSha"]}
            and type(merge_response.get("message")) is str
            and bool(merge_response["message"]),
            "banner merge response is missing a distinct accepted commit")
    merge_sha = merge_response["sha"]
    require(type(merged_pr) is dict
            and type(merged_pr.get("number")) is int
            and merged_pr["number"] == request["prNumber"]
            and merged_pr.get("state") == "closed"
            and merged_pr.get("merged") is True
            and merged_pr.get("merge_commit_sha") == merge_sha
            and type(merged_pr.get("head")) is dict
            and merged_pr["head"].get("sha") == request["headSha"],
            "banner GitHub PR was not actually merged on its exact head")
    require(type(merge_commit) is dict
            and merge_commit.get("sha") == merge_sha
            and type(merge_commit.get("parents")) is list
            and len(merge_commit["parents"]) == 2
            and all(type(row) is dict
                    and type(row.get("sha")) is str
                    and SHA.fullmatch(row["sha"]) is not None
                    for row in merge_commit["parents"])
            and [row["sha"] for row in merge_commit["parents"]]
                == [request["baseSha"], request["headSha"]],
            "banner merge commit does not preserve the protected base/head lineage")
    require(type(final_main_ref) is dict
            and final_main_ref.get("ref") == "refs/heads/main"
            and type(final_main_ref.get("object")) is dict
            and final_main_ref["object"].get("type") == "commit"
            and final_main_ref["object"].get("sha") == merge_sha,
            "banner protected main did not advance to verified merge SHA")
    require(type(observed_at) is str and observed_at.endswith("Z"),
            "banner post-merge evidence lacks canonical UTC timestamp")
    started = admission.exact_utc(reviewed["observedAt"])
    finished = admission.exact_utc(observed_at)
    require(timedelta() <= finished - started <= TTL
            and started.date() == finished.date(),
            "banner merge proof crossed UTC day or expired")
    return {
        "decision": "native-banner-protected-merge-observed-no-write",
        "prNumber": request["prNumber"], "baseSha": request["baseSha"],
        "headSha": request["headSha"], "mergeSha": merge_sha,
        "ownerReviewId": request["ownerReviewId"],
    }


def self_test() -> None:
    initial = admission.fixture()
    start = admission.exact_utc(initial["observedAt"])
    reviewed = copy.deepcopy(initial)
    reviewed["observedAt"] = (start + timedelta(minutes=3)).isoformat(
        timespec="seconds").replace("+00:00", "Z")
    prepared = owner.exact_request(initial)
    approval = {
        "id": 904, "user": {"login": "portyu9"}, "state": "APPROVED",
        "commit_id": prepared["headSha"],
        "body": prepared["request"]["body"],
        "submitted_at": (start + timedelta(minutes=1)).isoformat(
            timespec="seconds").replace("+00:00", "Z"),
    }
    reviewed["reviews"].append(copy.deepcopy(approval))
    reviewed["completeness"]["reviews"]["totalCount"] = 1
    command = exact_merge_request(
        initial=initial, reviewed=reviewed,
        owner_status="HTTP/2.0 200 OK", owner_response=approval,
    )
    require(command["request"] == {
        "sha": prepared["headSha"], "merge_method": "merge",
    } and command["method"] == "PUT" and command["endpoint"]
            == f"repos/{REPOSITORY}/pulls/{command['prNumber']}/merge",
            "banner merge command escaped ordinary exact-head protected endpoint")
    sha = "c" * 40
    response = {"merged": True, "sha": sha, "message": "Pull Request successfully merged"}
    pr = {
        "number": command["prNumber"], "state": "closed", "merged": True,
        "merge_commit_sha": sha, "head": {"sha": command["headSha"]},
    }
    commit = {"sha": sha, "parents": [
        {"sha": command["baseSha"]}, {"sha": command["headSha"]},
    ]}
    main = {"ref": "refs/heads/main", "object": {"type": "commit", "sha": sha}}
    when = (start + timedelta(minutes=4)).isoformat(
        timespec="seconds").replace("+00:00", "Z")
    params = {
        "initial": initial, "reviewed": reviewed,
        "owner_status": "HTTP/2.0 200 OK", "owner_response": approval,
        "merge_status": "HTTP/2.0 200 OK", "merge_response": response,
        "merged_pr": pr, "merge_commit": commit,
        "final_main_ref": main, "observed_at": when,
    }
    result = verify_merge(**params)
    require(result["decision"] == "native-banner-protected-merge-observed-no-write"
            and result["mergeSha"] == sha, "native merge proof was not exact")

    def rejected(label: str, change: Any) -> None:
        case = copy.deepcopy(params)
        change(case)
        try:
            verify_merge(**case)
        except (ValueError, KeyError, TypeError):
            return
        raise AssertionError("unsafe native banner merge accepted: " + label)

    for label, change in [
        ("HTTP 201", lambda x: x.update(merge_status="HTTP/2.0 201 Created")),
        ("HTTP 204", lambda x: x.update(merge_status="HTTP/2.0 204 No Content")),
        ("HTTP response injected", lambda x: x.update(
            merge_status="HTTP/2.0 200 OK\nHTTP/2.0 403 Forbidden")),
        ("false merged status", lambda x: x["merge_response"].update(merged=False)),
        ("boolean merge SHA", lambda x: x["merge_response"].update(sha=True)),
        ("merge response repeats head", lambda x: x["merge_response"].update(
            sha=command["headSha"])),
        ("PR is still open", lambda x: x["merged_pr"].update(state="open")),
        ("PR merged false", lambda x: x["merged_pr"].update(merged=False)),
        ("PR different number", lambda x: x["merged_pr"].update(number=4)),
        ("PR different head", lambda x: x["merged_pr"]["head"].update(sha="d" * 40)),
        ("wrong merge parent", lambda x: x["merge_commit"]["parents"][0].update(
            sha="d" * 40)),
        ("extra merge parent", lambda x: x["merge_commit"]["parents"].append(
            {"sha": "d" * 40})),
        ("wrong merge SHA", lambda x: x["merge_commit"].update(sha="d" * 40)),
        ("main ref unchanged", lambda x: x["final_main_ref"]["object"].update(
            sha=command["baseSha"])),
        ("main ref wrong branch", lambda x: x["final_main_ref"].update(
            ref="refs/heads/generated")),
        ("merge proof stale", lambda x: x.update(
            observed_at=(start + timedelta(minutes=15)).isoformat(
                timespec="seconds").replace("+00:00", "Z"))),
        ("main owner review revoked", lambda x: x["reviewed"]["reviews"][0].update(
            state="DISMISSED")),
        ("reviewed source modified", lambda x: x["reviewed"].update(
            proposedReadme="forged")),
        ("review response forged", lambda x: x["owner_response"].update(
            user={"login": "attacker"})),
    ]:
        rejected(label, change)
    print("native banner exact reviewed merge + protected main ancestry, HTTP "
          "and veto negative controls PASS; zero merge/network capability")


if __name__ == "__main__":
    self_test()
