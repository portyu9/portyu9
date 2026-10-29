#!/usr/bin/env python3
"""Fail-closed native owner-review request/response contract for approved banners.

This module is intentionally PURE. It does not read secrets, issue a review,
make HTTP requests, create checks or merge branches. A future independently
authorized owner-identity writer must obtain authenticated native observations,
send the exact returned request, verify the live HTTP response here, then
independently re-collect the complete native GitHub evidence before any
separate scoped-App terminal merge. A green CI check is never an approval.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta
import re
from typing import Any

import banner_native_live_admission as admission
import banner_native_terminal_reproof as terminal
from automation_governed_bot_review_gate import REVIEW_LOGIN, review_marker

REPOSITORY = "portyu9/portyu9"
HTTP_200 = re.compile(r"^HTTP/(?:1\.[01]|2(?:\.0)?) 200(?: [^\r\n]*)?$")
TTL = timedelta(minutes=10)


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def exact_request(initial: Any) -> dict[str, Any]:
    """Prepare one precise native review request; grant NO write authority."""
    require(type(initial) is dict
            and set(initial) == terminal.DATA_FIELDS,
            "banner review request requires one complete exact native candidate")
    decision = admission.decide(initial)
    require(decision.get("decision")
            == "exact-native-banner-owner-review-ready-read-only",
            "banner review not ready, owner vetoed or native evidence incomplete")
    pr = decision["prNumber"]
    base = decision["baseSha"]
    head = decision["headSha"]
    require(type(pr) is int and pr > 0 and type(base) is str
            and type(head) is str and base != head
            and initial["pr"]["head"]["sha"] == head
            and initial["pr"]["base"]["sha"] == base,
            "banner review subject did not bind exact main/head")
    marker = review_marker(base, head)
    require(type(marker) is str and marker.startswith(
        "<!-- portyu9-bot-review:v2 base="), "native owner marker changed")
    return {
        "endpoint": f"repos/{REPOSITORY}/pulls/{pr}/reviews",
        "request": {
            "event": "APPROVE",
            "commit_id": head,
            "body": marker,
        },
        "prNumber": pr,
        "baseSha": base,
        "headSha": head,
    }


def verify_submission(*, initial: Any, status_line: Any,
                      response: Any, after: Any) -> dict[str, Any]:
    """Verify one real HTTP-200 owner response AND full two-phase native proof.

    Transport authentication, complete GitHub pagination, fresh refs and the
    separate App merger remain responsibilities of the trusted-main workflow.
    This function cannot manufacture the owner response or any review state.
    """
    request = exact_request(initial)
    require(type(status_line) is str
            and HTTP_200.fullmatch(status_line.rstrip("\r")) is not None,
            "banner owner review must return native HTTP 200")
    require(type(response) is dict
            and type(response.get("id")) is int and response["id"] > 0
            and type(response.get("user")) is dict
            and response["user"].get("login") == REVIEW_LOGIN
            and response.get("state") == "APPROVED"
            and response.get("commit_id") == request["headSha"]
            and response.get("body") == request["request"]["body"],
            "banner owner review response actor/head/marker/state mismatched")
    submitted_at = response.get("submitted_at")
    require(type(submitted_at) is str and submitted_at.endswith("Z"),
            "banner owner review submission timestamp is absent or not UTC")
    submitted = admission.exact_utc(submitted_at)
    initial_time = admission.exact_utc(initial["observedAt"])
    require(type(after) is dict
            and type(after.get("observedAt")) is str,
            "banner post-review observation is missing")
    after_time = admission.exact_utc(after["observedAt"])
    require(timedelta() <= submitted - initial_time <= TTL
            and timedelta() <= after_time - submitted <= TTL
            and initial_time.date() == submitted.date() == after_time.date(),
            "banner owner approval is stale, future-dated or crossed UTC day")
    approved = terminal.evaluate(initial, after)
    require(approved.get("decision")
            == "exact-two-phase-owner-reviewed-banner-data-only"
            and approved.get("ownerReviewId") == response["id"]
            and approved.get("prNumber") == request["prNumber"]
            and approved.get("baseSha") == request["baseSha"]
            and approved.get("headSha") == request["headSha"],
            "banner owner response does not bind one newly observed exact review")
    # Never return an authorization token or an unvalidated raw review payload.
    return {
        "decision": "exact-native-banner-owner-review-observed-no-merge",
        "prNumber": request["prNumber"],
        "baseSha": request["baseSha"],
        "headSha": request["headSha"],
        "ownerReviewId": response["id"],
    }


def self_test() -> None:
    before = admission.fixture()
    expected = exact_request(before)
    require(expected["request"]["event"] == "APPROVE"
            and expected["request"]["commit_id"] == expected["headSha"]
            and expected["endpoint"]
            == f"repos/{REPOSITORY}/pulls/{expected['prNumber']}/reviews",
            "positive owner review request not exact")
    after = copy.deepcopy(before)
    first = admission.exact_utc(before["observedAt"])
    after["observedAt"] = (first + timedelta(minutes=3)).isoformat(
        timespec="seconds").replace("+00:00", "Z")
    approval = {
        "id": 851, "user": {"login": REVIEW_LOGIN},
        "state": "APPROVED", "commit_id": expected["headSha"],
        "body": expected["request"]["body"],
        "submitted_at": (first + timedelta(minutes=1)).isoformat(
            timespec="seconds").replace("+00:00", "Z"),
    }
    after["reviews"].append(copy.deepcopy(approval))
    after["completeness"]["reviews"]["totalCount"] = 1
    passed = verify_submission(
        initial=before, status_line="HTTP/2.0 200 OK",
        response=approval, after=after,
    )
    require(passed["decision"] == "exact-native-banner-owner-review-observed-no-merge"
            and passed["ownerReviewId"] == approval["id"],
            "real owner-review evidence was not matched")

    def rejected(label: str, mutate: Any) -> None:
        initial, later, response = (
            copy.deepcopy(before), copy.deepcopy(after), copy.deepcopy(approval)
        )
        status = mutate(initial, later, response)
        if status is None:
            status = "HTTP/2.0 200 OK"
        try:
            verify_submission(
                initial=initial, status_line=status,
                response=response, after=later,
            )
        except (ValueError, KeyError, TypeError):
            return
        raise AssertionError(f"untrusted banner review accepted: {label}")

    cases = [
        ("unexpected 201 status",
         lambda a, b, c: "HTTP/2.0 201 Created"),
        ("unexpected 204 status",
         lambda a, b, c: "HTTP/2.0 204 No Content"),
        ("misleading HTTP header",
         lambda a, b, c: "HTTP/2.0 200 OK\nHTTP/2.0 403"),
        ("wrong review actor",
         lambda a, b, c: c["user"].update(login="attacker")),
        ("wrong exact head",
         lambda a, b, c: c.update(commit_id="f" * 40)),
        ("wrong base/head marker",
         lambda a, b, c: c.update(body="approved")),
        ("nonapproving review",
         lambda a, b, c: c.update(state="COMMENTED")),
        ("response id is boolean",
         lambda a, b, c: c.update(id=True)),
        ("unobserved response id",
         lambda a, b, c: c.update(id=913)),
        ("response timestamp future",
         lambda a, b, c: c.update(submitted_at="2099-01-01T00:00:00Z")),
        ("response timestamp stale",
         lambda a, b, c: c.update(submitted_at="2020-01-01T00:00:00Z")),
        ("owner veto",
         lambda a, b, c: b["reviews"].append({
             "id": 856, "user": {"login": REVIEW_LOGIN},
             "state": "CHANGES_REQUESTED", "commit_id": expected["headSha"],
             "body": "Stop merge",
         })),
        ("post review ref moved",
         lambda a, b, c: b["mainRef"]["object"].update(sha="f" * 40)),
        ("post review head changed",
         lambda a, b, c: b["pr"]["head"].update(sha="f" * 40)),
        ("post review artwork changed",
         lambda a, b, c: b.update(proposedReadme="forged")),
        ("post review clock replay",
         lambda a, b, c: b.update(observedAt="2030-01-01T12:03:00Z")),
        ("post review missing",
         lambda a, b, c: b["reviews"].clear()),
        ("post review duplication",
         lambda a, b, c: b["reviews"].append(copy.deepcopy(approval))),
        ("initial preapproved",
         lambda a, b, c: a["reviews"].append(copy.deepcopy(approval))),
        ("initial invalid check",
         lambda a, b, c: a["checkRuns"][0].update(conclusion="failure")),
    ]
    for label, mutate in cases:
        rejected(label, mutate)
    print("native banner owner-review HTTP200, actor, response, two-phase "
          "exact-subject and veto negatives PASS (no network or mutation)")


if __name__ == "__main__":
    self_test()
