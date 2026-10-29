#!/usr/bin/env python3
"""Pure two-phase reviewer/terminal reproof for one native banner candidate.

This computes evidence only. It never opens a network connection, mints tokens,
approves a review, publishes checks, calls a merge API, or changes a repository
ref. A trusted future writer MUST collect independently authenticated fresh
GitHub responses, separately verify the owner credential and App installation,
and use a normal protected merge bound to the exact PR head.
"""
from __future__ import annotations

import copy
from datetime import datetime, timedelta
from typing import Any

import banner_native_live_admission as admission
import independent_banner_candidate_contract as contract
from automation_governed_bot_review_gate import (
    REVIEW_LOGIN, review_marker, review_decision, validate_review_entries,
)

DATA_FIELDS = frozenset(admission.BASIC | admission.CURRENT)
STABLE_FIELDS = DATA_FIELDS - frozenset({"observedAt", "reviews", "completeness", "pr", "openPrs"})
REVIEW_TTL = timedelta(minutes=10)


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def same_except_owner_review_clock(before: Any, after: Any, approval: Any,
                                   start: datetime, end: datetime) -> bool:
    """Admit only GitHub's owner-APPROVED updated_at side effect, never PR edits.

    GitHub updates both REST /pulls and the open-PR list's updated_at when a
    review lands. An immediately read owner receipt may still see the previous
    timestamp; the later isolated App job can see the submitted review time.
    The exact authenticated new review supplies that single allowed timestamp.
    """
    if type(before) is not dict or type(after) is not dict:
        return False
    if (set(before) != set(after)
            or any(before[key] != after[key]
                   for key in before if key != "updated_at")):
        return False
    previous = before.get("updated_at")
    current = after.get("updated_at")
    if previous == current:
        return True
    if type(previous) is not str or type(current) is not str:
        return False
    submitted = approval.get("submitted_at") if type(approval) is dict else None
    if type(submitted) is not str:
        return False
    try:
        old = admission.exact_utc(previous)
        new = admission.exact_utc(current)
        approved = admission.exact_utc(submitted)
    except ValueError:
        return False
    return old <= start <= approved <= end and new == approved


def evaluated(snapshot: Any) -> dict[str, str | int]:
    """Never promote an unauthenticated caller-supplied snapshot to authority."""
    require(type(snapshot) is dict and set(snapshot) == DATA_FIELDS,
            "banner two-phase review needs one exact current candidate snapshot")
    return admission.decide(snapshot)


def evaluate(initial: Any, after_review: Any) -> dict[str, str | int]:
    """Bind the owner-only approval to unchanged pre-reviewed native evidence."""
    first = evaluated(initial)
    require(first.get("decision") == "exact-native-banner-owner-review-ready-read-only",
            "banner initial evidence is not exact owner-review-ready")
    second = evaluated(after_review)
    require(second.get("decision") == "exact-owner-reviewed-banner-terminal-ready-read-only",
            "banner terminal evidence is not exact owner-reviewed/merge-ready")
    require(set(initial) == set(after_review) == DATA_FIELDS,
            "banner two-phase observation schema drifted")

    start = admission.exact_utc(initial["observedAt"])
    end = admission.exact_utc(after_review["observedAt"])
    require(timedelta() <= end - start <= REVIEW_TTL
            and start.date() == end.date(),
            "banner owner-review observation is replayed, stale or crossed UTC day")
    require(all(initial[key] == after_review[key] for key in STABLE_FIELDS),
            "banner base/head/artwork/App/CI/refs/threads changed around owner review")
    for name in admission.INVENTORIES:
        if name == "reviews":
            continue
        require(initial["completeness"][name] == after_review["completeness"][name],
                f"banner {name} native completeness witness drifted around review")

    old = validate_review_entries(initial["reviews"])
    fresh = validate_review_entries(after_review["reviews"])
    require(type(initial["completeness"]["reviews"]) is dict
            and type(after_review["completeness"]["reviews"]) is dict
            and initial["completeness"]["reviews"] == {
                "totalCount": len(old), "hasNextPage": False,
            }
            and after_review["completeness"]["reviews"] == {
                "totalCount": len(fresh), "hasNextPage": False,
            }, "banner owner review collection is incomplete")
    previous = {review["id"]: review for review in old}
    following = {review["id"]: review for review in fresh}
    require(len(previous) == len(old) and len(following) == len(fresh),
            "banner native owner-review IDs are duplicated")
    require(all(following.get(identity) == review
                for identity, review in previous.items()),
            "banner historical review disappeared or changed around owner approval")
    created = [review for review in fresh if review["id"] not in previous]
    require(len(created) == 1,
            "exactly one owner approval must appear, with no competing review write")

    base = first["baseSha"]
    head = first["headSha"]
    require(base == second["baseSha"] and head == second["headSha"]
            and first["prNumber"] == second["prNumber"]
            and type(base) is str and type(head) is str,
            "banner two-phase candidate identity changed")
    new = created[0]
    require(type(new.get("user")) is dict
            and new["user"].get("login") == REVIEW_LOGIN
            and new.get("commit_id") == head
            and new.get("state") == "APPROVED"
            and new.get("body") == review_marker(base, head)
            and type(new.get("id")) is int and new["id"] > 0,
            "banner new owner approval lacks exact actor/head/marker binding")
    # Authenticate the exactly one new owner review before accepting its
    # GitHub-managed updated_at side effect. All other native PR fields remain
    # byte-for-byte stable, including base/head, body, metadata and branch.
    require(same_except_owner_review_clock(
                initial["pr"], after_review["pr"], new, start, end),
            "banner detailed PR changed beyond the exact owner-review clock")
    require(type(initial["openPrs"]) is list
            and type(after_review["openPrs"]) is list
            and len(initial["openPrs"]) == len(after_review["openPrs"])
            and all(same_except_owner_review_clock(
                previous, current, new, start, end)
                if (type(previous) is dict and
                    previous.get("number") == first["prNumber"])
                else previous == current
                for previous, current in zip(
                    initial["openPrs"], after_review["openPrs"], strict=True)),
            "banner open PR inventory changed beyond the exact owner-review clock")
    require(review_decision(fresh, base, head) == "approved",
            "banner terminal review was subsequently vetoed/revoked")
    require(after_review["pr"]["head"]["ref"] ==
            contract.expected_branch(start.date(), base),
            "banner review branch does not bind exact accepted base and UTC day")

    return {
        "decision": "exact-two-phase-owner-reviewed-banner-data-only",
        "prNumber": first["prNumber"], "baseSha": base,
        "headSha": head, "headRef": after_review["pr"]["head"]["ref"],
        "utcDay": start.date().isoformat(),
        "ownerReviewId": new["id"],
    }


def self_test() -> None:
    before = admission.fixture()
    require(evaluated(before)["decision"]
            == "exact-native-banner-owner-review-ready-read-only",
            "two-phase positive starting evidence rejected")
    after = copy.deepcopy(before)
    after["observedAt"] = after["observedAt"].replace("T12:00:00Z", "T12:03:00Z")
    reviewed = {
        "id": 517, "user": {"login": REVIEW_LOGIN},
        "commit_id": before["pr"]["head"]["sha"], "state": "APPROVED",
        "body": review_marker(
            before["mainSha"], before["pr"]["head"]["sha"],
        ),
    }
    after["reviews"].append(reviewed)
    after["completeness"]["reviews"]["totalCount"] = 1
    ready = evaluate(before, after)
    require(ready == {
        "decision": "exact-two-phase-owner-reviewed-banner-data-only",
        "prNumber": before["pr"]["number"],
        "baseSha": before["mainSha"],
        "headSha": before["pr"]["head"]["sha"],
        "headRef": before["pr"]["head"]["ref"],
        "utcDay": admission.exact_utc(before["observedAt"]).date().isoformat(),
        "ownerReviewId": 517,
    }, "approved two-phase reviewer proof returned ambiguous subject")

    # Production failure 40972395420: native owner APPROVED succeeded, but
    # GitHub advanced PR updated_at from original creation time to the exact
    # native review submitted_at only after the owner's receipt was captured.
    # This is not a PR file/body/ref mutation; every other field stays pinned.
    clock_reviewed = copy.deepcopy(after)
    start = admission.exact_utc(before["observedAt"])
    creation_clock = start - timedelta(minutes=3)
    origin = creation_clock.isoformat(timespec="seconds").replace("+00:00", "Z")
    approval_clock = (start + timedelta(minutes=2)).isoformat(
        timespec="seconds").replace("+00:00", "Z")
    before_clock = copy.deepcopy(before)
    for snapshot in (before_clock, clock_reviewed):
        snapshot["pr"]["updated_at"] = origin
        for row in snapshot["openPrs"]:
            row["updated_at"] = origin
    clock_reviewed["reviews"][0]["submitted_at"] = approval_clock
    clock_reviewed["pr"]["updated_at"] = approval_clock
    clock_reviewed["openPrs"][0]["updated_at"] = approval_clock
    require(evaluate(before_clock, clock_reviewed)["ownerReviewId"] == 517,
            "legitimate delayed native owner-review timestamp blocked exact merge")
    stale_clock = copy.deepcopy(clock_reviewed)
    stale_clock["pr"]["updated_at"] = origin
    stale_clock["openPrs"][0]["updated_at"] = origin
    require(evaluate(before_clock, stale_clock)["ownerReviewId"] == 517,
            "immediate native review observation cannot retain prior PR clock")
    for label, change in (
        ("unrelated PR metadata timestamp", lambda x:
         x["pr"].update(updated_at=(start + timedelta(seconds=1))
                        .isoformat(timespec="seconds").replace("+00:00", "Z"))),
        ("unrelated open PR metadata timestamp", lambda x:
         x["openPrs"][0].update(updated_at=(start + timedelta(seconds=1))
                               .isoformat(timespec="seconds").replace("+00:00", "Z"))),
        ("changed PR body at review", lambda x:
         x["pr"].update(body="forged after approval")),
        ("changed PR source title", lambda x:
         x["openPrs"][0].update(title="forged")),
        ("approval submitted time missing", lambda x:
         x["reviews"][0].pop("submitted_at")),
        ("approval submitted time forged", lambda x:
         x["reviews"][0].update(submitted_at=origin)),
    ):
        bad = copy.deepcopy(clock_reviewed)
        change(bad)
        try:
            evaluate(before_clock, bad)
        except (ValueError, KeyError, TypeError):
            pass
        else:
            raise AssertionError("owner PR clock exception admitted " + label)

    # Build independent mutated observations so even a nested data mutation
    # cannot contaminate the positive evidence.
    failures: list[tuple[str, Any, Any]] = []
    def invalid(label: str, key: str, value: Any) -> None:
        candidate = copy.deepcopy(after)
        candidate[key] = value
        failures.append((label, copy.deepcopy(before), candidate))

    for label, value in (
        ("different main SHA", "e" * 40),
        ("boolean main SHA", True),
    ):
        invalid(label, "mainSha", value)
    invalid("different repository", "repository", "attacker/repo")
    invalid("extra token in response", "token", "not-allowed")
    invalid("stale terminal clock", "observedAt",
            before["observedAt"].replace("T12:00:00Z", "T12:11:00Z"))
    invalid("UTC reversal", "observedAt",
            before["observedAt"].replace("T12:00:00Z", "T11:59:00Z"))
    invalid("different day", "observedAt",
            (admission.exact_utc(before["observedAt"]) + timedelta(days=1))
            .isoformat(timespec="seconds").replace("+00:00", "Z"))

    for label, rewrite in (
        ("changed branch", lambda x: x["pr"]["head"].update(ref="other")),
        ("changed head", lambda x: x["pr"]["head"].update(sha="f" * 40)),
        ("changed check suite", lambda x: x["checkRuns"][0]["check_suite"].update(id=1)),
        ("changed workflow run", lambda x: x["workflowRuns"][0].update(run_attempt=2)),
        ("changed artwork", lambda x: x.update(proposedReadme="forged")),
        ("changed App", lambda x: x["nativeApp"].update(expected_repository_id=88)),
        ("changed main ref", lambda x: x["mainRef"]["object"].update(sha="f" * 40)),
        ("changed thread pagination", lambda x: x["reviewThreads"]["pageInfo"].update(hasNextPage=True)),
        ("changed open PR count", lambda x: x["completeness"]["openPrs"].update(totalCount=2)),
        ("review disappeared", lambda x: x["reviews"].clear()),
        ("wrong actor", lambda x: x["reviews"][0]["user"].update(login="attacker")),
        ("wrong approval commit", lambda x: x["reviews"][0].update(commit_id="f" * 40)),
        ("wrong marker", lambda x: x["reviews"][0].update(body="Approved")),
        ("wrong approval state", lambda x: x["reviews"][0].update(state="COMMENTED")),
        ("boolean review ID", lambda x: x["reviews"][0].update(id=True)),
        ("duplicate review ID", lambda x: x["reviews"].append(copy.deepcopy(x["reviews"][0]))),
        ("unrelated new review", lambda x: x["reviews"].append({
            "id": 518, "user": {"login": "outsider"},
            "commit_id": before["pr"]["head"]["sha"],
            "state": "COMMENTED", "body": "another review",
        })),
        ("owner veto", lambda x: x["reviews"].append({
            "id": 519, "user": {"login": REVIEW_LOGIN},
            "commit_id": before["pr"]["head"]["sha"],
            "state": "CHANGES_REQUESTED", "body": "Owner veto",
        })),
    ):
        candidate = copy.deepcopy(after)
        rewrite(candidate)
        if label in {"duplicate review ID", "unrelated new review", "owner veto"}:
            candidate["completeness"]["reviews"]["totalCount"] = len(candidate["reviews"])
        failures.append((label, copy.deepcopy(before), candidate))

    for label, start, finish in failures:
        try:
            evaluate(start, finish)
        except (ValueError, TypeError, KeyError):
            continue
        raise AssertionError(f"unsafe banner two-phase review transition accepted: {label}")

    # A previous comment/review may be retained, but cannot disappear or
    # be rewritten across the review transaction.
    historic = {
        "id": 300, "user": {"login": "contributor"},
        "commit_id": before["pr"]["head"]["sha"],
        "state": "COMMENTED", "body": "Prior non-owner review",
    }
    previous = copy.deepcopy(before)
    previous["reviews"].append(historic)
    previous["completeness"]["reviews"]["totalCount"] = 1
    following = copy.deepcopy(after)
    following["reviews"].insert(0, copy.deepcopy(historic))
    following["completeness"]["reviews"]["totalCount"] = 2
    require(evaluate(previous, following)["ownerReviewId"] == 517,
            "historic review preservation prevents legitimate exact owner approval")
    changed = copy.deepcopy(following)
    changed["reviews"][0]["body"] = "rewritten"
    try:
        evaluate(previous, changed)
    except ValueError:
        pass
    else:
        raise AssertionError("two-phase gate accepted rewritten historical review")

    print(
        "banner two-phase terminal: exact App/PR/README/first-run/ref leases, "
        "one owner approval, historical preservation, veto and 26+ fail-closed probes PASS"
    )
