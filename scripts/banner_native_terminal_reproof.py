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
STABLE_FIELDS = DATA_FIELDS - frozenset({"observedAt", "reviews", "completeness"})
REVIEW_TTL = timedelta(minutes=10)


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


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
            "banner base/head/PR/artwork/App/CI/refs/threads changed around owner review")
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
        "utcDay": "2026-10-27", "ownerReviewId": 517,
    }, "approved two-phase reviewer proof returned ambiguous subject")

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
    invalid("stale terminal clock", "observedAt", "2026-10-27T12:11:00Z")
    invalid("UTC reversal", "observedAt", "2026-10-27T11:59:00Z")
    invalid("different day", "observedAt", "2026-10-28T00:00:00Z")

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
