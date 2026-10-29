#!/usr/bin/env python3
"""Data-only banner review/merge transaction envelope adapter.

This is NOT a reviewer or merger. It performs no network I/O, GitHub mutations,
token acquisition, review, dispatch or merge. A separately authenticated
trusted-main caller must collect every live native GitHub snapshot, own the
appropriate isolated credential and perform the exact request only after an
independent capability/TCB authorization has merged to protected main.

Use O_NOFOLLOW, O_EXCL, bounded UTF-8 JSON and strict closed schemas so an
untrusted job artifact cannot smuggle an endpoint, credential or status writer.
"""
from __future__ import annotations

import argparse
import copy
from datetime import timedelta
from pathlib import Path
from typing import Any

import banner_native_live_admission as admission
import banner_native_owner_review_transaction_contract as owner
import banner_native_protected_merge_response_contract as merge
import banner_native_observer_cli as observer
from independent_banner_candidate_contract import verified_native_banner_app_identity

SCHEMAS = {
    "review-request": frozenset({"initial"}),
    "authenticated-review-request": frozenset({
        "initial", "appIdentity", "ownerIdentity",
    }),
    "review-receipt": frozenset({
        "initial", "reviewed", "ownerStatus", "ownerResponse",
    }),
    "merge-request": frozenset({
        "initial", "reviewed", "ownerStatus", "ownerResponse",
    }),
    "merge-receipt": frozenset({
        "initial", "reviewed", "ownerStatus", "ownerResponse",
        "mergeStatus", "mergeResponse", "mergedPr", "mergeCommit",
        "finalMainRef", "observedAt",
    }),
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def compile_transaction(operation: str, documents: Any) -> dict[str, Any]:
    """Return exact native request or verified receipt, never authorizing it."""
    require(type(operation) is str and operation in SCHEMAS,
            "unrecognized banner transaction operation")
    require(type(documents) is dict
            and set(documents) == SCHEMAS[operation],
            "banner transaction envelope missing or contains extra inputs")
    before = documents["initial"]
    if operation == "review-request":
        return owner.exact_request(before)
    if operation == "authenticated-review-request":
        # The native observer and each independently credentialed source
        # MUST be fetched by the trusted caller over verified HTTPS in its
        # isolated environment. This pure check cannot authenticate a JSON
        # artifact or issue a review on its own.
        app_identity = documents["appIdentity"]
        reviewer_identity = documents["ownerIdentity"]
        require(type(before) is dict,
                "banner dual identity intent requires one native snapshot object")
        require(type(app_identity) is dict and
                set(app_identity) == {
                    "installation", "bot_user", "expected_app_id",
                    "expected_installation_id", "expected_repository_id",
                } and app_identity == before.get("nativeApp"),
                "selected App origin does not match fresh reviewed candidate")
        selected = verified_native_banner_app_identity(**app_identity)
        require(type(reviewer_identity) is dict
                and set(reviewer_identity) == {
                    "login", "userId", "repositoryId", "repository",
                    "defaultBranch",
                } and reviewer_identity["login"] == owner.REVIEW_LOGIN
                and type(reviewer_identity["userId"]) is int
                and reviewer_identity["userId"] > 0
                and type(reviewer_identity["repositoryId"]) is int
                and reviewer_identity["repositoryId"] == selected["repositoryId"]
                and reviewer_identity["repository"] == "portyu9/portyu9"
                and reviewer_identity["defaultBranch"] == "main",
                "independent owner identity is not bound to selected App repository")
        # Exact owner subject is ready only when native status, check,
        # inventory, UTC artwork and veto predicates independently pass.
        return {
            "intent": owner.exact_request(before),
            "identityBinding": {
                "ownerLogin": reviewer_identity["login"],
                "ownerUserId": reviewer_identity["userId"],
                "appId": selected["appId"],
                "installationId": selected["installationId"],
                "repositoryId": selected["repositoryId"],
            },
            "decision": "dual-source-banner-owner-review-intent-no-write",
        }
    reviewed = documents["reviewed"]
    status = documents["ownerStatus"]
    response = documents["ownerResponse"]
    if operation == "review-receipt":
        return owner.verify_submission(
            initial=before, after=reviewed,
            status_line=status, response=response,
        )
    if operation == "merge-request":
        return merge.exact_merge_request(
            initial=before, reviewed=reviewed,
            owner_status=status, owner_response=response,
        )
    return merge.verify_merge(
        initial=before, reviewed=reviewed,
        owner_status=status, owner_response=response,
        merge_status=documents["mergeStatus"],
        merge_response=documents["mergeResponse"],
        merged_pr=documents["mergedPr"],
        merge_commit=documents["mergeCommit"],
        final_main_ref=documents["finalMainRef"],
        observed_at=documents["observedAt"],
    )


def self_test() -> None:
    before = admission.fixture()
    initial = admission.exact_utc(before["observedAt"])
    review_request = compile_transaction(
        "review-request", {"initial": before},
    )
    require(review_request["request"]["event"] == "APPROVE"
            and review_request["request"]["commit_id"] == review_request["headSha"]
            and review_request["endpoint"].endswith(
                f"/pulls/{review_request['prNumber']}/reviews"
            ), "review request must bind exact native candidate")
    # Two distinct exact HTTPS-origin identities are required for the
    # future privileged owner writer; neither source is a bearer credential.
    app_identity = copy.deepcopy(before["nativeApp"])
    reviewer_identity = {
        "login": "portyu9", "userId": 9922,
        "repositoryId": app_identity["expected_repository_id"],
        "repository": "portyu9/portyu9", "defaultBranch": "main",
    }
    dual = {
        "initial": before, "appIdentity": app_identity,
        "ownerIdentity": reviewer_identity,
    }
    authenticated = compile_transaction("authenticated-review-request", dual)
    require(authenticated["intent"] == review_request
            and authenticated["identityBinding"]["repositoryId"]
                == app_identity["expected_repository_id"]
            and authenticated["decision"]
                == "dual-source-banner-owner-review-intent-no-write",
            "independent App/owner identity binding did not preserve native request")
    after = copy.deepcopy(before)
    after["observedAt"] = (initial + timedelta(minutes=3)).isoformat(
        timespec="seconds",
    ).replace("+00:00", "Z")
    approval = {
        "id": 914, "user": {"login": "portyu9"},
        "state": "APPROVED", "commit_id": review_request["headSha"],
        "body": review_request["request"]["body"],
        "submitted_at": (initial + timedelta(minutes=1)).isoformat(
            timespec="seconds",
        ).replace("+00:00", "Z"),
    }
    after["reviews"].append(copy.deepcopy(approval))
    after["completeness"]["reviews"]["totalCount"] = 1
    transaction = {
        "initial": before, "reviewed": after,
        "ownerStatus": "HTTP/2.0 200 OK", "ownerResponse": approval,
    }
    receipt = compile_transaction("review-receipt", transaction)
    require(receipt["ownerReviewId"] == approval["id"]
            and receipt["decision"] ==
                "exact-native-banner-owner-review-observed-no-merge",
            "review receipt was not exact actor/head/native response")
    request = compile_transaction("merge-request", transaction)
    require(request["method"] == "PUT"
            and request["request"] == {
                "sha": review_request["headSha"], "merge_method": "merge",
            }, "ordinary protected merge request not exact")

    merge_sha = "d" * 40
    complete = {
        **transaction,
        "mergeStatus": "HTTP/2.0 200 OK",
        "mergeResponse": {
            "merged": True, "sha": merge_sha,
            "message": "Pull Request successfully merged",
        },
        "mergedPr": {
            "number": request["prNumber"], "state": "closed",
            "merged": True, "merge_commit_sha": merge_sha,
            "head": {"sha": request["headSha"]},
        },
        "mergeCommit": {
            "sha": merge_sha,
            "parents": [{"sha": request["baseSha"]},
                        {"sha": request["headSha"]}],
        },
        "finalMainRef": {
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": merge_sha},
        },
        "observedAt": (initial + timedelta(minutes=4)).isoformat(
            timespec="seconds",
        ).replace("+00:00", "Z"),
    }
    verified = compile_transaction("merge-receipt", complete)
    require(verified["mergeSha"] == merge_sha
            and verified["decision"] ==
                "native-banner-protected-merge-observed-no-write",
            "merge receipt did not establish actual protected main lineage")

    def reject(label: str, operation: str, payload: Any) -> None:
        try:
            compile_transaction(operation, payload)
        except (KeyError, TypeError, ValueError):
            return
        raise AssertionError("unsafe transaction envelope admitted: " + label)

    # Fail closed before any future owner HTTP writer can be invoked.
    bad_binding = copy.deepcopy(dual)
    bad_binding["initial"] = []
    reject("non-object initial snapshot", "authenticated-review-request", bad_binding)
    bad_binding = copy.deepcopy(dual)
    bad_binding["ownerIdentity"]["userId"] = True
    reject("boolean owner user ID", "authenticated-review-request", bad_binding)
    bad_binding = copy.deepcopy(dual)
    bad_binding["ownerIdentity"]["repositoryId"] += 1
    reject("cross-repo reviewer identity", "authenticated-review-request", bad_binding)
    bad_binding = copy.deepcopy(dual)
    bad_binding["ownerIdentity"]["login"] = "attacker"
    reject("wrong owner login", "authenticated-review-request", bad_binding)
    bad_binding = copy.deepcopy(dual)
    bad_binding["ownerIdentity"]["defaultBranch"] = "generated"
    reject("non-main reviewer intent", "authenticated-review-request", bad_binding)
    bad_binding = copy.deepcopy(dual)
    bad_binding["ownerIdentity"]["token"] = "must-never-cross"
    reject("owner secret injected", "authenticated-review-request", bad_binding)
    bad_binding = copy.deepcopy(dual)
    bad_binding["appIdentity"]["installation"]["id"] += 1
    reject("forged App installation", "authenticated-review-request", bad_binding)
    bad_binding = copy.deepcopy(dual)
    bad_binding["appIdentity"]["expected_repository_id"] = True
    reject("boolean App repo ID", "authenticated-review-request", bad_binding)
    bad_binding = copy.deepcopy(dual)
    bad_binding["initial"]["mainRef"]["object"]["sha"] = "f" * 40
    reject("moved protected main", "authenticated-review-request", bad_binding)

    with_added_field = copy.deepcopy(complete)
    with_added_field["token"] = "cannot-be-carried"
    reject("unexpected secret-bearing key", "merge-receipt", with_added_field)
    reject("wrong operation", "approve", {"initial": before})
    reject("missing owner response", "merge-request", {
        "initial": before, "reviewed": after,
        "ownerStatus": "HTTP/2.0 200 OK",
    })
    wrong_status = copy.deepcopy(transaction)
    wrong_status["ownerStatus"] = "HTTP/2.0 204 No Content"
    reject("false HTTP owner review", "review-receipt", wrong_status)
    wrong_status["ownerStatus"] = "HTTP/2.0 200 OK\nHTTP/2.0 403"
    reject("header injection", "merge-request", wrong_status)
    forged_review = copy.deepcopy(transaction)
    forged_review["ownerResponse"]["user"]["login"] = "attacker"
    reject("wrong owner identity", "review-receipt", forged_review)
    forged_ref = copy.deepcopy(transaction)
    forged_ref["reviewed"]["mainRef"]["object"]["sha"] = "f" * 40
    reject("moved accepted main", "merge-request", forged_ref)
    bad_parent = copy.deepcopy(complete)
    bad_parent["mergeCommit"]["parents"].reverse()
    reject("reversed merge parents", "merge-receipt", bad_parent)
    bad_main = copy.deepcopy(complete)
    bad_main["finalMainRef"]["object"]["sha"] = "e" * 40
    reject("unaccepted merge", "merge-receipt", bad_main)
    bad_day = copy.deepcopy(complete)
    bad_day["observedAt"] = (
        initial + timedelta(days=1)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    reject("UTC-day rollover", "merge-receipt", bad_day)

    # File I/O lives behind the separately reviewed observer CLI. It is not
    # reachable from protected validator self-tests: validator-purity recursively
    # checks delegated production function bodies, even if caller uses a
    # temporary fixture. The accepted observer self-test owns its own
    # exclusive O_NOFOLLOW/O_EXCL and duplicate-key adversarial cases.
    print("banner native transaction artifact adapter: exact review/merge "
          "envelopes, owner veto, HTTP and ancestry negatives PASS; "
          "no credentials, network or mutations")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--operation", choices=sorted(SCHEMAS))
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.self_test:
        require(args.operation is None and args.input is None
                and args.output is None,
                "self-test cannot accept external transaction input")
        self_test()
        return 0
    require(args.operation is not None and args.input is not None
            and args.output is not None
            and args.input != args.output,
            "one operation, bounded input and exclusive output required")
    envelope = observer.read_bounded(args.input)
    result = compile_transaction(args.operation, envelope)
    observer.write_exclusive(args.output, result)
    print(result.get("decision", "exact-native-banner-request-data-only"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
