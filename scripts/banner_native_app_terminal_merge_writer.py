#!/usr/bin/env python3
"""Dormant selected-App-only native banner protected merge HTTP transport.

This source does NOT mint a selected-installation credential, acquire a human
owner token, approve a review, publish a check or invoke GitHub from CI.
A future separately authorized, isolated ruleset-admin-identity App job must
mint and independently prove its exact selected-installation token. It may
invoke this transport ONLY after importing authentic owner review evidence
from the disjoint owner identity environment, re-reading the full current
native banner subject and proving no new review veto or main/head movement.

A direct HTTP 200 is not a merge witness: fresh native PR, two-parent merge
commit and exact protected main ref are mandatory before success.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timedelta, timezone
import http.client
import json
import os
from pathlib import Path
import re
import ssl
from typing import Any, Callable

import banner_native_live_admission as admission
import banner_native_observer_cli as observer
import banner_native_protected_merge_response_contract as merge_contract
import banner_native_terminal_reproof as terminal
import banner_native_transaction_artifact_cli as transaction
from banner_native_authenticated_app_source import (
    FixedOriginRead, REPOSITORY, unique_object,
)
from independent_banner_candidate_contract import verified_native_banner_app_identity

HOST = "api.github.com"
MERGE_PATH = re.compile(r"^repos/portyu9/portyu9/pulls/([1-9][0-9]*)/merge$")
MAX_RESPONSE = 131_072
PREWRITE_TTL = timedelta(seconds=75)
OWNER_KEYS = frozenset({
    "initial", "appIdentity", "ownerIdentity",
    "reviewed", "ownerStatus", "ownerResponse",
})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


class ExactSelectedAppMergePut:
    """One ordinary SHA-guarded protected merge, no bypass or auto-merge."""

    def __init__(self, app_token: str,
                 connection_factory: Callable[..., Any] | None = None):
        require(type(app_token) is str and len(app_token) >= 8
                and not any(c.isspace() for c in app_token),
                "selected-installation App token malformed")
        self.__token = app_token
        self.__factory = connection_factory or http.client.HTTPSConnection

    def submit(self, intent: Any) -> tuple[str, dict[str, Any]]:
        require(type(intent) is dict
                and set(intent) == {
                    "method", "endpoint", "request", "prNumber",
                    "baseSha", "headSha", "ownerReviewId",
                } and intent["method"] == "PUT"
                and type(intent["prNumber"]) is int
                and intent["prNumber"] > 0
                and type(intent["ownerReviewId"]) is int
                and intent["ownerReviewId"] > 0,
                "untrusted App terminal request shape")
        path = intent["endpoint"]
        require(type(path) is str and MERGE_PATH.fullmatch(path) is not None
                and path == (
                    f"repos/portyu9/portyu9/pulls/{intent['prNumber']}/merge"
                ),
                "App merge endpoint escaped exact selected PR")
        request = intent["request"]
        require(type(intent["baseSha"]) is str
                and type(intent["headSha"]) is str
                and admission.HEX40.fullmatch(intent["baseSha"]) is not None
                and admission.HEX40.fullmatch(intent["headSha"]) is not None
                and intent["baseSha"] != intent["headSha"]
                and type(request) is dict
                and set(request) == {"sha", "merge_method"}
                and request["sha"] == intent["headSha"]
                and request["merge_method"] == "merge",
                "App merge is not SHA-guarded ordinary protected merge")
        data = json.dumps(
            request, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        require(0 < len(data) <= 1024,
                "App merge command unexpectedly large")
        connection = self.__factory(
            HOST, timeout=15, context=ssl.create_default_context(),
        )
        try:
            connection.request("PUT", "/" + path, body=data, headers={
                "Authorization": "Bearer " + self.__token,
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "portyu9-banner-exact-protected-app-merge",
            })
            reply = connection.getresponse()
            require(reply.status == 200
                    and reply.version in (10, 11)
                    and reply.getheader("Location") is None
                    and reply.getheader("Link") is None,
                    "selected-App merge must return direct native HTTP 200")
            raw = reply.read(MAX_RESPONSE + 1)
            reason = reply.reason
            version = "1.1" if reply.version == 11 else "1.0"
        finally:
            connection.close()
        require(len(raw) <= MAX_RESPONSE
                and type(reason) is str
                and re.fullmatch(r"[A-Za-z0-9 ._-]{1,80}", reason) is not None,
                "selected-App merge HTTP response malformed")
        try:
            response = json.loads(
                raw.decode("utf-8"), object_pairs_hook=unique_object,
            )
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("App merge response is not unique-key JSON") from exc
        require(type(response) is dict
                and response.get("merged") is True
                and type(response.get("sha")) is str
                and admission.HEX40.fullmatch(response["sha"]) is not None,
                "App HTTP 200 did not acknowledge a distinct merge commit")
        return f"HTTP/{version} 200 {reason}", response


def complete_app_protected_merge(
    *, owner_documents: Any, fresh_reviewed: Any, observed_at: datetime,
    submit: Callable[[dict[str, Any]], tuple[str, dict[str, Any]]],
    observe_merged: Callable[[str, int], Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Owner-receipt + exact-current two-phase veto + one App PUT + native proof."""
    require(type(owner_documents) is dict
            and set(owner_documents) == OWNER_KEYS,
            "App terminal requires only complete owner-review native receipt")
    require(type(observed_at) is datetime
            and observed_at.tzinfo is not None
            and observed_at.utcoffset() == timedelta(),
            "selected-App terminal clock is not UTC")
    before = owner_documents["initial"]
    owner_evidence = transaction.compile_transaction(
        "authenticated-review-receipt", owner_documents,
    )
    app = owner_documents["appIdentity"]
    require(type(app) is dict and before["nativeApp"] == app,
            "terminal App differs from source installation")
    identity = verified_native_banner_app_identity(**app)
    require(identity["repositoryId"] == app["expected_repository_id"],
            "terminal App no longer binds selected repository")
    reproof = terminal.evaluate(before, fresh_reviewed)
    require(reproof["decision"] == "exact-two-phase-owner-reviewed-banner-data-only"
            and reproof["ownerReviewId"] == owner_evidence["ownerReviewId"],
            "fresh owner reviewed state is not the same genuine native approval")
    fresh = {**owner_documents, "reviewed": fresh_reviewed}
    fresh_owner = transaction.compile_transaction(
        "authenticated-review-receipt", fresh,
    )
    require(fresh_owner["ownerUserId"] == owner_evidence["ownerUserId"]
            and fresh_owner["ownerReviewId"] == owner_evidence["ownerReviewId"]
            and fresh_owner["baseSha"] == owner_evidence["baseSha"]
            and fresh_owner["headSha"] == owner_evidence["headSha"],
            "owner numeric identity or review intent changed before App merge")
    last = admission.exact_utc(fresh_reviewed["observedAt"])
    require(timedelta() <= observed_at - last <= PREWRITE_TTL
            and observed_at.date() == last.date(),
            "fresh protected merge veto evidence expired or crossed UTC day")
    request = transaction.compile_transaction(
        "merge-request", {
            "initial": before,
            "reviewed": fresh_reviewed,
            "ownerStatus": fresh["ownerStatus"],
            "ownerResponse": fresh["ownerResponse"],
        },
    )
    require(request["baseSha"] == reproof["baseSha"]
            and request["headSha"] == reproof["headSha"]
            and request["prNumber"] == reproof["prNumber"]
            and request["ownerReviewId"] == reproof["ownerReviewId"],
            "App merge body is not the exact re-proven native current head")
    status, response = submit(request)
    require(type(status) is str
            and merge_contract.HTTP_OK.fullmatch(status) is not None
            and type(response) is dict
            and response.get("merged") is True
            and type(response.get("sha")) is str
            and admission.HEX40.fullmatch(response["sha"]) is not None,
            "App merge POST returned no authentic native HTTP 200 merge")
    result = observe_merged(response["sha"], request["prNumber"])
    require(type(result) is dict
            and set(result) == {
                "mergedPr", "mergeCommit", "finalMainRef", "observedAt",
            }, "post-merge native proof requires exactly four complete fields")
    packet = {
        "initial": before,
        "reviewed": fresh_reviewed,
        "ownerStatus": fresh["ownerStatus"],
        "ownerResponse": fresh["ownerResponse"],
        "mergeStatus": status,
        "mergeResponse": response,
        **result,
    }
    receipt = transaction.compile_transaction("merge-receipt", packet)
    require(receipt["mergeSha"] == response["sha"]
            and receipt["ownerReviewId"] == owner_evidence["ownerReviewId"],
            "App merge receipt did not advance exact protected main")
    return packet, receipt


def self_test() -> None:
    before = admission.fixture()
    start = admission.exact_utc(before["observedAt"])
    owner_request = transaction.compile_transaction(
        "review-request", {"initial": before},
    )
    approval = {
        "id": 904, "user": {"login": "portyu9", "id": 9922},
        "state": "APPROVED", "commit_id": owner_request["headSha"],
        "body": owner_request["request"]["body"],
        "submitted_at": (start + timedelta(minutes=1)).isoformat(
            timespec="seconds",
        ).replace("+00:00", "Z"),
    }
    reviewed = copy.deepcopy(before)
    reviewed["observedAt"] = (start + timedelta(minutes=3)).isoformat(
        timespec="seconds",
    ).replace("+00:00", "Z")
    reviewed["reviews"].append(copy.deepcopy(approval))
    reviewed["completeness"]["reviews"]["totalCount"] = 1
    fresh_reviewed = copy.deepcopy(reviewed)
    fresh_reviewed["observedAt"] = (start + timedelta(minutes=4)).isoformat(
        timespec="seconds",
    ).replace("+00:00", "Z")
    own = {
        "login": "portyu9", "userId": 9922,
        "repositoryId": before["nativeApp"]["expected_repository_id"],
        "repository": "portyu9/portyu9", "defaultBranch": "main",
    }
    owner_documents = {
        "initial": before, "appIdentity": before["nativeApp"],
        "ownerIdentity": own, "reviewed": reviewed,
        "ownerStatus": "HTTP/1.1 200 OK",
        "ownerResponse": copy.deepcopy(approval),
    }
    request = transaction.compile_transaction(
        "merge-request", {
            "initial": before, "reviewed": fresh_reviewed,
            "ownerStatus": owner_documents["ownerStatus"],
            "ownerResponse": owner_documents["ownerResponse"],
        },
    )
    merge_sha = "c" * 40
    response = {
        "merged": True, "sha": merge_sha,
        "message": "Pull Request successfully merged",
    }
    sent: list[Any] = []
    def submit(subject: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        sent.append(copy.deepcopy(subject))
        return "HTTP/1.1 200 OK", copy.deepcopy(response)

    def observed(_merge: str, _number: int) -> dict[str, Any]:
        return {
            "mergedPr": {
                "number": request["prNumber"], "state": "closed",
                "merged": True, "merge_commit_sha": merge_sha,
                "head": {"sha": request["headSha"]},
            },
            "mergeCommit": {
                "sha": merge_sha, "parents": [
                    {"sha": request["baseSha"]},
                    {"sha": request["headSha"]},
                ],
            },
            "finalMainRef": {
                "ref": "refs/heads/main",
                "object": {"type": "commit", "sha": merge_sha},
            },
            "observedAt": (start + timedelta(minutes=4, seconds=20))
                .isoformat(timespec="seconds").replace("+00:00", "Z"),
        }

    packet, receipt = complete_app_protected_merge(
        owner_documents=owner_documents, fresh_reviewed=fresh_reviewed,
        observed_at=start + timedelta(minutes=4, seconds=10),
        submit=submit, observe_merged=observed,
    )
    require(len(sent) == 1 and sent[0] == request
            and receipt["decision"] ==
                "native-banner-protected-merge-observed-no-write"
            and receipt["mergeSha"] == merge_sha
            and packet["mergedPr"]["merge_commit_sha"] == merge_sha,
            "App protected merge did not bind native owner/base/head/main")

    def reject(label: str, tweak: Callable[[dict[str, Any]], None]) -> None:
        inputs: dict[str, Any] = {
            "owner_documents": copy.deepcopy(owner_documents),
            "fresh_reviewed": copy.deepcopy(fresh_reviewed),
            "observed_at": start + timedelta(minutes=4, seconds=10),
        }
        tweak(inputs)
        attempted: list[Any] = []
        try:
            complete_app_protected_merge(
                **inputs,
                submit=lambda intent: (
                    attempted.append(intent), ("HTTP/1.1 200 OK", response),
                )[1],
                observe_merged=observed,
            )
        except (KeyError, TypeError, ValueError):
            require(not attempted, "invalid owner/main reached App PUT: " + label)
            return
        raise AssertionError("unreviewed terminal reached App token: " + label)

    reject("unsigned owner source", lambda c:
           c["owner_documents"]["ownerIdentity"].update(userId=True))
    reject("different owner user ID", lambda c:
           c["owner_documents"]["ownerIdentity"].update(userId=9923))
    reject("stale App installation", lambda c:
           c["owner_documents"]["appIdentity"]["installation"].update(id=99))
    reject("moved protected main", lambda c:
           c["fresh_reviewed"]["mainRef"]["object"].update(sha="f" * 40))
    reject("owner approval vetoed", lambda c:
           c["fresh_reviewed"]["reviews"][0].update(state="DISMISSED"))
    reject("foreign review ID", lambda c:
           c["fresh_reviewed"]["reviews"][0].update(id=905))
    reject("different review actor", lambda c:
           c["fresh_reviewed"]["reviews"][0]["user"].update(id=9923))
    reject("stale reproof", lambda c:
           c.update(observed_at=start + timedelta(minutes=8)))
    reject("replayed UTC day", lambda c:
           c.update(observed_at=start + timedelta(days=1)))
    reject("smuggled owner secret", lambda c:
           c["owner_documents"].update(ownerToken="forbidden"))

    class HTTPResponse:
        version = 11
        reason = "OK"
        def __init__(self, body: bytes, status: int = 200):
            self.status, self.body = status, body
        def getheader(self, _key: str) -> None:
            return None
        def read(self, _max: int) -> bytes:
            return self.body

    class Connection:
        def __init__(self, reply: HTTPResponse):
            self.reply = reply
            self.requests: list[Any] = []
        def request(self, method: str, path: str, body: bytes,
                    headers: dict[str, str]) -> None:
            self.requests.append((method, path, body, headers))
        def getresponse(self) -> HTTPResponse:
            return self.reply
        def close(self) -> None:
            pass

    calls: list[Connection] = []
    def factory(_host: str, **_kwargs: Any) -> Connection:
        client = Connection(HTTPResponse(json.dumps(response).encode("utf-8")))
        calls.append(client)
        return client

    writer = ExactSelectedAppMergePut("fixture-scoped-token", factory)
    status, body = writer.submit(request)
    require(status == "HTTP/1.1 200 OK" and body == response
            and len(calls) == 1
            and calls[0].requests[0][:2] ==
                ("PUT", "/" + request["endpoint"])
            and b"fixture-scoped-token" not in calls[0].requests[0][2],
            "App terminal transport mutated outside exact reviewed endpoint")
    def reject_http(label: str, forged: Any, response_status: int,
                    result_bytes: bytes) -> None:
        current = ExactSelectedAppMergePut(
            "fixture-scoped-token",
            lambda *_a, **_kw: Connection(HTTPResponse(
                result_bytes, response_status,
            )),
        )
        try:
            current.submit(forged)
        except (TypeError, ValueError):
            return
        raise AssertionError("unbounded App merge HTTP accepted: " + label)

    bad = copy.deepcopy(request)
    bad["request"]["merge_method"] = "squash"
    reject_http("squash bypass", bad, 200, json.dumps(response).encode())
    bad = copy.deepcopy(request)
    bad["endpoint"] = "repos/portyu9/attacker/pulls/25/merge"
    reject_http("wrong repo", bad, 200, json.dumps(response).encode())
    bad = copy.deepcopy(request)
    bad["request"]["sha"] = "f" * 40
    reject_http("wrong branch head", bad, 200, json.dumps(response).encode())
    reject_http("HTTP 302 redirect", request, 302, json.dumps(response).encode())
    reject_http("duplicate JSON key", request, 200, b'{"sha":"a","sha":"b"}')
    reject_http("wrong merged boolean", request, 200,
                b'{"merged":false,"sha":"cccccccccccccccccccccccccccccccccccccccc"}')
    reject_http("oversize HTTP", request, 200, b" " * (MAX_RESPONSE + 1))
    print("native banner App terminal: exact numeric owner/veto/main checks, "
          "single ordinary SHA-guarded PUT, native protected two-parent main "
          "receipt and adversarial negatives PASS; workflow unconnected")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--owner-receipt", type=Path)
    parser.add_argument("--repository-id", type=int)
    parser.add_argument("--merge-out", type=Path)
    args = parser.parse_args()
    if args.self_test:
        require(all(getattr(args, n) is None for n in (
            "owner_receipt", "repository_id", "merge_out",
        )), "App merge self-test must never use live credentials")
        self_test()
        return 0
    require(args.owner_receipt is not None
            and type(args.repository_id) is int
            and args.repository_id > 0
            and args.merge_out is not None
            and os.environ.get("GITHUB_REPOSITORY") == "portyu9/portyu9"
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") in {
                "workflow_run", "repository_dispatch",
            },
            "App merger requires separate trusted main native run")
    app_token = os.environ.get("BANNER_SCOPED_APP_TOKEN")
    read_token = os.environ.get("GH_TOKEN")
    require(app_token is not None and read_token is not None
            and app_token != read_token,
            "selected App token must differ from the read credential")
    require(os.environ.get("BANNER_OWNER_TOKEN") is None,
            "owner token must never enter isolated App merge environment")
    owner_documents = observer.read_bounded(args.owner_receipt)
    require(type(owner_documents) is dict
            and set(owner_documents) == OWNER_KEYS,
            "owner receipt artifact missing exact unique data schema")
    app_identity = owner_documents["appIdentity"]
    require(type(app_identity) is dict
            and app_identity.get("expected_repository_id") ==
                args.repository_id,
            "App source does not bind independently known repository ID")
    now = datetime.now(timezone.utc).replace(microsecond=0)
    fresh_reviewed, decision = observer.observe(
        app_evidence=app_identity, token=read_token,
        observed_now=now, initial=owner_documents["initial"],
    )
    require(decision.get("decision") ==
            "exact-two-phase-owner-reviewed-banner-data-only",
            "exact native owner review was not freshly re-observed")
    subject = transaction.compile_transaction(
        "authenticated-review-receipt", owner_documents,
    )
    candidate = subject["prNumber"]
    def observe_merged(sha: str, number: int) -> dict[str, Any]:
        require(number == candidate,
                "postmerge native PR differs from the authenticated owner")
        root = f"{REPOSITORY}"
        paths = (
            f"{root}/pulls/{number}",
            f"{root}/commits/{sha}",
            f"{root}/git/ref/heads/main",
        )
        reader = FixedOriginRead(read_token, frozenset(paths))
        return {
            "mergedPr": reader.get(paths[0]),
            "mergeCommit": reader.get(paths[1]),
            "finalMainRef": reader.get(paths[2]),
            "observedAt": datetime.now(timezone.utc).replace(
                microsecond=0,
            ).isoformat(timespec="seconds").replace("+00:00", "Z"),
        }
    packet, receipt = complete_app_protected_merge(
        owner_documents=owner_documents, fresh_reviewed=fresh_reviewed,
        observed_at=datetime.now(timezone.utc).replace(microsecond=0),
        submit=ExactSelectedAppMergePut(app_token).submit,
        observe_merged=observe_merged,
    )
    observer.write_exclusive(args.merge_out, {
        "mergeEvidence": packet, "receipt": receipt,
    })
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
