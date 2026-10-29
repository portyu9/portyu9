#!/usr/bin/env python3
"""Exact native owner review HTTP-200 writer, NOT an activated workflow.

Future owner-only trusted-main caller must independently attest that the
selected-App evidence originated in a genuine, trusted, successful publisher
run and that the wake is a genuine completed native CI run. This program
MUST execute only under portyu9-review-identity with the owner's distinct
token. The App merger/token belongs to another environment, never this job.

One verified current UTC candidate -> one exact native POST review -> a fresh
complete two-phase owner-ID-bound native review re-observation. Ref/status
races and bad HTTP receipts fail closed: no merge or checks are published.
No pipeline currently invokes this script, so its code alone grants NO
production owner review authority. Prior capability/TCB authorization is
required before connecting it to a trusted workflow.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
from typing import Any, Callable

import banner_native_live_admission as admission
import banner_native_observer_cli as observer
import banner_native_owner_identity_source as owner_source
import banner_native_publisher_run_artifact as producer_origin
import banner_native_owner_review_transaction_contract as owner_contract
import banner_native_transaction_artifact_cli as transaction
from banner_native_authenticated_app_source import (
    FixedOriginRead, REPOSITORY, unique_object,
)

HOST = "api.github.com"
MAX_RESPONSE_BYTES = 131_072
OWNER_PATH = re.compile(r"^repos/portyu9/portyu9/pulls/([1-9][0-9]*)/reviews$")
FRESH_TTL = timedelta(seconds=75)


def read_bounded_source_zip(path: Path) -> bytes:
    """Read one untrusted archive without symlink traversal or unbounded I/O."""
    require(type(path) is Path and path.is_file() and not path.is_symlink(),
            "scheduled publisher ZIP source is not a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        require(stat.S_ISREG(metadata.st_mode)
                and 0 < metadata.st_size <= producer_origin.MAX_ARCHIVE,
                "scheduled publisher archive exceeds exact input budget")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            archive = stream.read(producer_origin.MAX_ARCHIVE + 1)
    finally:
        os.close(descriptor)
    require(0 < len(archive) <= producer_origin.MAX_ARCHIVE
            and len(archive) == metadata.st_size,
            "scheduled publisher archive changed while being read")
    return archive


def verified_scheduled_review_source(
    *, documents: Any, wake: Any, source_run: Any,
    artifact_inventory: Any, archive: bytes, observed_at: datetime,
    expected_repository_id: int,
) -> dict[str, str | int]:
    """Prove exact native CI wake AND independent scheduled App source."""
    require(type(documents) is dict
            and set(documents) == {"initial", "appIdentity", "ownerIdentity"}
            and type(wake) is dict
            and wake.get("decision") == "exact-native-banner-wake-observed-no-write",
            "reviewer missing exact independent CI wake or identity inputs")
    before = documents["initial"]
    require(type(before) is dict and type(wake.get("prNumber")) is int
            and type(wake.get("baseSha")) is str
            and type(wake.get("headSha")) is str
            and type(wake.get("headRef")) is str,
            "reviewer wake/subject malformed")
    evidence = producer_origin.attest(
        source_run=source_run, artifact_inventory=artifact_inventory,
        archive=archive, snapshot=before, observed_now=observed_at,
        expected_repository_id=expected_repository_id,
    )
    require(evidence["decision"] ==
            "authenticated-native-banner-schedule-app-origin-data-only"
            and evidence["prNumber"] == wake["prNumber"]
            and evidence["baseSha"] == wake["baseSha"]
            and evidence["headSha"] == wake["headSha"]
            and before["pr"]["head"]["ref"] == wake["headRef"]
            and evidence["repositoryId"] ==
                documents["appIdentity"]["expected_repository_id"]
            and evidence["ownerEligibleDay"] == observed_at.date().isoformat(),
            "selected App publisher source/wake/owner identity changed")
    require(before["nativeApp"] == documents["appIdentity"],
            "reviewer identity differs from authenticated publisher artifact")
    return evidence


def complete_provenance_bound_review(
    *, documents: Any, wake: Any, source_run: Any,
    artifact_inventory: Any, archive: bytes, observed_at: datetime,
    expected_repository_id: int,
    submit: Callable[[dict[str, Any]], tuple[str, dict[str, Any]]],
    observe_after: Callable[[dict[str, Any]], Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    # Fail closed BEFORE the first owner-token POST. This is a production
    # prerequisite, not a caller-supplied boolean or an artifact signature.
    verified_scheduled_review_source(
        documents=documents, wake=wake, source_run=source_run,
        artifact_inventory=artifact_inventory, archive=archive,
        observed_at=observed_at,
        expected_repository_id=expected_repository_id,
    )
    return complete_review(
        documents=documents, observed_at=observed_at,
        submit=submit, observe_after=observe_after,
    )


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


class ExactOwnerReviewPost:
    """One direct HTTPS POST to the exact previously admitted owner-review PR."""

    def __init__(self, token: str,
                 connection_factory: Callable[..., Any] | None = None):
        require(type(token) is str and len(token) >= 8
                and not any(c.isspace() for c in token),
                "isolated human owner token is missing or malformed")
        self.__token = token
        self.__factory = connection_factory or http.client.HTTPSConnection

    def submit(self, intent: Any) -> tuple[str, dict[str, Any]]:
        require(type(intent) is dict
                and set(intent) == {"endpoint", "request", "prNumber",
                                    "baseSha", "headSha"},
                "native owner writer input shape is not the exact request")
        endpoint = intent["endpoint"]
        request = intent["request"]
        require(type(endpoint) is str
                and OWNER_PATH.fullmatch(endpoint) is not None
                and type(intent["prNumber"]) is int
                and intent["prNumber"] > 0
                and endpoint == (
                    f"repos/portyu9/portyu9/pulls/{intent['prNumber']}/reviews"
                ), "native owner writer endpoint is not the exact PR")
        require(type(intent["baseSha"]) is str
                and type(intent["headSha"]) is str
                and admission.HEX40.fullmatch(intent["baseSha"]) is not None
                and admission.HEX40.fullmatch(intent["headSha"]) is not None
                and intent["baseSha"] != intent["headSha"]
                and type(request) is dict
                and set(request) == {"event", "commit_id", "body"}
                and request["event"] == "APPROVE"
                and request["commit_id"] == intent["headSha"]
                and request["body"] == owner_contract.review_marker(
                    intent["baseSha"], intent["headSha"]
                ),
                "native owner write is not one exact approved-head marker")
        payload = json.dumps(request, sort_keys=True,
                             separators=(",", ":")).encode("utf-8")
        require(len(payload) <= 4096,
                "native owner review request unexpectedly large")
        connection = self.__factory(
            HOST, timeout=15, context=ssl.create_default_context()
        )
        try:
            connection.request("POST", "/" + endpoint, body=payload, headers={
                "Authorization": "Bearer " + self.__token,
                "Accept": "application/vnd.github+json",
                "Content-Type": "application/json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "portyu9-banner-owner-exact-review",
            })
            reply = connection.getresponse()
            require(reply.status == 200
                    and reply.version in (10, 11)
                    and reply.getheader("Location") is None
                    and reply.getheader("Link") is None,
                    "native owner approval must return direct HTTP 200")
            raw = reply.read(MAX_RESPONSE_BYTES + 1)
            reason = reply.reason
            version = "1.1" if reply.version == 11 else "1.0"
        finally:
            connection.close()
        require(len(raw) <= MAX_RESPONSE_BYTES
                and type(reason) is str
                and bool(reason)
                and re.fullmatch(r"[A-Za-z0-9 ._-]{1,80}", reason) is not None,
                "native owner review HTTP body or status line malformed")
        try:
            response = json.loads(
                raw.decode("utf-8"), object_pairs_hook=unique_object,
            )
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("native owner review response not unique-key JSON") from exc
        require(type(response) is dict,
                "native owner review response must be one JSON object")
        return f"HTTP/{version} 200 {reason}", response


def complete_review(
    *, documents: Any, observed_at: datetime,
    submit: Callable[[dict[str, Any]], tuple[str, dict[str, Any]]],
    observe_after: Callable[[dict[str, Any]], Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Do precisely one review mutation, then independently verify the receipt.

    Only the caller can authenticate publisher evidence, the wake, HTTPS
    read-token provenance and isolated owner-token origin. If the post succeeds
    but subsequent native ref/review checks fail, STOP without a merge.
    """
    require(type(observed_at) is datetime
            and observed_at.tzinfo is not None
            and observed_at.utcoffset() == timedelta(),
            "owner writer observation clock must be UTC")
    require(type(documents) is dict and
            set(documents) == {
                "initial", "appIdentity", "ownerIdentity",
            }, "owner writer requires exactly three verified inputs")
    intent = transaction.compile_transaction(
        "authenticated-review-request", documents,
    )
    initial = documents["initial"]
    start = admission.exact_utc(initial["observedAt"])
    require(timedelta() <= observed_at - start <= FRESH_TTL
            and observed_at.date() == start.date(),
            "owner review pre-write snapshot expired or crossed UTC day")
    expected = intent["intent"]
    status, response = submit(expected)
    require(type(status) is str
            and owner_contract.HTTP_200.fullmatch(status) is not None
            and type(response) is dict
            and type(response.get("user")) is dict
            and type(response["user"].get("id")) is int
            and response["user"]["id"] == intent["identityBinding"]["ownerUserId"],
            "owner HTTP approval is not from the authenticated numeric owner")
    reviewed = observe_after(initial)
    artifacts = {
        **documents, "reviewed": reviewed,
        "ownerStatus": status, "ownerResponse": response,
    }
    receipt = transaction.compile_transaction(
        "authenticated-review-receipt", artifacts,
    )
    require(receipt["prNumber"] == expected["prNumber"]
            and receipt["baseSha"] == expected["baseSha"]
            and receipt["headSha"] == expected["headSha"]
            and receipt["ownerUserId"] == intent["identityBinding"]["ownerUserId"],
            "native approval actor or subject changed during post")
    return artifacts, receipt


def self_test() -> None:
    import copy

    before = admission.fixture()
    start = admission.exact_utc(before["observedAt"])
    app = copy.deepcopy(before["nativeApp"])
    owner = {
        "login": owner_contract.REVIEW_LOGIN,
        "userId": 9922,
        "repositoryId": app["expected_repository_id"],
        "repository": "portyu9/portyu9",
        "defaultBranch": "main",
    }
    documents = {
        "initial": before, "appIdentity": app,
        "ownerIdentity": owner,
    }
    prepared = transaction.compile_transaction(
        "authenticated-review-request", documents,
    )["intent"]
    review = {
        "id": 713, "user": {"login": owner_contract.REVIEW_LOGIN, "id": 9922},
        "state": "APPROVED", "commit_id": prepared["headSha"],
        "body": prepared["request"]["body"],
        "submitted_at": (start + timedelta(seconds=40)).isoformat(
            timespec="seconds",
        ).replace("+00:00", "Z"),
    }
    after = copy.deepcopy(before)
    after["observedAt"] = (start + timedelta(seconds=60)).isoformat(
        timespec="seconds",
    ).replace("+00:00", "Z")
    after["reviews"].append(copy.deepcopy(review))
    after["completeness"]["reviews"]["totalCount"] = 1
    posted: list[dict[str, Any]] = []

    def submit(intent: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        posted.append(copy.deepcopy(intent))
        return "HTTP/1.1 200 OK", copy.deepcopy(review)

    artifact, receipt = complete_review(
        documents=documents, observed_at=start + timedelta(seconds=10),
        submit=submit, observe_after=lambda initial: copy.deepcopy(after),
    )
    require(len(posted) == 1 and posted[0] == prepared
            and artifact["ownerResponse"]["id"] == review["id"]
            and receipt["ownerUserId"] == 9922
            and receipt["decision"] ==
                "dual-source-banner-owner-review-receipt-no-merge",
            "positive owner write did not re-prove exact HTTP/native approval")

    # Exercise the actual ZIP/run/App/CI pre-write binding, not merely the
    # request transport. Every forged origin is rejected before submit.
    import hashlib
    import io
    import zipfile
    import tempfile

    produced_at = start - timedelta(minutes=2)
    origin_packet = producer_origin.build(
        app_evidence=app, pr=before["pr"], base_sha=before["mainSha"],
        run_id=77, observed_at=produced_at,
    )
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as zipout:
        zipout.writestr(
            producer_origin.ARTIFACT_FILE,
            json.dumps(origin_packet, sort_keys=True, separators=(",", ":")),
        )
    zip_data = stream.getvalue()
    def iso(moment: datetime) -> str:
        return moment.isoformat(timespec="seconds").replace("+00:00", "Z")

    source_run = {
        "id": 77, "name": producer_origin.WORKFLOW,
        "path": producer_origin.WORKFLOW_PATH,
        "event": "schedule", "status": "completed",
        "conclusion": "success", "run_attempt": 1,
        "head_branch": "main", "head_sha": before["mainSha"],
        "repository": {"full_name": "portyu9/portyu9"},
        "head_repository": {"full_name": "portyu9/portyu9"},
        "actor": {"login": "portyu9"},
        "triggering_actor": {"login": "portyu9"},
        "created_at": iso(start - timedelta(minutes=4)),
        "updated_at": iso(start - timedelta(minutes=1)),
    }
    native_artifacts = {
        "total_count": 1,
        "artifacts": [{
            "id": 88, "name": producer_origin.ARTIFACT_NAME,
            "size_in_bytes": len(zip_data),
            "expired": False,
            "digest": "sha256:" + hashlib.sha256(zip_data).hexdigest(),
            "archive_download_url":
                "https://api.github.com/repos/portyu9/portyu9/actions/artifacts/88/zip",
            "created_at": iso(produced_at),
            "expires_at": iso(start + timedelta(days=1)),
            "workflow_run": {
                "id": 77, "repository_id": 14, "head_repository_id": 14,
                "head_branch": "main", "head_sha": before["mainSha"],
            },
        }],
    }
    exact_wake = {
        "decision": "exact-native-banner-wake-observed-no-write",
        "prNumber": before["pr"]["number"],
        "baseSha": before["mainSha"],
        "headSha": before["pr"]["head"]["sha"],
        "headRef": before["pr"]["head"]["ref"],
    }
    source_inputs = {
        "documents": documents, "wake": exact_wake,
        "source_run": source_run,
        "artifact_inventory": native_artifacts, "archive": zip_data,
        "observed_at": start + timedelta(seconds=10),
        "expected_repository_id": 14,
    }
    production_proof = verified_scheduled_review_source(**source_inputs)
    require(production_proof["producerRunId"] == 77
            and production_proof["prNumber"] == before["pr"]["number"],
            "independent scheduled App provenance did not bind")
    submitted: list[dict[str, Any]] = []
    artifacts2, receipt2 = complete_provenance_bound_review(
        **source_inputs,
        submit=lambda req: (submitted.append(req),
                            ("HTTP/1.1 200 OK", copy.deepcopy(review)))[1],
        observe_after=lambda old: copy.deepcopy(after),
    )
    require(len(submitted) == 1 and submitted[0] == prepared
            and artifacts2["ownerResponse"]["id"] == review["id"]
            and receipt2["ownerUserId"] == 9922,
            "authentic scheduled publisher did not preserve owner receipt")

    def reject_source(label: str, mutate: Callable[[dict[str, Any]], None]) -> None:
        case = copy.deepcopy(source_inputs)
        mutate(case)
        attempted: list[Any] = []
        try:
            complete_provenance_bound_review(
                **case,
                submit=lambda req: (attempted.append(req),
                                    ("HTTP/1.1 200 OK", review))[1],
                observe_after=lambda old: copy.deepcopy(after),
            )
        except (KeyError, TypeError, ValueError):
            require(not attempted, "owner POST before source veto: " + label)
            return
        raise AssertionError("untrusted publisher reached owner token: " + label)

    reject_source("manual publisher trigger",
                  lambda c: c["source_run"].update(event="workflow_dispatch"))
    reject_source("replayed publisher attempt",
                  lambda c: c["source_run"].update(run_attempt=2))
    reject_source("different producer main",
                  lambda c: c["source_run"].update(head_sha="f" * 40))
    reject_source("wrong producer actor",
                  lambda c: c["source_run"]["actor"].update(login="attacker"))
    reject_source("tampered publisher ZIP",
                  lambda c: c.update(archive=b"untrusted"))
    reject_source("wrong repo-bound artifact ID",
                  lambda c: c["artifact_inventory"]["artifacts"][0]
                      ["workflow_run"].update(repository_id=99))
    reject_source("wrong native workflow wake head",
                  lambda c: c["wake"].update(headSha="f" * 40))
    reject_source("wrong owner source repository",
                  lambda c: c["documents"]["ownerIdentity"].update(
                      repositoryId=99))
    reject_source("missing source artifact",
                  lambda c: c["artifact_inventory"].update(artifacts=[]))

    with tempfile.TemporaryDirectory(prefix="banner-owner-zip-") as location:
        path = Path(location) / "native.zip"
        path.write_bytes(zip_data)
        require(read_bounded_source_zip(path) == zip_data,
                "bounded real ZIP file read did not preserve exact bytes")
        link = Path(location) / "link.zip"
        link.symlink_to(path)
        try:
            read_bounded_source_zip(link)
        except ValueError:
            pass
        else:
            raise AssertionError("symlink source ZIP crossed owner boundary")
        path.write_bytes(b"x" * (producer_origin.MAX_ARCHIVE + 1))
        try:
            read_bounded_source_zip(path)
        except ValueError:
            pass
        else:
            raise AssertionError("oversized source ZIP crossed owner boundary")

    def no_post(label: str, data: Any, when: datetime) -> None:
        counter: list[Any] = []
        try:
            complete_review(
                documents=data, observed_at=when,
                submit=lambda req: (counter.append(req), ("HTTP/1.1 200 OK", review))[1],
                observe_after=lambda initial: copy.deepcopy(after),
            )
        except (KeyError, TypeError, ValueError):
            require(not counter, "owner approval issued before failure: " + label)
            return
        raise AssertionError("inadmissible owner write did not fail: " + label)

    no_post("UTC rollover", documents, start + timedelta(days=1))
    no_post("stale snapshot", documents, start + timedelta(seconds=76))
    no_post("clock reversal", documents, start - timedelta(seconds=1))
    forged = copy.deepcopy(documents)
    forged["ownerIdentity"]["userId"] = True
    no_post("boolean owner ID", forged, start + timedelta(seconds=10))
    forged = copy.deepcopy(documents)
    forged["appIdentity"]["installation"]["id"] += 1
    no_post("wrong App installation", forged, start + timedelta(seconds=10))
    forged = copy.deepcopy(documents)
    forged["initial"]["mainRef"]["object"]["sha"] = "f" * 40
    no_post("moved main", forged, start + timedelta(seconds=10))
    forged = copy.deepcopy(documents)
    forged["token"] = "credential"
    no_post("smuggled token", forged, start + timedelta(seconds=10))

    class Response:
        version = 11
        reason = "OK"
        def __init__(self, body: bytes, status: int = 200):
            self.status, self.body = status, body
        def getheader(self, _key: str) -> None:
            return None
        def read(self, _limit: int) -> bytes:
            return self.body

    class Connection:
        def __init__(self, response: Response):
            self.response = response
            self.calls: list[tuple[str, str, bytes, dict[str, str]]] = []
        def request(self, method: str, path: str, body: bytes,
                    headers: dict[str, str]) -> None:
            self.calls.append((method, path, body, headers))
        def getresponse(self) -> Response:
            return self.response
        def close(self) -> None:
            pass

    expected_body = json.dumps(review, separators=(",", ":")).encode("utf-8")
    connections: list[Connection] = []
    def factory(_host: str, **_kwargs: Any) -> Connection:
        client = Connection(Response(expected_body))
        connections.append(client)
        return client

    writer = ExactOwnerReviewPost("fixture-token", factory)
    status, obj = writer.submit(prepared)
    require(status == "HTTP/1.1 200 OK" and obj == review
            and len(connections) == 1
            and connections[0].calls[0][0:2] ==
                ("POST", "/" + prepared["endpoint"])
            and b"fixture-token" not in connections[0].calls[0][2],
            "owner POST endpoint/method/body and status drifted")

    def reject_transport(label: str, intent: Any, response: Response) -> None:
        writer = ExactOwnerReviewPost(
            "fixture-token",
            lambda *_a, **_kw: Connection(response),
        )
        try:
            writer.submit(intent)
        except (TypeError, ValueError):
            return
        raise AssertionError("unsafe owner POST accepted: " + label)

    bad = copy.deepcopy(prepared)
    bad["request"]["event"] = "REQUEST_CHANGES"
    reject_transport("non-approved event", bad, Response(expected_body))
    bad = copy.deepcopy(prepared)
    bad["endpoint"] = "repos/portyu9/attacker/pulls/123/reviews"
    reject_transport("escaped repository", bad, Response(expected_body))
    bad = copy.deepcopy(prepared)
    bad["request"]["commit_id"] = "a" * 40
    reject_transport("wrong commit", bad, Response(expected_body))
    bad = copy.deepcopy(prepared)
    bad["request"]["body"] = "unreviewed body"
    reject_transport("wrong review marker", bad, Response(expected_body))
    reject_transport("HTTP 302", prepared, Response(expected_body, 302))
    reject_transport("duplicate JSON key", prepared,
                     Response(b'{"id":1,"id":2}'))
    reject_transport("oversize response", prepared,
                     Response(b" " * (MAX_RESPONSE_BYTES + 1)))
    reject_transport("non-object response", prepared, Response(b"[]"))
    print("native banner owner POST: exact one approved-head HTTPS write, "
          "numeric owner HTTP+fresh inventory receipt, no premature post, "
          "direct HTTP 200 and adversarial negatives PASS; workflow disabled")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--app-evidence", type=Path)
    parser.add_argument("--producer-run-id", type=int)
    parser.add_argument("--app-origin-archive", type=Path)
    parser.add_argument("--wake-event", type=Path)
    parser.add_argument("--repository-id", type=int)
    parser.add_argument("--receipt-out", type=Path)
    args = parser.parse_args()
    if args.self_test:
        require(all(getattr(args, key) is None for key in (
            "app_evidence", "wake_event", "repository_id", "receipt_out",
            "producer_run_id", "app_origin_archive",
        )), "owner POST self-test cannot use live paths or credentials")
        self_test()
        return 0
    require(args.app_evidence is not None and args.wake_event is not None
            and type(args.producer_run_id) is int
            and args.producer_run_id > 0
            and args.app_origin_archive is not None
            and type(args.repository_id) is int
            and args.repository_id > 0 and args.receipt_out is not None
            and os.environ.get("GITHUB_REPOSITORY") == "portyu9/portyu9"
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_run",
            "owner POST requires trusted-main native workflow_run environment")
    owner_token = os.environ.get("BANNER_OWNER_TOKEN")
    read_token = os.environ.get("GH_TOKEN")
    require(owner_token is not None and read_token is not None
            and owner_token != read_token,
            "native owner token must be isolated from repository read token")
    native_app = observer.read_bounded(args.app_evidence)
    wake_event = observer.read_bounded(args.wake_event)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    initial, wake = observer.observe_native_wake(
        app_evidence=native_app, token=read_token,
        event=wake_event, observed_now=now,
    )
    require(wake["decision"] == "exact-native-banner-wake-observed-no-write",
            "actual native banner completion did not match accepted candidate")
    # The run is independently authenticated by a separate read-only GitHub
    # credential and a closed exact endpoint allowlist. A JSON artifact or
    # unverified caller-supplied run metadata cannot authorize an owner POST.
    source_path = f"{REPOSITORY}/actions/runs/{args.producer_run_id}"
    reader = FixedOriginRead(
        read_token,
        frozenset({source_path, source_path + "/artifacts"}),
    )
    authenticated_run = reader.get(source_path)
    authenticated_artifacts = reader.get(source_path + "/artifacts")
    source_archive = read_bounded_source_zip(args.app_origin_archive)
    own = owner_source.collect(
        get_owner=FixedOriginRead(owner_token, frozenset({"/user"})).get,
        get_repository=FixedOriginRead(read_token, frozenset({REPOSITORY})).get,
        expected_repository_id=args.repository_id,
    )
    documents = {
        "initial": initial, "appIdentity": native_app, "ownerIdentity": own,
    }

    def observe_after(_before: dict[str, Any]) -> dict[str, Any]:
        after, verdict = observer.observe(
            app_evidence=native_app, token=read_token,
            observed_now=datetime.now(timezone.utc).replace(microsecond=0),
            initial=initial,
        )
        require(verdict["decision"] ==
                "exact-two-phase-owner-reviewed-banner-data-only",
                "actual owner review did not survive full native re-observation")
        return after

    artifacts, receipt = complete_provenance_bound_review(
        documents=documents,
        wake=wake,
        source_run=authenticated_run,
        artifact_inventory=authenticated_artifacts,
        archive=source_archive,
        expected_repository_id=args.repository_id,
        observed_at=datetime.now(timezone.utc).replace(microsecond=0),
        submit=ExactOwnerReviewPost(owner_token).submit,
        observe_after=observe_after,
    )
    # Only credential-free native snapshots; never write credentials or
    # synthetic checks. The App merger is a distinct future trusted job.
    observer.write_exclusive(args.receipt_out, artifacts)
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
