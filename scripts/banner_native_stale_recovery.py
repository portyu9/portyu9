#!/usr/bin/env python3
"""Collect exact, read-only native evidence before a stale banner PR may be closed.

This module deliberately has NO write-capable GitHub transport. Its result is
only an observed, bounded decision, never permission to mutate without a
separate current-main/head/engagement lease and authenticated App identity.
"""
from __future__ import annotations

import argparse
import base64
import copy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from typing import Any

import banner_native_live_admission as admission
import banner_native_observer_cli as observer
import banner_native_rest_transport as rest
import banner_native_review_threads_transport as threads
import banner_native_snapshot_collector as collector
import independent_banner_candidate_contract as contract


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def pack_stale_decision(
    proof: dict[str, Any], *, number: int, main_sha: str,
    head_sha: str, head_ref: str, historical_base: str, utc_day: str,
    observed_now: datetime,
) -> dict[str, str | int]:
    """Preserve original authenticated owner review in the publisher packet.

    The privileged YAML consumes BOTH fields. Previously observe() silently
    dropped them even though the native close-eligibility contract proved them.
    """
    review_id = proof.get("ownerReviewId")
    reviewed_at = proof.get("ownerReviewSubmittedAt")
    require(type(review_id) is int and review_id >= 0
            and type(reviewed_at) is str,
            "native stale decision lost immutable owner review provenance")
    require((review_id == 0 and reviewed_at == "") or (
        review_id > 0
        and len(reviewed_at) == 20
        and reviewed_at[4] == "-" and reviewed_at[7] == "-"
        and reviewed_at[10] == "T" and reviewed_at[13] == ":"
        and reviewed_at[16] == ":" and reviewed_at.endswith("Z")
        and datetime.fromisoformat(reviewed_at.replace("Z", "+00:00"))
        <= observed_now),
        "native stale decision owner review ID/timestamp inconsistent")
    return {
        "decision": "stale-banner-candidate-comment-then-close-only",
        "prNumber": number, "mainSha": main_sha,
        "headSha": head_sha, "headRef": head_ref,
        "historicalBaseSha": historical_base,
        "utcDay": utc_day,
        "ownerReviewId": review_id,
        "ownerReviewSubmittedAt": reviewed_at,
    }


def observe(*, native_app: dict[str, Any], token: str,
            observed_now: datetime, client: Any = None,
            threads_reader: Any = None) -> dict[str, str | int]:
    """Verify unique App origin, complete native snapshots, and exact leases."""
    require(type(observed_now) is datetime
            and observed_now.tzinfo is not None
            and observed_now.utcoffset() == timezone.utc.utcoffset(observed_now)
            and observed_now.microsecond == 0,
            "stale banner recovery must use current second-resolution UTC")
    require(type(native_app) is dict and set(native_app) == observer.APP_KEYS,
            "stale banner recovery App identity shape changed")
    contract.verified_native_banner_app_identity(**native_app)
    require(type(token) is str and bool(token)
            and token.strip() == token
            and not any(char.isspace() for char in token),
            "stale banner recovery requires a separately scoped read token")
    api = rest.ReadOnlyGitHub(token) if client is None else client
    native_threads = (
        (lambda repo, number: threads.fetch_connection(repo, number, token=token))
        if threads_reader is None else threads_reader
    )
    first_main = collector.read_ref(api, "main")
    main_sha = first_main["object"]["sha"]
    open_prs, witness = rest.inventory(
        api, collector.PREFIX + "pulls?state=open&base=main", limit=99,
    )
    require(witness == {"totalCount": len(open_prs), "hasNextPage": False}
            and len(open_prs) < 100, "open native banner PR collection incomplete")
    choice = contract.select_read_only_banner_candidate(
        open_prs, current_main_sha=main_sha, utc_day=observed_now.date(),
        native_app=native_app,
    )
    state = choice["decision"]
    if state in {"no-open-banner-candidate",
                 "current-banner-candidate-requires-proof"}:
        require(collector.read_ref(api, "main") == first_main,
                "main advanced during no-action banner recovery")
        return {
            "decision": state, "mainSha": main_sha,
            "utcDay": observed_now.date().isoformat(),
        }
    require(state == "stale-banner-candidate-requires-proof",
            "unrecognized stale banner recovery decision")

    number = choice["prNumber"]
    head_ref = choice["headRef"]
    head_sha = choice["headSha"]
    pr = collector.read_object(api, f"pulls/{number}")
    commit = collector.read_object(api, f"commits/{head_sha}")
    parents = commit.get("parents")
    require(type(parents) is list and len(parents) == 1
            and type(parents[0]) is dict
            and type(parents[0].get("sha")) is str
            and contract.HEX40.fullmatch(parents[0]["sha"]) is not None,
            "historical banner candidate requires one authenticated parent")
    original_base = parents[0]["sha"]

    original_readme = collector.read_readme(api, original_base)
    proposed_readme = collector.read_readme(api, head_sha)
    current_readme = collector.read_readme(api, main_sha)
    files, files_witness = rest.inventory(
        api, collector.PREFIX + f"pulls/{number}/files",
        uniqueness="filename", limit=1,
    )
    reviews, reviews_witness = rest.inventory(
        api, collector.PREFIX + f"pulls/{number}/reviews", limit=100,
    )
    comments, comments_witness = rest.inventory(
        api, collector.PREFIX + f"issues/{number}/comments", limit=100,
    )
    thread_connection = native_threads(contract.REPOSITORY, number)
    require(files_witness == {"totalCount": 1, "hasNextPage": False}
            and reviews_witness == {"totalCount": len(reviews), "hasNextPage": False}
            and comments_witness == {"totalCount": len(comments), "hasNextPage": False},
            "stale PR file/review/comment evidence incomplete")
    head_native = collector.read_ref(api, head_ref)
    result = contract.verified_stale_banner_close_readiness(
        open_prs=open_prs, pr=pr, commit=commit, files=files,
        historical_base_sha=original_base,
        historical_readme=original_readme,
        proposed_readme=proposed_readme,
        live_main_sha=main_sha, live_main_readme=current_readme,
        utc_day=observed_now.date(), observed_now=observed_now,
        reviews=reviews, issue_comments=comments,
        review_threads=thread_connection,
        main_ref=first_main, candidate_ref=head_native,
        native_app=native_app,
    )
    require(result["decision"] == "stale-banner-candidate-comment-then-close-only"
            and result["prNumber"] == number
            and result["headSha"] == head_sha
            and result["historicalBaseSha"] == original_base
            and result["currentMainSha"] == main_sha,
            "native historical salvage authorization drifted")
    require(collector.read_ref(api, "main") == first_main
            and collector.read_ref(api, head_ref) == head_native,
            "banner ref advanced during exact historical salvage")
    second_open, second_witness = rest.inventory(
        api, collector.PREFIX + "pulls?state=open&base=main", limit=99,
    )
    require(second_witness == witness
            and second_open == open_prs,
            "open PR inventory changed before stale cleanup authorization")
    return pack_stale_decision(
        result, number=number, main_sha=main_sha, head_sha=head_sha,
        head_ref=head_ref, historical_base=original_base,
        utc_day=observed_now.date().isoformat(), observed_now=observed_now,
    )


def self_test() -> None:
    """Adversarially prove the classifier cannot dismiss current/unreviewed PRs."""
    original = admission.fixture()
    now = admission.exact_utc(original["observedAt"])
    identity = original["nativeApp"]
    normal = contract.select_read_only_banner_candidate(
        original["openPrs"], current_main_sha=original["mainSha"],
        utc_day=now.date(), native_app=identity,
    )
    require(normal["decision"] == "current-banner-candidate-requires-proof",
            "current banner candidate incorrectly classified stale")
    stale_sha = ("f" if original["mainSha"][0] != "f" else "e") * 40
    old = contract.select_read_only_banner_candidate(
        original["openPrs"], current_main_sha=stale_sha,
        utc_day=now.date(), native_app=identity,
    )
    require(old["decision"] == "stale-banner-candidate-requires-proof",
            "changed accepted main did not mark old PR stale")
    for rewrite in (
        lambda rows: rows[0].update(draft=True),
        lambda rows: rows[0]["head"].update(ref="automation/banner-rotation/invalid"),
        lambda rows: rows.append(copy.deepcopy(rows[0])),
        lambda rows: rows[0]["user"].update(login="attacker"),
    ):
        poisoned = copy.deepcopy(original["openPrs"])
        rewrite(poisoned)
        try:
            contract.select_read_only_banner_candidate(
                poisoned, current_main_sha=stale_sha,
                utc_day=now.date(), native_app=identity,
            )
        except ValueError:
            pass
        else:
            raise AssertionError("stale banner selector admitted tampered PR")
    # Actual native handoff, not an independently reconstructed schema:
    # a single genuine prior-day owner approval must reach BOTH jq consumers.
    prior = (datetime.now(timezone.utc) - timedelta(days=1)).replace(
        microsecond=0)
    stamp = prior.isoformat(timespec="seconds").replace("+00:00", "Z")
    params = dict(observed_now=datetime.now(timezone.utc),
                  number=19, main_sha="a" * 40,
                  head_sha="b" * 40,
                  head_ref=("automation/banner-rotation/" +
                            prior.date().isoformat() + "-" + "c" * 12),
                  historical_base="c" * 40,
                  utc_day=datetime.now(timezone.utc).date().isoformat())
    reviewed = {"ownerReviewId": 517, "ownerReviewSubmittedAt": stamp}
    packet = pack_stale_decision(reviewed, **params)
    require(set(packet) == {
                "decision", "prNumber", "mainSha", "headSha",
                "headRef", "historicalBaseSha", "utcDay",
                "ownerReviewId", "ownerReviewSubmittedAt"}
            and packet["ownerReviewId"] == reviewed["ownerReviewId"]
            and packet["ownerReviewSubmittedAt"] == reviewed["ownerReviewSubmittedAt"],
            "exact native approved owner evidence dropped by output packet")
    unreviewed = pack_stale_decision(
        {"ownerReviewId": 0, "ownerReviewSubmittedAt": ""}, **params)
    require(unreviewed["ownerReviewId"] == 0
            and unreviewed["ownerReviewSubmittedAt"] == "",
            "explicit zero-review recovery changed")
    for label, bad in (
        ("missing owner ID", {"ownerReviewSubmittedAt": reviewed["ownerReviewSubmittedAt"]}),
        ("missing owner date", {"ownerReviewId": reviewed["ownerReviewId"]}),
        ("boolean ID", {"ownerReviewId": True,
                        "ownerReviewSubmittedAt": reviewed["ownerReviewSubmittedAt"]}),
        ("downgraded approval", {"ownerReviewId": reviewed["ownerReviewId"],
                                 "ownerReviewSubmittedAt": ""}),
        ("spurious review", {"ownerReviewId": 0,
                             "ownerReviewSubmittedAt": reviewed["ownerReviewSubmittedAt"]}),
        ("malformed UTC", {"ownerReviewId": reviewed["ownerReviewId"],
                           "ownerReviewSubmittedAt": "not-utc"}),
    ):
        try:
            pack_stale_decision(bad, **params)
        except (ValueError, TypeError):
            pass
        else:
            raise AssertionError("stale owner review handoff accepted " + label)

    # Cross the complete native REST/GraphQL observation boundary with
    # synthetic, source-generated GitHub evidence. This catches schema-loss
    # regressions *between* verified eligibility and the published JSON packet,
    # which isolated self-tests failed to detect in the October incident.
    sample = admission.fixture()
    old_pr = copy.deepcopy(sample["pr"])
    old_commit = copy.deepcopy(sample["commit"])
    old_files = copy.deepcopy(sample["files"])
    original_day = admission.exact_utc(sample["observedAt"]).date()
    current_day = original_day + timedelta(days=1)
    replay_now = datetime.combine(
        current_day, datetime.min.time(), tzinfo=timezone.utc).replace(hour=12)
    current_main = "d" * 40
    old_head = old_pr["head"]["sha"]
    old_base = old_pr["base"]["sha"]
    original_readme = sample["acceptedReadme"]
    old_candidate_readme = sample["proposedReadme"]
    catalog = contract.approved.load_catalog()
    current_readme = contract.approved.propose(
        original_readme, contract.approved.chosen(current_day, catalog), catalog)
    require(current_readme != original_readme,
            "cross-boundary native fixture did not advance accepted artwork")
    from automation_governed_bot_review_gate import review_marker
    owner_review = {
        "id": 517, "state": "APPROVED", "user": {"login": "portyu9"},
        "commit_id": old_head, "body": review_marker(old_base, old_head),
        "submitted_at": (
            replay_now - timedelta(days=1, minutes=10)
        ).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }
    prefix = collector.PREFIX
    def content_document(source: str) -> dict[str, Any]:
        encoded = source.encode("utf-8")
        return {
            "name": "README.md", "path": "README.md", "type": "file",
            "encoding": "base64", "size": len(encoded),
            "sha": contract.blob_sha(source),
            "content": base64.b64encode(encoded).decode("ascii"),
        }

    refs = {
        prefix + "git/ref/heads/main": {
            "ref": "refs/heads/main",
            "object": {"type": "commit", "sha": current_main},
        },
        prefix + "git/ref/heads/" + old_pr["head"]["ref"]: {
            "ref": "refs/heads/" + old_pr["head"]["ref"],
            "object": {"type": "commit", "sha": old_head},
        },
    }
    values = {
        **refs,
        prefix + "pulls?state=open&base=main&per_page=100&page=1": [old_pr],
        prefix + f"pulls/{old_pr['number']}": old_pr,
        prefix + f"commits/{old_head}": old_commit,
        prefix + f"contents/README.md?ref={old_base}":
            content_document(original_readme),
        prefix + f"contents/README.md?ref={old_head}":
            content_document(old_candidate_readme),
        prefix + f"contents/README.md?ref={current_main}":
            content_document(current_readme),
        prefix + f"pulls/{old_pr['number']}/files?per_page=100&page=1":
            old_files,
        prefix + f"pulls/{old_pr['number']}/reviews?per_page=100&page=1":
            [owner_review],
        prefix + f"issues/{old_pr['number']}/comments?per_page=100&page=1": [],
    }
    class NativeReplay:
        def __init__(self, responses: dict[str, Any]):
            self.responses = responses
            self.requests: list[str] = []
        def get(self, endpoint: str) -> tuple[Any, None]:
            self.requests.append(endpoint)
            require(endpoint in self.responses,
                    "native replay unexpectedly accessed an unreviewed endpoint")
            return copy.deepcopy(self.responses[endpoint]), None

    def read_threads(repository: str, number: int) -> dict[str, Any]:
        require(repository == contract.REPOSITORY
                and number == old_pr["number"],
                "native GraphQL replay changed repository or PR identity")
        return copy.deepcopy(sample["reviewThreads"])

    replay = NativeReplay(values)
    observed = observe(
        native_app=sample["nativeApp"], token="synthetic-read-only",
        observed_now=replay_now, client=replay, threads_reader=read_threads)
    require(observed["decision"] == "stale-banner-candidate-comment-then-close-only"
            and observed["prNumber"] == old_pr["number"]
            and observed["mainSha"] == current_main
            and observed["headSha"] == old_head
            and observed["ownerReviewId"] == owner_review["id"]
            and observed["ownerReviewSubmittedAt"] == owner_review["submitted_at"],
            "complete synthetic native replay lost publisher owner approval")
    require(replay.requests.count(prefix + "git/ref/heads/main") == 2
            and replay.requests.count(
                prefix + "git/ref/heads/" + old_pr["head"]["ref"]) == 2
            and replay.requests.count(
                prefix + "pulls?state=open&base=main&per_page=100&page=1") == 2,
            "native replay did not repeat immutable main/head/PR inventory")
    zero = copy.deepcopy(values)
    zero[prefix + f"pulls/{old_pr['number']}/reviews?per_page=100&page=1"] = []
    zero_packet = observe(
        native_app=sample["nativeApp"], token="synthetic-read-only",
        observed_now=replay_now, client=NativeReplay(zero),
        threads_reader=read_threads)
    require(zero_packet["ownerReviewId"] == 0
            and zero_packet["ownerReviewSubmittedAt"] == "",
            "complete zero-review historical candidate failed to transmit")

    for label, mutated in (
        ("competing user comment", lambda obj: obj[
            prefix + f"issues/{old_pr['number']}/comments?per_page=100&page=1"
        ].append({"id": 99})),
        ("changed owner approval", lambda obj: obj[
            prefix + f"pulls/{old_pr['number']}/reviews?per_page=100&page=1"
        ][0].update(body="Unbound owner review")),
        ("new main ref", lambda obj: obj[prefix + "git/ref/heads/main"][
            "object"].update(sha="e" * 40)),
        ("unrecognized head", lambda obj: obj[
            prefix + f"pulls/{old_pr['number']}"
        ]["head"].update(sha="e" * 40)),
    ):
        bad = copy.deepcopy(values)
        mutated(bad)
        try:
            observe(native_app=sample["nativeApp"],
                    token="synthetic-read-only",
                    observed_now=replay_now, client=NativeReplay(bad),
                    threads_reader=read_threads)
        except (ValueError, KeyError, TypeError):
            pass
        else:
            raise AssertionError(
                "cross-boundary native observation admitted " + label)

    # Lock the actual privileged publisher's post-comment transaction to
    # the same historical-or-current base predicate already authorized by
    # verified_stale_banner_close_readiness. GitHub can retain the original
    # base SHA after main advances; requiring only current main would leave
    # a comment on the old PR and then fail, blocking autonomous recovery.
    workflow = (Path(__file__).resolve().parents[1] /
                ".github/workflows/approved-banner-rotation.yml").read_text(
                    encoding="utf-8")
    require(workflow.count('jq -er .ownerReviewId') == 1
            and workflow.count('jq -r .ownerReviewSubmittedAt') == 1,
            "privileged publisher owner-review handoff schema drifted")
    guard = (
        '.state == "open" and .merged == false and .head.sha == $sha and '
        '.base.ref == "main" and '
        '(.base.sha == $historical or .base.sha == $main)'
    )
    require(
        workflow.count(guard) == 1
        and workflow.count('--arg historical "$HISTORICAL_BASE"') == 1
        and workflow.index('COMMENT_ID="$(jq') < workflow.index(guard)
        < workflow.index('CLOSE_RESPONSE='),
        "actual post-comment stale-close gate lost exact historical/current base",
    )
    print("stale banner recovery classifier: current/stale, guarded post-comment "
          "historical/main, and adversarial fixtures PASS")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--app-evidence", type=Path)
    parser.add_argument("--decision-out", type=Path)
    args = parser.parse_args()
    if args.self_test:
        require(args.app_evidence is None and args.decision_out is None,
                "self-test cannot ingest trusted credentials or native data")
        self_test()
        return 0
    require(args.app_evidence is not None and args.decision_out is not None,
            "stale native recovery requires exact App evidence and new output")
    token = os.environ.get("GH_TOKEN")
    require(token is not None, "read-only GH_TOKEN not provided")
    identity = observer.read_bounded(args.app_evidence)
    result = observe(
        native_app=identity, token=token,
        observed_now=datetime.now(timezone.utc).replace(microsecond=0),
    )
    observer.write_exclusive(args.decision_out, result)
    # Never output raw PR inventories, secrets or bearer tokens.
    print(result["decision"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
