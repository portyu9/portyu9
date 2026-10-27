"""Read-only, exact-subject admission for a future isolated banner reviewer.

This module consumes *authenticated and complete* native GitHub snapshots from a
separately reviewed trusted-main collector. A JSON file alone is not an authority
credential: callers must authenticate every response, validate pagination/link
headers, pin the expected installation and repository identities independently,
and re-read live refs before any future privileged action.

No network request, secret, review, status publication or repository mutation
exists here. It is deliberately NOT the production terminal merger.
"""

from __future__ import annotations

import argparse
import copy
import json
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import approved_banner_rotation as approved
import independent_banner_candidate_contract as contract
from automation_governed_bot_review_gate import review_decision, review_marker

HEX40 = contract.HEX40
BASIC = frozenset({"schemaVersion", "repository", "observedAt", "mainSha",
                   "nativeApp", "openPrs", "completeness"})
CURRENT = frozenset({"pr", "commit", "files", "acceptedReadme",
                     "proposedReadme", "checkRuns", "workflowRuns",
                     "reviews", "reviewThreads", "mainRef", "candidateRef"})
INVENTORIES = ("openPrs", "files", "checkRuns", "workflowRuns", "reviews")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def complete_inventory(envelope: Any, key: str, rows: Any, maximum: int) -> None:
    require(type(rows) is list and len(rows) <= maximum,
            f"{key} inventory is missing, oversized or malformed")
    witness = envelope.get(key) if type(envelope) is dict else None
    require(type(witness) is dict
            and set(witness) == {"totalCount", "hasNextPage"}
            and type(witness.get("totalCount")) is int
            and witness["totalCount"] == len(rows)
            and witness.get("hasNextPage") is False,
            f"{key} requires an exact complete authenticated page witness")


def exact_utc(value: Any) -> datetime:
    require(type(value) is str and value.endswith("Z"),
            "observation timestamp must be canonical UTC Z")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("malformed UTC observation timestamp") from exc
    require(parsed.tzinfo is not None and parsed.utcoffset() == timedelta(),
            "banner observation is not UTC")
    return parsed


def decide(snapshot: Any) -> dict[str, str | int]:
    """Conservatively classify *only* complete, trusted collector input.

    The result is planning evidence, NEVER a review or merge authorization.
    """
    require(type(snapshot) is dict and BASIC <= set(snapshot),
            "native banner snapshot missing required fields")
    require(snapshot.get("schemaVersion") == 1
            and snapshot.get("repository") == contract.REPOSITORY,
            "banner snapshot source/version is not canonical")
    now = exact_utc(snapshot.get("observedAt"))
    main_sha = snapshot.get("mainSha")
    require(type(main_sha) is str and HEX40.fullmatch(main_sha) is not None,
            "banner trusted main SHA invalid")
    native_app = snapshot.get("nativeApp")
    require(type(native_app) is dict
            and set(native_app) == {
                "installation", "bot_user", "expected_app_id",
                "expected_installation_id", "expected_repository_id",
            }, "native banner App pinned identity proof missing")
    contract.verified_native_banner_app_identity(**native_app)
    counts = snapshot.get("completeness")
    require(type(counts) is dict
            and set(counts) == set(INVENTORIES),
            "native banner inventory completeness map is not exact")
    open_prs = snapshot.get("openPrs")
    complete_inventory(counts, "openPrs", open_prs, 99)

    selected = contract.select_read_only_banner_candidate(
        open_prs, current_main_sha=main_sha, utc_day=now.date(),
        native_app=native_app,
    )
    state = selected["decision"]
    if state == "no-open-banner-candidate":
        require(set(snapshot) == BASIC, "no-candidate bundle contains unreviewed extras")
        return {"decision": "no-candidate-read-only", "mainSha": main_sha}
    if state == "stale-banner-candidate-requires-proof":
        require(set(snapshot) == BASIC, "stale candidate must use separate salvage path")
        return {
            "decision": "stale-requires-historical-salvage",
            "prNumber": selected["prNumber"],
            "headSha": selected["headSha"],
        }
    require(state == "current-banner-candidate-requires-proof"
            and set(snapshot) == BASIC | CURRENT,
            "current banner snapshot is incomplete or unrecognized")
    for name, maximum in (
        ("files", 1), ("checkRuns", 100),
        ("workflowRuns", 4), ("reviews", 100),
    ):
        complete_inventory(counts, name, snapshot[name], maximum)
    require(type(snapshot["pr"]) is dict
            and snapshot["pr"].get("number") == selected["prNumber"]
            and snapshot["pr"].get("head", {}).get("sha") == selected["headSha"],
            "selected candidate and detailed PR snapshot diverged")
    threads = snapshot["reviewThreads"]
    contract.verified_review_thread_connection(threads)
    contract.verified_native_ref_leases(
        main_ref=snapshot["mainRef"],
        candidate_ref=snapshot["candidateRef"], base_sha=main_sha,
        head_ref=selected["headRef"], head_sha=selected["headSha"],
    )
    result = contract.valid_candidate(
        pr=snapshot["pr"], commit=snapshot["commit"],
        files=snapshot["files"], accepted_readme=snapshot["acceptedReadme"],
        proposed_readme=snapshot["proposedReadme"],
        base_sha=main_sha, utc_day=now.date(), native_app=native_app,
    )
    contract.verified_required_check_snapshot(
        snapshot["checkRuns"], result["headSha"],
    )
    contract.verified_required_workflow_runs(
        snapshot["checkRuns"], snapshot["workflowRuns"],
        selected["headRef"], result["headSha"],
    )
    require(all(row["run_attempt"] == 1
                for row in snapshot["workflowRuns"]),
            "banner native validation was retried: no unattended authority")
    pr = snapshot["pr"]
    require(pr.get("mergeable") is True
            and pr.get("mergeable_state") == "clean",
            "banner candidate not in clean protected mergeable state")
    state = review_decision(snapshot["reviews"], main_sha, result["headSha"])
    if state in {"veto", "revoked"}:
        return {
            "decision": "owner-veto-or-revocation-no-action",
            "prNumber": result["prNumber"], "headSha": result["headSha"],
        }
    if state == "waiting":
        # Never overwrite a manual decisive owner review with an automated one.
        for row in snapshot["reviews"]:
            if (row["user"]["login"] == "portyu9"
                    and row["commit_id"] == result["headSha"]
                    and row["state"] in {"APPROVED", "CHANGES_REQUESTED"}):
                return {
                    "decision": "manual-owner-review-exists-no-action",
                    "prNumber": result["prNumber"],
                    "headSha": result["headSha"],
                }
        return {
            "decision": "exact-native-banner-owner-review-ready-read-only",
            "prNumber": result["prNumber"], "baseSha": main_sha,
            "headSha": result["headSha"],
        }
    require(state == "approved", "unsupported banner owner review decision")
    contract.terminal_banner_readiness(
        pr=pr, commit=snapshot["commit"], files=snapshot["files"],
        accepted_readme=snapshot["acceptedReadme"],
        proposed_readme=snapshot["proposedReadme"],
        base_sha=main_sha, utc_day=now.date(), observed_now=now,
        check_runs=snapshot["checkRuns"],
        workflow_runs=snapshot["workflowRuns"],
        reviews=snapshot["reviews"], review_threads=threads,
        main_ref=snapshot["mainRef"], candidate_ref=snapshot["candidateRef"],
        native_app=native_app,
    )
    return {
        "decision": "exact-owner-reviewed-banner-terminal-ready-read-only",
        "prNumber": result["prNumber"], "baseSha": main_sha,
        "headSha": result["headSha"],
    }


def fixture() -> dict[str, Any]:
    """Build deterministic real-artwork evidence with synthetic API identities."""
    root = Path(__file__).resolve().parents[1]
    before = (root / "README.md").read_text(encoding="utf-8")
    slots = approved.load_catalog()
    approved.validate_readme_state(before, slots)
    day = date(2026, 10, 27)
    for offset in range(30):
        candidate_day = day + timedelta(days=offset)
        after = approved.propose(
            before, approved.chosen(candidate_day, slots), slots,
        )
        if after != before:
            day = candidate_day
            break
    else:
        raise ValueError("no alternate approved banner was found")
    base, head = "a" * 40, "b" * 40
    ref = contract.expected_branch(day, base)
    app = {
        "installation": {
            "id": 11, "app_id": 12, "app_slug": "reviewed-banner-app",
            "account": {"login": "portyu9"}, "repository_selection": "selected",
            "permissions": {"contents": "write", "pull_requests": "write"},
        },
        "bot_user": {"id": 13, "login": "reviewed-banner-app[bot]",
                     "type": "Bot"},
        "expected_app_id": 12, "expected_installation_id": 11,
        "expected_repository_id": 14,
    }
    pr = {
        "number": 25, "state": "open", "draft": False,
        "changed_files": 1, "mergeable": True, "mergeable_state": "clean",
        "title": f"chore(profile): independently rotate approved banners for {day}",
        "body": contract.expected_body(base, contract.sha256(after), native_app=True),
        "user": {"login": app["bot_user"]["login"], "id": 13},
        "base": {"ref": "main", "sha": base,
                 "repo": {"full_name": contract.REPOSITORY}},
        "head": {"ref": ref, "sha": head,
                 "repo": {"full_name": contract.REPOSITORY}},
    }
    actor = {"name": contract.BOT_LOGIN, "email": contract.BOT_EMAIL}
    commit = {
        "sha": head, "parents": [{"sha": base}],
        "commit": {
            "message": f"chore(profile): rotate approved banner triplet for {day}",
            "author": actor, "committer": actor,
        },
        "author": {"login": contract.BOT_LOGIN},
    }
    suites = {
        "Profile quality": 101, "CodeQL": 102,
        "Dependency review": 103, "Capability admission": 104,
    }
    checks: list[dict[str, Any]] = []
    runs: list[dict[str, Any]] = []
    for n, (path, event, contexts) in contract.EXPECTED_PROTECTED_WORKFLOWS.items():
        suite = suites[n]
        runs.append({
            "name": n, "path": path, "event": event,
            "head_sha": head, "head_branch": ref,
            "id": suite + 500, "workflow_id": suite + 900,
            "check_suite_id": suite, "run_attempt": 1,
            "status": "completed", "conclusion": "success",
            "repository": {"full_name": contract.REPOSITORY},
            "head_repository": {"full_name": contract.REPOSITORY},
        })
        for index, name in enumerate(sorted(contexts)):
            checks.append({
                "id": suite * 10 + index, "name": name,
                "app": {"id": contract.GITHUB_ACTIONS_APP_ID},
                "check_suite": {"id": suite},
                "head_sha": head, "status": "completed",
                "conclusion": "success",
            })
    counts = {
        k: {"totalCount": length, "hasNextPage": False}
        for k, length in {
            "openPrs": 1, "files": 1, "checkRuns": len(checks),
            "workflowRuns": len(runs), "reviews": 0,
        }.items()
    }
    return {
        "schemaVersion": 1, "repository": contract.REPOSITORY,
        "observedAt": f"{day.isoformat()}T12:00:00Z",
        "mainSha": base, "nativeApp": app, "openPrs": [pr],
        "completeness": counts, "pr": pr, "commit": commit,
        "acceptedReadme": before, "proposedReadme": after,
        "files": [{
            "filename": "README.md", "sha": contract.blob_sha(after),
            "status": "modified", "additions": 1, "deletions": 1,
        }],
        "checkRuns": checks, "workflowRuns": runs,
        "reviews": [],
        "reviewThreads": {
            "totalCount": 0, "nodes": [],
            "pageInfo": {"hasNextPage": False, "endCursor": None},
        },
        "mainRef": {"ref": "refs/heads/main",
                    "object": {"type": "commit", "sha": base}},
        "candidateRef": {"ref": f"refs/heads/{ref}",
                         "object": {"type": "commit", "sha": head}},
    }


def self_test() -> None:
    valid = fixture()
    expected = "exact-native-banner-owner-review-ready-read-only"
    require(decide(valid)["decision"] == expected,
            "synthetic complete first-attempt review lane should pass")
    reviewed = copy.deepcopy(valid)
    reviewed["reviews"] = [{
        "id": 91, "user": {"login": "portyu9"},
        "commit_id": reviewed["pr"]["head"]["sha"], "state": "APPROVED",
        "body": review_marker(
            reviewed["mainSha"], reviewed["pr"]["head"]["sha"],
        ),
    }]
    reviewed["completeness"]["reviews"]["totalCount"] = 1
    require(decide(reviewed)["decision"]
            == "exact-owner-reviewed-banner-terminal-ready-read-only",
            "valid marker-bound owner-reviewed terminal evidence should pass")

    cases: list[tuple[str, Any]] = []
    def mutate(label: str, change: Any) -> None:
        sample = copy.deepcopy(valid)
        change(sample)
        cases.append((label, sample))

    mutate("truncated native inventory",
           lambda x: x["completeness"]["checkRuns"].update(
               hasNextPage=True,
           ))
    mutate("false count",
           lambda x: x["completeness"]["openPrs"].update(
               totalCount=2,
           ))
    mutate("app identity drift",
           lambda x: x["nativeApp"].update(expected_app_id=999))
    mutate("wrong repository",
           lambda x: x.update(repository="attacker/copy"))
    mutate("wrong native suite",
           lambda x: x["checkRuns"][0]["check_suite"].update(id=999))
    mutate("replayed workflow attempt",
           lambda x: x["workflowRuns"][0].update(run_attempt=2))
    mutate("stale artifact blob",
           lambda x: x["files"][0].update(sha="f" * 40))
    mutate("unresolved review thread",
           lambda x: x["reviewThreads"]["nodes"].append(
               {"id": "THREAD", "isResolved": False},
           ))
    mutate("main ref advanced",
           lambda x: x["mainRef"]["object"].update(sha="e" * 40))
    mutate("unexpected extra payload",
           lambda x: x.update(token="must-not-appear"))
    mutate("UTC drift",
           lambda x: x.update(observedAt="2026-10-27T11:00:00+02:00"))
    mutate("unmergeable PR",
           lambda x: x["pr"].update(mergeable=False))
    for label, invalid in cases:
        try:
            decide(invalid)
        except (ValueError, KeyError, TypeError):
            continue
        raise AssertionError(f"unsafe native banner observation accepted: {label}")
    veto = copy.deepcopy(valid)
    veto["reviews"] = [{
        "id": 92, "user": {"login": "portyu9"},
        "commit_id": veto["pr"]["head"]["sha"], "state": "CHANGES_REQUESTED",
        "body": "Owner veto",
    }]
    veto["completeness"]["reviews"]["totalCount"] = 1
    require(decide(veto)["decision"] == "owner-veto-or-revocation-no-action",
            "explicit owner veto must never grant review or merge")
    no_candidate = {k: copy.deepcopy(valid[k]) for k in BASIC}
    no_candidate["openPrs"] = []
    no_candidate["completeness"]["openPrs"]["totalCount"] = 0
    require(decide(no_candidate)["decision"] == "no-candidate-read-only",
            "no native banner PR must be a safe idle no-op")
    # Native REST inventories must be exhausted over pinned authenticated HTTPS,
    # never inferred from a caller-provided count or unverified Link header.
    import banner_native_rest_transport
    import banner_native_review_threads_transport
    import banner_native_snapshot_collector
    import banner_native_terminal_reproof
    banner_native_rest_transport.self_test()
    banner_native_review_threads_transport.self_test()
    banner_native_snapshot_collector.self_test()
    banner_native_terminal_reproof.self_test()
    # Profile Quality's transitive validator-purity firewall intentionally
    # forbids executing a CLI that opens network/local file descriptors.
    # Freeze the exact separately runnable observer executable instead; its
    # reused live collector and two-phase proof remain dynamically exercised
    # above. Any observer implementation change requires reviewed re-lock.
    observer_path = Path(__file__).with_name("banner_native_observer_cli.py")
    require(observer_path.is_file() and not observer_path.is_symlink(),
            "read-only banner observer executable is missing or aliased")
    require(approved.git_blob(observer_path.read_text(encoding="utf-8"))
            == "0fe206d64d08bb216f4e379d656e27fa3acabcdc",
            "read-only banner observer executable changed without re-review")
    print("banner native admission: first-attempt, veto and 12 fail-closed probes PASS")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    choice = parser.add_mutually_exclusive_group(required=True)
    choice.add_argument("--self-test", action="store_true")
    choice.add_argument("--verified-bundle", type=Path)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    path: Path = args.verified_bundle
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 1024 * 1024:
        raise ValueError("banner observation must be bounded regular JSON file")
    data = json.loads(path.read_text(encoding="utf-8"))
    print(json.dumps(decide(data), sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
