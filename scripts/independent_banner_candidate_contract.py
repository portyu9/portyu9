#!/usr/bin/env python3
"""Pure exact-candidate identity and artwork proof for future banner PR governance.

Consumes untrusted API snapshots only as inert data. Does not contact GitHub, mint
tokens, change the approved catalog, approve reviews, forge checks or merge refs.
Trusted callers must separately prove API transport, exact main, schedule/UTC
date, GitHub Actions check provenance and user veto before any authority step.
"""
from __future__ import annotations

import copy
from datetime import date, timedelta
import hashlib
import re
from typing import Any

import approved_banner_rotation as approved

REPOSITORY = "portyu9/portyu9"
BOT_LOGIN = "github-actions[bot]"
BOT_ID = 41898282
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
HEX40 = re.compile(r"^[0-9a-f]{40}$")


def require(condition: bool, explanation: str) -> None:
    if not condition:
        raise ValueError(explanation)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def blob_sha(text: str) -> str:
    value = text.encode("utf-8")
    return hashlib.sha1(
        f"blob {len(value)}\0".encode("ascii") + value, usedforsecurity=False
    ).hexdigest()


def expected_branch(day: date, base_sha: str) -> str:
    return f"automation/banner-rotation/{day.isoformat()}-{base_sha[:12]}"


def expected_body(base_sha: str, readme_sha256: str) -> str:
    return (
        "README-only UTC banner rotation using the reviewed approved v7 catalog. "
        "Three image surfaces and marker only; external CI evidence unchanged. "
        f"Base {base_sha}. Output SHA256 {readme_sha256}. Requires normal protected checks."
    )


def valid_candidate(
    *, pr: Any, commit: Any, files: Any,
    accepted_readme: str, proposed_readme: str,
    base_sha: str, utc_day: date,
) -> dict[str, str | int]:
    require(type(base_sha) is str and HEX40.fullmatch(base_sha) is not None,
            "trusted current-main SHA is malformed")
    require(type(utc_day) is date, "trusted UTC date must be a date")
    require(type(accepted_readme) is str and type(proposed_readme) is str,
            "readme payload must be UTF-8 text")
    slots = approved.load_catalog()
    approved.validate_readme_state(accepted_readme, slots)
    exact = approved.propose(accepted_readme, approved.chosen(utc_day, slots), slots)
    require(exact != accepted_readme and exact == proposed_readme,
            "candidate README is unchanged, stale or not exact approved artwork")
    # Independently check every non-banner byte remains the same; prohibit
    # badges, Ledger/Spotlight epoch, metrics, unrelated prose and SVG mutation.
    import independent_banner_rotation as rotation
    rotation.only_banner_changes(accepted_readme, proposed_readme)

    require(type(pr) is dict and type(commit) is dict
            and type(files) is list and len(files) == 1,
            "candidate PR/commit/file response shape is malformed")
    require(type(pr.get("number")) is int and pr["number"] > 0
            and pr.get("state") == "open" and pr.get("draft") is False
            and pr.get("changed_files") == 1 and type(pr.get("changed_files")) is int,
            "banner PR cardinality/open/non-draft invariant failed")
    require(pr.get("title") ==
            f"chore(profile): independently rotate approved banners for {utc_day.isoformat()}",
            "banner PR title is not exact reviewed producer")
    require(pr.get("body") == expected_body(base_sha, sha256(proposed_readme)),
            "banner PR body binds a different base, artwork or source")
    user = pr.get("user")
    require(type(user) is dict and user.get("login") == BOT_LOGIN
            and type(user.get("id")) is int and user.get("id") == BOT_ID,
            "banner PR was not opened by the reviewed Actions identity")
    base, head = pr.get("base"), pr.get("head")
    require(type(base) is dict and type(head) is dict,
            "banner PR base/head identities are absent")
    require(base.get("ref") == "main" and base.get("sha") == base_sha
            and type(base.get("repo")) is dict
            and base["repo"].get("full_name") == REPOSITORY,
            "banner PR accepted main binding changed")
    head_sha = head.get("sha")
    require(type(head_sha) is str and HEX40.fullmatch(head_sha) is not None
            and head_sha != base_sha
            and head.get("ref") == expected_branch(utc_day, base_sha)
            and type(head.get("repo")) is dict
            and head["repo"].get("full_name") == REPOSITORY,
            "banner PR head identity/ref is not a same-repo reviewed lane")

    require(commit.get("sha") == head_sha
            and type(commit.get("parents")) is list
            and len(commit["parents"]) == 1
            and type(commit["parents"][0]) is dict
            and commit["parents"][0].get("sha") == base_sha,
            "banner candidate commit is not a one-commit exact-main child")
    payload = commit.get("commit")
    require(type(payload) is dict
            and payload.get("message") ==
            f"chore(profile): rotate approved banner triplet for {utc_day.isoformat()} [skip ci]",
            "banner candidate commit message changed")
    author, committer = payload.get("author"), payload.get("committer")
    require(type(author) is dict and type(committer) is dict
            and author.get("name") == BOT_LOGIN and committer.get("name") == BOT_LOGIN
            and author.get("email") == BOT_EMAIL and committer.get("email") == BOT_EMAIL,
            "banner candidate was not produced with reviewed bot commit identity")
    require(type(commit.get("author")) is dict
            and commit["author"].get("login") == BOT_LOGIN,
            "banner head commit author account is not GitHub Actions")
    row = files[0]
    require(type(row) is dict and row.get("filename") == "README.md"
            and row.get("status") == "modified"
            and row.get("sha") == blob_sha(proposed_readme),
            "candidate changed a file beyond the exact README output blob")
    require(type(row.get("additions")) is int and row["additions"] >= 0
            and type(row.get("deletions")) is int and row["deletions"] >= 0
            and row["additions"] + row["deletions"] > 0,
            "candidate file lacks a nonempty reviewed diff")
    return {
        "prNumber": pr["number"],
        "baseSha": base_sha,
        "headSha": head_sha,
        "utcDay": utc_day.isoformat(),
        "readmeSha256": sha256(proposed_readme),
        "readmeBlob": blob_sha(proposed_readme),
    }



# Read-only evidence projection for a *future separately authorized* banner
# reconciler. Never create or infer GitHub checks or owner approval here.
REQUIRED_CHECK_NAMES = frozenset({
    "validate-contracts",
    "integration-pinned-upstream",
    "trusted-governed-bot-review",
    "dependency-review",
    "analyze-actions",
    "analyze-python",
    "trusted-capability-admission",
})
PROFILE_CHECK_NAMES = frozenset({
    "validate-contracts", "integration-pinned-upstream",
    "trusted-governed-bot-review",
})
CODEQL_CHECK_NAMES = frozenset({"analyze-actions", "analyze-python"})
GITHUB_ACTIONS_APP_ID = 15368


def verified_required_check_snapshot(check_runs: Any, head_sha: str) -> dict[str, int]:
    """Reject missing/duplicate/foreign/non-success exact-head check observations.

    The trusted future caller must first prove the authenticated GitHub API
    transport and total_count/pagination completeness. This pure predicate
    does not create statuses and never treats its own output as a check.
    """
    require(type(head_sha) is str and HEX40.fullmatch(head_sha) is not None,
            "required check head SHA is malformed")
    require(type(check_runs) is list and len(check_runs) <= 100,
            "required check inventory is malformed or incomplete")
    seen: dict[str, dict[str, Any]] = {}
    ids: set[int] = set()
    for row in check_runs:
        require(type(row) is dict and type(row.get("name")) is str,
                "required check response has an invalid record")
        name = row["name"]
        if name not in REQUIRED_CHECK_NAMES:
            continue  # An unrelated check cannot satisfy a required context.
        require(name not in seen, f"duplicate required check context: {name}")
        run_id = row.get("id")
        suite = row.get("check_suite")
        app = row.get("app")
        require(type(run_id) is int and run_id > 0 and run_id not in ids,
                f"required check id invalid: {name}")
        require(type(app) is dict and type(app.get("id")) is int
                and app["id"] == GITHUB_ACTIONS_APP_ID,
                f"required check is not GitHub Actions: {name}")
        require(type(suite) is dict and type(suite.get("id")) is int
                and suite["id"] > 0,
                f"required check suite missing: {name}")
        require(row.get("head_sha") == head_sha
                and row.get("status") == "completed"
                and row.get("conclusion") == "success",
                f"required check is not successful on exact head: {name}")
        seen[name] = row
        ids.add(run_id)
    require(set(seen) == REQUIRED_CHECK_NAMES,
            "one or more required protected checks are missing")
    require(len({seen[n]["check_suite"]["id"] for n in PROFILE_CHECK_NAMES}) == 1,
            "Profile Quality checks do not share one verified suite")
    require(len({seen[n]["check_suite"]["id"] for n in CODEQL_CHECK_NAMES}) == 1,
            "CodeQL Actions and Python checks do not share one verified suite")
    return {name: seen[name]["id"] for name in sorted(seen)}


def verified_owner_review_snapshot(
    reviews: Any, base_sha: str, head_sha: str,
) -> None:
    """Require exact-marker owner APPROVED review, honoring explicit veto.

    Does not submit reviews, mint owner credentials or trigger a job rerun.
    """
    require(type(base_sha) is str and HEX40.fullmatch(base_sha) is not None
            and type(head_sha) is str and HEX40.fullmatch(head_sha) is not None
            and base_sha != head_sha,
            "governed owner review base/head binding malformed")
    require(type(reviews) is list and len(reviews) <= 2000,
            "governed owner review snapshot malformed or incomplete")
    from automation_governed_bot_review_gate import review_decision
    require(review_decision(reviews, base_sha, head_sha) == "approved",
            "exact-head governed owner approval is absent, revoked or vetoed")


def qualified_banner_candidate(
    *, pr: Any, commit: Any, files: Any,
    accepted_readme: str, proposed_readme: str,
    base_sha: str, utc_day: date,
    check_runs: Any, reviews: Any,
) -> dict[str, str | int]:
    """Compose reviewed artwork/ancestry, genuine-check and owner-veto gates.

    Caller must independently bind the exact live GitHub main ref, complete
    API pages, run-to-suite/event provenance and review-thread resolution.
    This helper does not grant merge permission or certify unattended runs.
    """
    result = valid_candidate(
        pr=pr, commit=commit, files=files,
        accepted_readme=accepted_readme, proposed_readme=proposed_readme,
        base_sha=base_sha, utc_day=utc_day,
    )
    verified_required_check_snapshot(check_runs, str(result["headSha"]))
    verified_owner_review_snapshot(reviews, base_sha, str(result["headSha"]))
    return result


def self_test() -> None:
    require(blob_sha("hello\n") == "ce013625030ba8dba906f756967f9e9ca394464a",
            "git blob SHA1 NUL delimiter regression")
    source = approved.read_file(approved.ROOT / "README.md")
    slots = approved.load_catalog()
    approved.validate_assets(slots)
    match = approved.MARKER.search(source)
    require(match is not None, "banner test requires the accepted rotation marker")
    day = date.fromisoformat(match.group(2)) + timedelta(days=1)
    proposed = approved.propose(source, approved.chosen(day, slots), slots)
    require(proposed != source, "candidate fixture must have a real banner change")
    base, head = "a" * 40, "b" * 40
    title = f"chore(profile): independently rotate approved banners for {day.isoformat()}"
    commit_message = f"chore(profile): rotate approved banner triplet for {day.isoformat()} [skip ci]"
    pr: dict[str, Any] = {
        "number": 19, "state": "open", "draft": False, "changed_files": 1,
        "title": title, "body": expected_body(base, sha256(proposed)),
        "user": {"login": BOT_LOGIN, "id": BOT_ID},
        "base": {"ref": "main", "sha": base, "repo": {"full_name": REPOSITORY}},
        "head": {"ref": expected_branch(day, base), "sha": head,
                 "repo": {"full_name": REPOSITORY}},
    }
    commit: dict[str, Any] = {
        "sha": head, "parents": [{"sha": base}],
        "author": {"login": BOT_LOGIN},
        "commit": {"message": commit_message,
                   "author": {"name": BOT_LOGIN, "email": BOT_EMAIL},
                   "committer": {"name": BOT_LOGIN, "email": BOT_EMAIL}},
    }
    files: list[dict[str, Any]] = [{
        "filename": "README.md", "status": "modified",
        "sha": blob_sha(proposed), "additions": 4, "deletions": 4,
    }]
    fixture = {
        "pr": pr, "commit": commit, "files": files,
        "accepted_readme": source, "proposed_readme": proposed,
        "base_sha": base, "utc_day": day,
    }
    result = valid_candidate(**fixture)
    require(result["headSha"] == head and result["readmeBlob"] == blob_sha(proposed),
            "valid exact banner candidate was rejected")
    corruptions: list[tuple[str, tuple[Any, ...], Any]] = [
        ("pr", ("state",), "closed"),
        ("pr", ("draft",), True),
        ("pr", ("changed_files",), True),
        ("pr", ("title",), title + " (spoof)"),
        ("pr", ("body",), "unbound proposal"),
        ("pr", ("user", "login"), "portyu9"),
        ("pr", ("user", "id"), True),
        ("pr", ("base", "sha"), "c" * 40),
        ("pr", ("base", "ref"), "generated"),
        ("pr", ("head", "repo", "full_name"), "outsider/fork"),
        ("pr", ("head", "ref"), "automation/banner-rotation/spoof"),
        ("pr", ("head", "sha"), "d" * 40),
        ("commit", ("sha",), "d" * 40),
        ("commit", ("parents",), [{"sha": "c" * 40}]),
        ("commit", ("commit", "message"), "unreviewed"),
        ("commit", ("commit", "committer", "email"), "attacker@example.com"),
        ("files", (0, "filename"), "scripts/generate.py"),
        ("files", (0, "sha"), "f" * 40),
        ("files", (0, "status"), "added"),
        ("files", (0, "additions"), True),
        ("proposed_readme", (), proposed.replace("© 2026", "© 2027", 1)),
        ("proposed_readme", (), source),
        ("utc_day", (), day + timedelta(days=1)),
    ]
    for section, path, value in corruptions:
        mutant = copy.deepcopy(fixture)
        if not path:
            mutant[section] = value
        else:
            item: Any = mutant[section]
            for part in path[:-1]:
                item = item[part]
            item[path[-1]] = value
        try:
            valid_candidate(**mutant)
        except ValueError:
            pass
        else:
            raise ValueError(f"unreviewed banner PR mutation accepted: {section}.{path}")
    try:
        valid_candidate(**{**fixture, "files": files + files})
    except ValueError:
        pass
    else:
        raise ValueError("extra candidate file escaped exact-one-file gate")

    # Phase 2: check-run and owner-veto evidence is independent of candidate art.
    checks: list[dict[str, Any]] = []
    for index, name in enumerate(sorted(REQUIRED_CHECK_NAMES), start=1):
        suite = (100 if name in PROFILE_CHECK_NAMES
                 else 200 if name in CODEQL_CHECK_NAMES
                 else 300 + index)
        checks.append({
            "id": index, "name": name, "head_sha": head,
            "status": "completed", "conclusion": "success",
            "app": {"id": GITHUB_ACTIONS_APP_ID},
            "check_suite": {"id": suite},
        })
    from automation_governed_bot_review_gate import review_marker
    owner_review = {
        "id": 1000, "user": {"login": "portyu9"},
        "state": "APPROVED", "commit_id": head,
        "body": review_marker(base, head),
    }
    verified_required_check_snapshot(checks, head)
    verified_owner_review_snapshot([owner_review], base, head)
    qualified_banner_candidate(**fixture, check_runs=checks, reviews=[owner_review])
    check_mutants: list[tuple[int, str, Any]] = [
        (0, "head_sha", "f" * 40),
        (0, "status", "queued"),
        (0, "conclusion", "failure"),
        (0, "id", True),
        (0, "app", {"id": 123}),
        (0, "check_suite", {"id": False}),
        (0, "name", "untrusted-check-name"),
    ]
    for index, key, value in check_mutants:
        mutation = copy.deepcopy(checks)
        mutation[index][key] = value
        try:
            verified_required_check_snapshot(mutation, head)
        except ValueError:
            pass
        else:
            raise ValueError(f"mutated required check was accepted: {key}")
    for mutation in (checks[:-1], checks + [checks[0]], "not-a-list"):
        try:
            verified_required_check_snapshot(mutation, head)
        except ValueError:
            pass
        else:
            raise ValueError("missing, duplicated or malformed required checks accepted")
    mismatched_suite = copy.deepcopy(checks)
    one_profile = next(i for i, row in enumerate(checks)
                       if row["name"] == "validate-contracts")
    mismatched_suite[one_profile]["check_suite"]["id"] = 900
    try:
        verified_required_check_snapshot(mismatched_suite, head)
    except ValueError:
        pass
    else:
        raise ValueError("split profile required-check suite was accepted")
    stale_review = {**owner_review, "commit_id": "e" * 40}
    revoked_review = {**owner_review, "state": "DISMISSED"}
    manual_veto = {
        "id": 1001, "user": {"login": "portyu9"},
        "state": "CHANGES_REQUESTED", "commit_id": head, "body": "Stop",
    }
    for evidence in (
        [], [stale_review], [revoked_review],
        [owner_review, manual_veto],
        [{**owner_review, "body": "ordinary manual review"}],
    ):
        try:
            verified_owner_review_snapshot(evidence, base, head)
        except ValueError:
            pass
        else:
            raise ValueError("unapproved, revoked or vetoed owner review was accepted")
