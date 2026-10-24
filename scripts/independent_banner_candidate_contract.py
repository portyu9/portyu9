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
