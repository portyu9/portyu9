#!/usr/bin/env python3
"""Fail-closed evidence checks for a separately provisioned workflow-rebase App.

No network calls, credentials, or GitHub mutations are performed here.
"""
from __future__ import annotations
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
import re

PERMISSIONS = {"metadata": "read", "contents": "write",
               "pull_requests": "write", "workflows": "write"}
SHA = re.compile(r"[0-9a-f]{40}")
NODE = re.compile(r"PR_[A-Za-z0-9_-]{8,128}")
REF = re.compile(r"dependabot/github_actions/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")


def require(valid: bool, message: str) -> None:
    if not valid:
        raise ValueError(message)


def select_stale_native_pr(items: Any, repo: str, main_sha: str) -> dict[str, Any] | None:
    """Require an exhaustive open-PR page, select at most one stale native bot head."""
    require(type(repo) is str and repo.count("/") == 1
            and type(main_sha) is str and SHA.fullmatch(main_sha) is not None,
            "invalid trusted repository or main identity")
    require(type(items) is list and len(items) < 100, "incomplete open-PR page")
    seen: set[int] = set()
    selected = []
    for pr in items:
        require(isinstance(pr, Mapping), "non-object pull response")
        n = pr.get("number")
        require(type(n) is int and n > 0 and n not in seen, "duplicate/invalid PR number")
        seen.add(n)
        user = pr.get("user")
        require(isinstance(user, Mapping) and type(user.get("login")) is str,
                "invalid PR author")
        if user["login"] != "dependabot[bot]":
            continue
        h, b = pr.get("head"), pr.get("base")
        require(pr.get("state") == "open" and pr.get("draft") is False
                and isinstance(h, Mapping) and isinstance(b, Mapping),
                "malformed native PR state/ref")
        require(type(h.get("ref")) is str and REF.fullmatch(h["ref"]) is not None
                and isinstance(h.get("repo"), Mapping) and h["repo"].get("full_name") == repo
                and b.get("ref") == "main",
                "native Dependabot ref/repository changed")
        require(type(h.get("sha")) is str and SHA.fullmatch(h["sha"]) is not None
                and type(b.get("sha")) is str and SHA.fullmatch(b["sha"]) is not None
                and type(pr.get("node_id")) is str
                and NODE.fullmatch(pr["node_id"]) is not None,
                "native PR immutable identity malformed")
        require("maintainer_can_modify" in pr
                and (pr["maintainer_can_modify"] is None
                     or type(pr["maintainer_can_modify"]) is bool),
                "native PR advisory permission field malformed")
        if b["sha"] != main_sha:
            selected.append({"number": n, "nodeId": pr["node_id"],
                             "headRef": h["ref"], "headSha": h["sha"],
                             "baseSha": b["sha"], "acceptedMainSha": main_sha})
    return sorted(selected, key=lambda x: x["number"])[0] if selected else None


def verify_app(install: Any, *, app_id: int, installation_id: int, owner: str) -> None:
    require(type(app_id) is int and app_id > 0
            and type(installation_id) is int and installation_id > 0
            and isinstance(install, Mapping)
            and install.get("id") == installation_id and install.get("app_id") == app_id
            and install.get("repository_selection") == "selected"
            and isinstance(install.get("account"), Mapping)
            and install["account"].get("login") == owner
            and install.get("permissions") == PERMISSIONS,
            "App identity, selected-repository scope, or least privilege differs")


def verify_token(token: Any, *, repository: str, observed_at: datetime) -> None:
    """Check only token metadata; never return or log the bearer value."""
    require(isinstance(token, Mapping)
            and type(token.get("token")) is str and len(token["token"]) > 30
            and token.get("permissions") == PERMISSIONS
            and token.get("repository_selection") == "selected"
            and type(token.get("repositories")) is list
            and len(token["repositories"]) == 1
            and isinstance(token["repositories"][0], Mapping)
            and token["repositories"][0].get("full_name") == repository,
            "installation token scope/permission mismatch")
    require(isinstance(observed_at, datetime) and observed_at.tzinfo is not None
            and type(token.get("expires_at")) is str, "invalid token clock")
    try:
        expires = datetime.fromisoformat(token["expires_at"].replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError("invalid token expiry") from e
    require(expires.tzinfo is not None
            and observed_at < expires <= observed_at + timedelta(minutes=65),
            "token expired or overlong")


def self_test() -> None:
    main = "a" * 40
    pr = {"number": 2, "node_id": "PR_validNative123456", "state": "open",
          "user": {"login": "dependabot[bot]"}, "draft": False,
          "head": {"ref": "dependabot/github_actions/upload-artifact-7.0.2",
                   "sha": "b" * 40, "repo": {"full_name": "x/y"}},
          "base": {"ref": "main", "sha": "c" * 40}, "maintainer_can_modify": False}
    require(select_stale_native_pr([pr], "x/y", main)["number"] == 2, "selection failed")
    require(select_stale_native_pr([{**pr, "base": {"ref": "main", "sha": main}}],
                                   "x/y", main) is None, "fresh PR selected")
    for bad in ([pr, pr], [pr] * 100,
                [{**pr, "maintainer_can_modify": "yes"}],
                [{**pr, "head": {**pr["head"], "repo": {"full_name": "x/z"}}}],
                [{**pr, "node_id": "untyped"}]):
        try:
            select_stale_native_pr(bad, "x/y", main)
        except ValueError:
            pass
        else:
            raise ValueError("bad PR accepted")
    app = {"id": 2, "app_id": 1, "repository_selection": "selected",
           "account": {"login": "x"}, "permissions": dict(PERMISSIONS)}
    verify_app(app, app_id=1, installation_id=2, owner="x")
    for bad in ({**app, "repository_selection": "all"},
                {**app, "permissions": {**PERMISSIONS, "administration": "write"}}):
        try:
            verify_app(bad, app_id=1, installation_id=2, owner="x")
        except ValueError:
            pass
        else:
            raise ValueError("overprivileged App accepted")
    now = datetime(2026, 10, 15, tzinfo=timezone.utc)
    token = {"token": "this-is-only-a-test-not-an-auth-token",
             "permissions": dict(PERMISSIONS), "repository_selection": "selected",
             "repositories": [{"full_name": "x/y"}], "expires_at": "2026-10-15T01:00:00Z"}
    verify_token(token, repository="x/y", observed_at=now)
    for bad in ({**token, "expires_at": "2026-10-16T00:00:00Z"},
                {**token, "repositories": [{"full_name": "x/z"}]}):
        try:
            verify_token(bad, repository="x/y", observed_at=now)
        except ValueError:
            pass
        else:
            raise ValueError("bad token accepted")


if __name__ == "__main__":
    self_test()
    print("Workflow-rebase App admission fixtures passed (no token issued).")
