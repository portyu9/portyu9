#!/usr/bin/env python3
"""Independent read-only native owner-identity proof for banner review.

A real future reviewer job must run within the *separate* owner-credential
environment, fetch GET /user using that owner credential, and GET the exact
repository over authenticated TLS. This module binds the authenticated user
ID to the repository owner ID and accepted repository ID; merely checking a
login string, native check, App envelope or review artifact is insufficient.

The output is minimal non-secret evidence, NOT a request to approve/merge.
No App JWT, review POST, status writer, workflow dispatch or Git mutation.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
from pathlib import Path
from typing import Any, Callable

from automation_governed_bot_review_gate import REVIEW_LOGIN
from banner_native_authenticated_app_source import FixedOriginRead, REPOSITORY


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def collect(*, get_owner: Callable[[str], Any],
            get_repository: Callable[[str], Any],
            expected_repository_id: int) -> dict[str, str | int]:
    """Reconcile two *independently authenticated* fixed HTTPS GET responses."""
    require(type(expected_repository_id) is int and expected_repository_id > 0,
            "owner source repository ID must be a positive non-boolean integer")
    owner = get_owner("/user")
    repository = get_repository(REPOSITORY)
    require(type(owner) is dict and type(repository) is dict,
            "native owner and repository response objects required")
    repo_owner = repository.get("owner")
    require(type(repo_owner) is dict,
            "protected repository owner identity response missing")
    identity = owner.get("id")
    require(type(identity) is int and identity > 0
            and owner.get("login") == REVIEW_LOGIN
            and owner.get("type") == "User"
            and type(repo_owner.get("id")) is int
            and repo_owner["id"] == identity
            and repo_owner.get("login") == REVIEW_LOGIN,
            "authenticated review token does not belong to exact repository owner")
    require(type(repository.get("id")) is int
            and repository["id"] == expected_repository_id
            and repository.get("full_name") == REPOSITORY.lstrip("/repos/")
            and repository.get("name") == "portyu9"
            and repository.get("private") is False,
            "native owner credential bound to different repository or state")
    require(type(repository.get("default_branch")) is str
            and repository["default_branch"] == "main",
            "native owner repository default branch moved")
    # Return only immutable routing identifiers. No owner credential, token,
    # email, response body, URL or untrusted extra fields cross this boundary.
    return {
        "login": REVIEW_LOGIN,
        "userId": identity,
        "repositoryId": expected_repository_id,
        "repository": "portyu9/portyu9",
        "defaultBranch": "main",
    }


def self_test() -> None:
    repository_id = 1355082509
    user_id = 35150859
    owner = {"id": user_id, "login": REVIEW_LOGIN, "type": "User"}
    repo = {
        "id": repository_id, "full_name": "portyu9/portyu9",
        "name": "portyu9", "private": False, "default_branch": "main",
        "owner": {"id": user_id, "login": REVIEW_LOGIN},
    }
    calls: list[tuple[str, str]] = []

    def get_owner(path: str) -> dict[str, Any]:
        calls.append(("owner", path))
        require(path == "/user", "owner token used on unreviewed route")
        return copy.deepcopy(owner)

    def get_repo(path: str) -> dict[str, Any]:
        calls.append(("repository", path))
        require(path == REPOSITORY, "read token used on unreviewed repo")
        return copy.deepcopy(repo)

    base = {"get_owner": get_owner, "get_repository": get_repo,
            "expected_repository_id": repository_id}
    result = collect(**base)
    require(result == {
        "login": REVIEW_LOGIN,
        "userId": user_id,
        "repositoryId": repository_id,
        "repository": "portyu9/portyu9",
        "defaultBranch": "main",
    } and calls == [("owner", "/user"), ("repository", REPOSITORY)],
        "positive native owner credential binding failed")
    require("token" not in json.dumps(result).lower(),
            "native owner identity leaked a credential")

    def rejected(label: str, *, changed_owner: dict[str, Any] | None = None,
                 changed_repo: dict[str, Any] | None = None,
                 expected: int = repository_id) -> None:
        new_owner = copy.deepcopy(owner)
        new_repo = copy.deepcopy(repo)
        if changed_owner:
            new_owner.update(changed_owner)
        if changed_repo:
            new_repo.update(changed_repo)
        try:
            collect(
                get_owner=lambda _path: new_owner,
                get_repository=lambda _path: new_repo,
                expected_repository_id=expected,
            )
        except (ValueError, TypeError, KeyError):
            return
        raise AssertionError("untrusted native banner owner identity accepted: " + label)

    rejected("wrong user", changed_owner={"login": "attacker"})
    rejected("bot", changed_owner={"type": "Bot"})
    rejected("wrong owner ID", changed_owner={"id": user_id + 1})
    rejected("boolean owner ID", changed_owner={"id": True})
    rejected("wrong owner login", changed_repo={"owner": {
        "id": user_id, "login": "attacker"}})
    rejected("wrong repository owner ID", changed_repo={"owner": {
        "id": user_id + 1, "login": REVIEW_LOGIN}})
    rejected("unexpected repository", changed_repo={"full_name": "attacker/repo"})
    rejected("renamed repository", changed_repo={"name": "attacker"})
    rejected("unexpected default branch", changed_repo={"default_branch": "staging"})
    rejected("private repository", changed_repo={"private": True})
    rejected("different repository ID", expected=repository_id + 1)
    rejected("boolean expected ID", expected=True)
    print("native banner owner identity: authenticated token/repository owner "
          "ID binding, same-repo main, minimal credential-free evidence "
          "and 12 adversarial negatives PASS; no review or merge")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--repository-id", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.self_test:
        require(args.repository_id is None and args.output is None,
                "owner identity self-test cannot read live credentials")
        self_test()
        return 0
    require(type(args.repository_id) is int
            and args.repository_id > 0 and args.output is not None,
            "reviewer identity requires exact repository ID and new output")
    owner_token = os.environ.get("BANNER_OWNER_TOKEN")
    read_token = os.environ.get("GH_TOKEN")
    require(owner_token is not None and read_token is not None
            and owner_token != read_token,
            "owner identity requires a distinct owner credential and read token")
    reviewer = FixedOriginRead(owner_token, frozenset({"/user"}))
    repository = FixedOriginRead(read_token, frozenset({REPOSITORY}))
    identity = collect(
        get_owner=reviewer.get,
        get_repository=repository.get,
        expected_repository_id=args.repository_id,
    )
    # Deferred filesystem-only dependency preserves the pure protected
    # self-test graph and never enters the privileged review environment.
    import banner_native_observer_cli as observer
    observer.write_exclusive(args.output, identity)
    print("banner-owner-identity-exact-authenticated-readonly-no-write")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
