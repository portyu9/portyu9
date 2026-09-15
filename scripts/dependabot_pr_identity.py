#!/usr/bin/env python3
"""Classify native GitHub Dependabot GitHub-Actions PR identity from trusted API metadata.

The classifier intentionally ignores PR title/body/labels as authority. Exact bot identity
constants are GitHub-global metadata observed on independent native Dependabot PRs. A PR
with no Dependabot actor marker is deterministically not applicable; a partial/malformed
Dependabot identity fails closed instead of falling through to not-applicable.
"""
from __future__ import annotations

import re
from typing import Any, Mapping

DEPENDABOT_LOGIN = "dependabot[bot]"
DEPENDABOT_USER_ID = 49699333
DEPENDABOT_NODE_ID = "MDM6Qm90NDk2OTkzMzM="
DEPENDABOT_TYPE = "Bot"
DEPENDABOT_HTML_URL = "https://github.com/apps/dependabot"
DEPENDABOT_API_URL = "https://api.github.com/users/dependabot%5Bbot%5D"
HEAD_REF = re.compile(
    r"^dependabot/github_actions/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$"
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def mapping(value: Any, label: str) -> Mapping[str, Any]:
    require(isinstance(value, Mapping), f"Dependabot PR metadata is missing object: {label}")
    return value


def actor_marked(user: Mapping[str, Any]) -> bool:
    """Return whether any stable Dependabot actor marker is present."""
    return (
        user.get("login") == DEPENDABOT_LOGIN
        or user.get("id") == DEPENDABOT_USER_ID
        or user.get("node_id") == DEPENDABOT_NODE_ID
        or user.get("html_url") == DEPENDABOT_HTML_URL
        or user.get("url") == DEPENDABOT_API_URL
    )


def classify_pr_identity(
    pr: Mapping[str, Any],
    *,
    repository: str,
    expected_head_sha: str,
) -> dict[str, object]:
    """Return deterministic not-applicable/applicable identity classification or fail closed."""
    require(repository == "portyu9/portyu9", "Dependabot admission repository identity changed")
    require(SHA40.fullmatch(expected_head_sha) is not None, "expected Dependabot PR head SHA is invalid")

    user = mapping(pr.get("user"), "user")
    if not actor_marked(user):
        return {
            "classification": "not-applicable",
            "reason": "actor-not-dependabot",
        }

    expected_actor = {
        "login": DEPENDABOT_LOGIN,
        "id": DEPENDABOT_USER_ID,
        "node_id": DEPENDABOT_NODE_ID,
        "type": DEPENDABOT_TYPE,
        "html_url": DEPENDABOT_HTML_URL,
        "url": DEPENDABOT_API_URL,
    }
    observed_actor = {key: user.get(key) for key in expected_actor}
    require(observed_actor == expected_actor,
            "Dependabot actor identity is partial, spoofed, or changed")
    require(user.get("site_admin") is False, "Dependabot actor unexpectedly has site-admin identity")

    require(pr.get("state") == "open", "Dependabot admission applies only to an open pull request")
    require(pr.get("draft") is False, "Dependabot admission does not admit draft pull requests")
    require(pr.get("author_association") == "NONE", "Dependabot PR author association changed")
    require(pr.get("maintainer_can_modify") is False, "Dependabot PR must disable maintainer head mutation")
    require(type(pr.get("number")) is int and pr["number"] > 0, "Dependabot PR number is invalid")
    require(type(pr.get("commits")) is int and pr["commits"] >= 1,
            "Dependabot PR must contain at least one commit")

    base = mapping(pr.get("base"), "base")
    head = mapping(pr.get("head"), "head")
    base_repo = mapping(base.get("repo"), "base.repo")
    head_repo = mapping(head.get("repo"), "head.repo")

    require(base.get("ref") == "main", "Dependabot PR base ref must be main")
    require(base_repo.get("full_name") == repository, "Dependabot PR base repository identity changed")
    require(head_repo.get("full_name") == repository,
            "Dependabot GitHub-Actions PR head must remain in the target repository")

    head_ref = head.get("ref")
    require(isinstance(head_ref, str) and HEAD_REF.fullmatch(head_ref) is not None,
            "Dependabot PR head ref is outside the reviewed github_actions namespace")
    require(head.get("sha") == expected_head_sha,
            "Dependabot PR head SHA differs from the exact event/admission head")

    return {
        "classification": "dependabot-github-actions",
        "repository": repository,
        "pullRequest": pr["number"],
        "headRef": head_ref,
        "headSha": expected_head_sha,
        "actor": {
            "login": DEPENDABOT_LOGIN,
            "id": DEPENDABOT_USER_ID,
            "nodeId": DEPENDABOT_NODE_ID,
            "type": DEPENDABOT_TYPE,
        },
    }


def fixture(*, login: str = DEPENDABOT_LOGIN, user_id: int = DEPENDABOT_USER_ID) -> dict[str, Any]:
    sha = "a" * 40
    return {
        "number": 17,
        "state": "open",
        "draft": False,
        "author_association": "NONE",
        "maintainer_can_modify": False,
        "commits": 2,
        "user": {
            "login": login,
            "id": user_id,
            "node_id": DEPENDABOT_NODE_ID,
            "type": DEPENDABOT_TYPE,
            "html_url": DEPENDABOT_HTML_URL,
            "url": DEPENDABOT_API_URL,
            "site_admin": False,
        },
        "base": {"ref": "main", "repo": {"full_name": "portyu9/portyu9"}},
        "head": {
            "ref": "dependabot/github_actions/github/codeql-action-4.38.0",
            "sha": sha,
            "repo": {"full_name": "portyu9/portyu9"},
        },
    }


def expect_failure(pr: Mapping[str, Any], expected: str) -> None:
    try:
        classify_pr_identity(pr, repository="portyu9/portyu9", expected_head_sha="a" * 40)
    except ValueError as exc:
        require(expected in str(exc), f"Dependabot identity self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"Dependabot identity self-test accepted forbidden metadata: {expected}")


def self_test() -> None:
    good = fixture()
    result = classify_pr_identity(good, repository="portyu9/portyu9", expected_head_sha="a" * 40)
    require(result["classification"] == "dependabot-github-actions" and result["headSha"] == "a" * 40,
            "Dependabot identity self-test changed canonical applicable result")

    human = fixture(login="portyu9", user_id=35150859)
    human["user"] = {
        "login": "portyu9",
        "id": 35150859,
        "node_id": "MDQ6VXNlcjM1MTUwODU5",
        "type": "User",
        "html_url": "https://github.com/portyu9",
        "url": "https://api.github.com/users/portyu9",
        "site_admin": False,
    }
    not_applicable = classify_pr_identity(
        human,
        repository="portyu9/portyu9",
        expected_head_sha="a" * 40,
    )
    require(not_applicable == {"classification": "not-applicable", "reason": "actor-not-dependabot"},
            "ordinary human PR must be deterministic not-applicable even with a Dependabot-looking branch")

    wrong_id = fixture(user_id=1)
    expect_failure(wrong_id, "partial, spoofed, or changed")

    wrong_node = fixture()
    wrong_node["user"]["node_id"] = "wrong"
    expect_failure(wrong_node, "partial, spoofed, or changed")

    wrong_repo = fixture()
    wrong_repo["head"]["repo"]["full_name"] = "someone/fork"
    expect_failure(wrong_repo, "head must remain in the target repository")

    wrong_ref = fixture()
    wrong_ref["head"]["ref"] = "dependabot/pip/example-1.0"
    expect_failure(wrong_ref, "outside the reviewed github_actions namespace")

    stale = fixture()
    stale["head"]["sha"] = "b" * 40
    expect_failure(stale, "differs from the exact event/admission head")

    mutable = fixture()
    mutable["maintainer_can_modify"] = True
    expect_failure(mutable, "disable maintainer head mutation")

    associated = fixture()
    associated["author_association"] = "MEMBER"
    expect_failure(associated, "author association changed")

    zero_commits = fixture()
    zero_commits["commits"] = 0
    expect_failure(zero_commits, "at least one commit")


def main() -> int:
    self_test()
    print(
        "Dependabot PR identity self-test passed: exact bot tuple + native github_actions head identity; "
        "ordinary human PRs are deterministic not-applicable."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
