#!/usr/bin/env python3
"""Pure schema boundary for governed automation-approval issue-comment evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Mapping

REPOSITORY = "portyu9/portyu9"
TRUSTED_ACTOR = "github-actions[bot]"
MARKER_RE = re.compile(r"<!-- portyu9-automation-approval:v1 head=[0-9a-f]{40} -->")


class ApprovalCommentError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ApprovalCommentError(message)


def positive_int(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be a positive integer")
    return value


def repository(value: str) -> str:
    require(value == REPOSITORY, "automation-approval repository identity changed")
    return value


def marker(value: str) -> str:
    require(
        isinstance(value, str) and MARKER_RE.fullmatch(value) is not None,
        "automation-approval marker is malformed",
    )
    return value


def issue_url(repo: str, pr_number: int) -> str:
    return f"https://api.github.com/repos/{repo}/issues/{pr_number}"


def comment_url(repo: str, comment_id: int) -> str:
    return f"https://api.github.com/repos/{repo}/issues/comments/{comment_id}"


def normalize_pages(
    value: Any,
    *,
    repo: str,
    pr_number: int,
) -> list[dict[str, Any]]:
    repo = repository(repo)
    pr_number = positive_int(pr_number, "automation-approval PR number")
    expected_issue_url = issue_url(repo, pr_number)
    require(
        isinstance(value, list),
        "automation-approval comment pages must be a slurped page array",
    )
    require(
        1 <= len(value) <= 20,
        "automation-approval comment page count must be between 1 and 20",
    )

    normalized: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    for page_index, page in enumerate(value):
        require(
            isinstance(page, list),
            f"automation-approval comment page {page_index + 1} must be an array",
        )
        require(
            len(page) <= 100,
            f"automation-approval comment page {page_index + 1} exceeds per_page=100",
        )
        if page_index + 1 < len(value):
            require(
                len(page) == 100,
                "non-final automation-approval comment page must contain exactly 100 entries",
            )
        for raw in page:
            require(
                isinstance(raw, Mapping),
                "automation-approval comment collection contains a non-object",
            )
            comment_id = positive_int(raw.get("id"), "automation-approval comment id")
            require(
                comment_id not in seen_ids,
                f"duplicate automation-approval comment id: {comment_id}",
            )
            seen_ids.add(comment_id)
            require(
                raw.get("issue_url") == expected_issue_url,
                "automation-approval comment issue URL mismatch",
            )
            require(
                raw.get("url") == comment_url(repo, comment_id),
                "automation-approval comment URL mismatch",
            )
            body = raw.get("body")
            require(
                isinstance(body, str),
                "automation-approval comment body must be a string",
            )
            user = raw.get("user")
            require(
                isinstance(user, Mapping),
                "automation-approval comment user must be an object",
            )
            login = user.get("login")
            require(
                isinstance(login, str) and bool(login),
                "automation-approval comment user.login must be non-empty",
            )
            html_url = raw.get("html_url")
            require(
                isinstance(html_url, str) and bool(html_url),
                "automation-approval comment html_url must be non-empty",
            )
            normalized.append(
                {
                    "id": comment_id,
                    "login": login,
                    "body": body,
                }
            )
    return normalized


def evidence(
    value: Any,
    *,
    repo: str,
    pr_number: int,
    expected_marker: str,
) -> dict[str, Any]:
    repo = repository(repo)
    pr_number = positive_int(pr_number, "automation-approval PR number")
    expected_marker = marker(expected_marker)
    comments = normalize_pages(value, repo=repo, pr_number=pr_number)
    matches = [
        item
        for item in comments
        if item["login"] == TRUSTED_ACTOR and expected_marker in item["body"]
    ]
    require(
        len(matches) <= 1,
        "duplicate trusted automation-approval comments exist",
    )
    return {
        "exists": len(matches) == 1,
        "commentId": matches[0]["id"] if matches else None,
        "prNumber": pr_number,
        "repository": repo,
        "marker": expected_marker,
    }


def validate_created(
    value: Any,
    *,
    repo: str,
    pr_number: int,
    expected_body: str,
) -> dict[str, Any]:
    repo = repository(repo)
    pr_number = positive_int(pr_number, "created automation-approval PR number")
    require(
        isinstance(expected_body, str) and bool(expected_body),
        "created automation-approval expected body must be non-empty",
    )
    expected_marker = marker(expected_body.split("\n", 1)[0])
    require(
        isinstance(value, Mapping),
        "created automation-approval comment response must be an object",
    )
    comment_id = positive_int(value.get("id"), "created automation-approval comment id")
    require(
        value.get("issue_url") == issue_url(repo, pr_number),
        "created automation-approval comment issue URL mismatch",
    )
    require(
        value.get("url") == comment_url(repo, comment_id),
        "created automation-approval comment URL mismatch",
    )
    require(
        value.get("body") == expected_body,
        "created automation-approval comment body mismatch",
    )
    user = value.get("user")
    require(
        isinstance(user, Mapping) and user.get("login") == TRUSTED_ACTOR,
        "created automation-approval comment actor mismatch",
    )
    html_url = value.get("html_url")
    require(
        isinstance(html_url, str) and bool(html_url),
        "created automation-approval comment html_url must be non-empty",
    )
    return {
        "id": comment_id,
        "prNumber": pr_number,
        "repository": repo,
        "actor": TRUSTED_ACTOR,
        "marker": expected_marker,
    }


def self_test() -> None:
    repo = REPOSITORY
    pr_number = 17
    head = "b" * 40
    expected_marker = f"<!-- portyu9-automation-approval:v1 head={head} -->"
    expected_body = expected_marker + "\nAutomation-approved exact head."
    fixture = {
        "id": 77,
        "issue_url": issue_url(repo, pr_number),
        "url": comment_url(repo, 77),
        "html_url": "https://github.com/portyu9/portyu9/pull/17#issuecomment-77",
        "body": expected_body,
        "user": {"login": TRUSTED_ACTOR},
    }
    require(
        evidence(
            [[fixture]],
            repo=repo,
            pr_number=pr_number,
            expected_marker=expected_marker,
        )["exists"]
        is True,
        "automation-approval positive evidence fixture changed",
    )
    human = {**fixture, "id": 78, "url": comment_url(repo, 78), "user": {"login": "portyu9"}}
    require(
        evidence(
            [[human]],
            repo=repo,
            pr_number=pr_number,
            expected_marker=expected_marker,
        )["exists"]
        is False,
        "human marker must not suppress trusted automation-approval evidence",
    )
    duplicate = {**fixture, "id": 79, "url": comment_url(repo, 79)}
    try:
        evidence(
            [[fixture, duplicate]],
            repo=repo,
            pr_number=pr_number,
            expected_marker=expected_marker,
        )
    except ApprovalCommentError as exc:
        require("duplicate trusted" in str(exc), f"duplicate fixture failed for wrong reason: {exc}")
    else:
        raise ApprovalCommentError("duplicate trusted marker fixture was accepted")

    mutations = (
        ({}, "slurped page array"),
        ([], "between 1 and 20"),
        ([[None]], "contains a non-object"),
        ([[{**fixture, "id": True}]], "positive integer"),
        ([[fixture, fixture]], "duplicate automation-approval comment id"),
        ([[{**fixture, "issue_url": "https://api.github.com/repos/other/repo/issues/17"}]], "issue URL mismatch"),
        ([[{**fixture, "url": "https://api.github.com/repos/portyu9/portyu9/issues/comments/999"}]], "comment URL mismatch"),
        ([[{**fixture, "body": None}]], "body must be a string"),
        ([[{**fixture, "user": None}]], "user must be an object"),
        ([[{**fixture, "user": {"login": ""}}]], "user.login must be non-empty"),
        ([[{**fixture, "html_url": ""}]], "html_url must be non-empty"),
    )
    for mutated, expected in mutations:
        try:
            evidence(
                mutated,
                repo=repo,
                pr_number=pr_number,
                expected_marker=expected_marker,
            )
        except ApprovalCommentError as exc:
            require(expected in str(exc), f"evidence mutation failed for wrong reason: {exc}")
        else:
            raise ApprovalCommentError(f"evidence mutation was accepted: {expected}")

    try:
        evidence([[fixture]], repo=repo, pr_number=pr_number, expected_marker="bad")
    except ApprovalCommentError as exc:
        require("marker is malformed" in str(exc), f"marker fixture failed for wrong reason: {exc}")
    else:
        raise ApprovalCommentError("malformed marker fixture was accepted")

    created = validate_created(
        fixture,
        repo=repo,
        pr_number=pr_number,
        expected_body=expected_body,
    )
    require(
        created["id"] == 77 and created["actor"] == TRUSTED_ACTOR,
        "created automation-approval positive fixture changed",
    )
    created_mutations = (
        ([], "must be an object"),
        ({**fixture, "id": 0}, "positive integer"),
        ({**fixture, "issue_url": "https://api.github.com/repos/other/repo/issues/17"}, "issue URL mismatch"),
        ({**fixture, "url": "https://api.github.com/repos/portyu9/portyu9/issues/comments/999"}, "comment URL mismatch"),
        ({**fixture, "body": "wrong"}, "body mismatch"),
        ({**fixture, "user": {"login": "portyu9"}}, "actor mismatch"),
        ({**fixture, "html_url": ""}, "html_url must be non-empty"),
    )
    for mutated, expected in created_mutations:
        try:
            validate_created(
                mutated,
                repo=repo,
                pr_number=pr_number,
                expected_body=expected_body,
            )
        except ApprovalCommentError as exc:
            require(expected in str(exc), f"created mutation failed for wrong reason: {exc}")
        else:
            raise ApprovalCommentError(f"created mutation was accepted: {expected}")


def load(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def dump(path: str, value: Any) -> None:
    Path(path).write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("evidence")
    p.add_argument("--comments-file", required=True)
    p.add_argument("--repository", required=True)
    p.add_argument("--pr-number", type=int, required=True)
    p.add_argument("--marker", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("created")
    p.add_argument("--comment-file", required=True)
    p.add_argument("--repository", required=True)
    p.add_argument("--pr-number", type=int, required=True)
    p.add_argument("--expected-body", required=True)
    p.add_argument("--out", required=True)

    sub.add_parser("self-test")

    args = parser.parse_args()
    try:
        if args.command == "evidence":
            dump(
                args.out,
                evidence(
                    load(args.comments_file),
                    repo=args.repository,
                    pr_number=args.pr_number,
                    expected_marker=args.marker,
                ),
            )
        elif args.command == "created":
            dump(
                args.out,
                validate_created(
                    load(args.comment_file),
                    repo=args.repository,
                    pr_number=args.pr_number,
                    expected_body=args.expected_body,
                ),
            )
        else:
            self_test()
            print("Governed automation-approval comment evidence self-test passed.")
        return 0
    except (OSError, json.JSONDecodeError, ApprovalCommentError) as exc:
        print(f"ERROR: {exc}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
