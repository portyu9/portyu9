#!/usr/bin/env python3
"""Trusted evaluator for the governed-bot native review gate.

This file is intended to be fetched from the pull request's exact accepted base
SHA and executed without checking out candidate repository bytes.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

REPOSITORY = "portyu9/portyu9"
REVIEW_LOGIN = "portyu9"
API_ORIGIN = "https://api.github.com"
API_VERSION = "2022-11-28"
PER_PAGE = 100
MAX_REVIEW_PAGES = 20
POLL_ATTEMPTS = 216
POLL_SECONDS = 5

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
DEPENDABOT_REF_RE = re.compile(r"^dependabot/github_actions/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*$")
CODEQL_REF_RE = re.compile(r"^codeql-autofix/alert-[1-9][0-9]*/run-[1-9][0-9]*$")
SPOTLIGHT_REF_RE = re.compile(r"^automation/spotlight-links/[0-9a-f]{64}$")
SAFE_REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")


class GateError(ValueError):
    """A fail-closed gate invariant was violated."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise GateError(message)


def exact_int(value: Any) -> bool:
    return type(value) is int


def exact_bool(value: Any) -> bool:
    return type(value) is bool


def classify_lane(author: str, head_repository: str, head_ref: str) -> str | None:
    if head_repository != REPOSITORY:
        return None
    if author == "dependabot[bot]" and DEPENDABOT_REF_RE.fullmatch(head_ref):
        return "dependabot"
    if author == "github-actions[bot]" and CODEQL_REF_RE.fullmatch(head_ref):
        return "codeql-autofix"
    if author == "github-actions[bot]" and SPOTLIGHT_REF_RE.fullmatch(head_ref):
        return "spotlight"
    return None


def review_marker(base_sha: str, head_sha: str) -> str:
    return f"<!-- portyu9-bot-review:v2 base={base_sha} head={head_sha} -->"


def review_decision(reviews: list[Any], base_sha: str, head_sha: str) -> str:
    marker = review_marker(base_sha, head_sha)
    marker_reviews: list[dict[str, Any]] = []
    manual_decisive: list[dict[str, Any]] = []

    for item in reviews:
        require(isinstance(item, dict), "review response contains a non-object entry")
        user = item.get("user")
        if not isinstance(user, dict) or user.get("login") != REVIEW_LOGIN:
            continue
        if item.get("commit_id") != head_sha:
            continue
        body = item.get("body")
        body_text = body if isinstance(body, str) else ""
        state = item.get("state")
        if marker in body_text:
            marker_reviews.append(item)
            continue
        if state in {"APPROVED", "CHANGES_REQUESTED"}:
            review_id = item.get("id")
            require(exact_int(review_id) and review_id > 0, "manual decisive review has invalid id")
            manual_decisive.append(item)

    require(len(marker_reviews) <= 1, "multiple marker-bound portyu9 reviews exist for the exact head")

    latest_manual_state = ""
    if manual_decisive:
        latest = max(manual_decisive, key=lambda review: review["id"])
        latest_manual_state = str(latest.get("state") or "")

    if latest_manual_state == "CHANGES_REQUESTED":
        return "veto"

    if not marker_reviews:
        return "waiting"

    state = marker_reviews[0].get("state")
    if state != "APPROVED":
        return "revoked"
    return "approved"


class GitHubApi:
    def __init__(self, token: str) -> None:
        require(bool(token), "GITHUB_TOKEN is required")
        self._token = token

    def _open(self, path: str) -> tuple[Any, Any]:
        require(path.startswith("/repos/portyu9/portyu9/"), "unexpected GitHub API path")
        request = urllib.request.Request(
            API_ORIGIN + path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self._token}",
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "portyu9-governed-bot-review-gate",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.loads(response.read().decode("utf-8"))
                return payload, response.headers
        except urllib.error.HTTPError as exc:
            raise GateError(f"GitHub API GET failed with HTTP {exc.code}") from exc
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise GateError("GitHub API GET failed or returned malformed JSON") from exc

    def get(self, path: str) -> Any:
        payload, _ = self._open(path)
        return payload

    def all_reviews(self, pr_number: int) -> list[Any]:
        reviews: list[Any] = []
        for page_number in range(1, MAX_REVIEW_PAGES + 1):
            payload = self.get(
                f"/repos/{REPOSITORY}/pulls/{pr_number}/reviews?per_page={PER_PAGE}&page={page_number}"
            )
            require(isinstance(payload, list), "reviews endpoint returned a non-array")
            require(len(payload) <= PER_PAGE, "reviews page exceeded requested page size")
            reviews.extend(payload)
            if len(payload) < PER_PAGE:
                return reviews
        raise GateError("review pagination exceeded the bounded completeness limit")


def nested_string(payload: Any, *path: str) -> str:
    current = payload
    for key in path:
        require(isinstance(current, dict), f"missing object while reading {'.'.join(path)}")
        current = current.get(key)
    require(isinstance(current, str), f"missing string while reading {'.'.join(path)}")
    return current


def bind_live_pr(
    api: GitHubApi,
    *,
    pr_number: int,
    event_author: str,
    event_base_ref: str,
    event_base_sha: str,
    event_head_repository: str,
    event_head_ref: str,
    event_head_sha: str,
) -> tuple[dict[str, Any], str | None]:
    pr = api.get(f"/repos/{REPOSITORY}/pulls/{pr_number}")
    require(isinstance(pr, dict), "pull request endpoint returned a non-object")
    require(pr.get("number") == pr_number, "pull request number changed")
    require(nested_string(pr, "user", "login") == event_author, "pull request author differs from event binding")
    require(nested_string(pr, "base", "ref") == event_base_ref, "pull request base ref differs from event binding")
    require(nested_string(pr, "base", "sha") == event_base_sha, "pull request base SHA differs from event binding")
    require(
        nested_string(pr, "head", "repo", "full_name") == event_head_repository,
        "pull request head repository differs from event binding",
    )
    require(nested_string(pr, "head", "ref") == event_head_ref, "pull request head ref differs from event binding")
    require(nested_string(pr, "head", "sha") == event_head_sha, "pull request head SHA differs from event binding")
    lane = classify_lane(event_author, event_head_repository, event_head_ref)
    return pr, lane


def validate_governed_topology(
    api: GitHubApi,
    pr: dict[str, Any],
    *,
    base_sha: str,
    head_ref: str,
    head_sha: str,
) -> None:
    require(pr.get("state") == "open", "governed bot pull request is not open")
    require(exact_bool(pr.get("draft")) and pr.get("draft") is False, "governed bot pull request is draft or malformed")
    require(nested_string(pr, "base", "ref") == "main", "governed bot pull request does not target main")
    require(nested_string(pr, "head", "repo", "full_name") == REPOSITORY, "governed bot pull request is not same-repository")

    main_ref = api.get(f"/repos/{REPOSITORY}/git/ref/heads/main")
    require(nested_string(main_ref, "object", "sha") == base_sha, "current main differs from the exact PR base SHA")

    require(SAFE_REF_RE.fullmatch(head_ref) is not None, "governed bot head ref contains unsupported characters")
    encoded_ref = urllib.parse.quote(head_ref, safe="/")
    head_ref_payload = api.get(f"/repos/{REPOSITORY}/git/ref/heads/{encoded_ref}")
    require(nested_string(head_ref_payload, "object", "sha") == head_sha, "governed bot head ref moved")


def env_string(name: str) -> str:
    value = os.environ.get(name, "")
    require(bool(value), f"{name} is required")
    return value


def run_gate() -> None:
    target_repository = env_string("TARGET_REPOSITORY")
    require(target_repository == REPOSITORY, "target repository changed")

    raw_pr_number = env_string("PR_NUMBER")
    require(raw_pr_number.isdigit() and not raw_pr_number.startswith("0"), "PR_NUMBER is malformed")
    pr_number = int(raw_pr_number)
    require(pr_number > 0, "PR_NUMBER must be positive")

    event_author = env_string("EVENT_PR_AUTHOR")
    event_base_ref = env_string("EVENT_BASE_REF")
    event_base_sha = env_string("EVENT_BASE_SHA")
    event_head_repository = env_string("EVENT_HEAD_REPOSITORY")
    event_head_ref = env_string("EVENT_HEAD_REF")
    event_head_sha = env_string("EVENT_HEAD_SHA")
    require(event_base_ref == "main", "pull request does not target main")
    require(SHA_RE.fullmatch(event_base_sha) is not None, "EVENT_BASE_SHA is malformed")
    require(SHA_RE.fullmatch(event_head_sha) is not None, "EVENT_HEAD_SHA is malformed")
    require(SAFE_REF_RE.fullmatch(event_head_ref) is not None, "EVENT_HEAD_REF is malformed")

    api = GitHubApi(env_string("GITHUB_TOKEN"))

    for attempt in range(1, POLL_ATTEMPTS + 1):
        pr, lane = bind_live_pr(
            api,
            pr_number=pr_number,
            event_author=event_author,
            event_base_ref=event_base_ref,
            event_base_sha=event_base_sha,
            event_head_repository=event_head_repository,
            event_head_ref=event_head_ref,
            event_head_sha=event_head_sha,
        )
        if lane is None:
            print(
                f"trusted-governed-bot-review: not applicable to PR #{pr_number}; "
                "live PR identity matches the immutable event binding."
            )
            return

        validate_governed_topology(
            api,
            pr,
            base_sha=event_base_sha,
            head_ref=event_head_ref,
            head_sha=event_head_sha,
        )
        reviews = api.all_reviews(pr_number)
        decision = review_decision(reviews, event_base_sha, event_head_sha)

        if decision == "approved":
            # One final live topology + review re-read narrows the approval/merge race
            # and prevents success from being emitted from a stale first snapshot.
            final_pr, final_lane = bind_live_pr(
                api,
                pr_number=pr_number,
                event_author=event_author,
                event_base_ref=event_base_ref,
                event_base_sha=event_base_sha,
                event_head_repository=event_head_repository,
                event_head_ref=event_head_ref,
                event_head_sha=event_head_sha,
            )
            require(final_lane == lane, "governed bot lane changed during final review re-proof")
            validate_governed_topology(
                api,
                final_pr,
                base_sha=event_base_sha,
                head_ref=event_head_ref,
                head_sha=event_head_sha,
            )
            require(
                review_decision(api.all_reviews(pr_number), event_base_sha, event_head_sha) == "approved",
                "governed bot review state changed during final review re-proof",
            )
            print(
                f"trusted-governed-bot-review: exact {lane} PR #{pr_number} has exactly one "
                "marker-bound APPROVED review and no active latest manual veto."
            )
            return

        if decision == "veto":
            raise GateError("latest manual exact-head portyu9 review requests changes")
        if decision == "revoked":
            raise GateError("the exact marker-bound portyu9 review was dismissed or revoked")

        if attempt == POLL_ATTEMPTS:
            break
        if attempt == 1 or attempt % 24 == 0:
            print(
                f"trusted-governed-bot-review: waiting for exact marker-bound approval "
                f"for {lane} PR #{pr_number} (attempt {attempt}/{POLL_ATTEMPTS})."
            )
        time.sleep(POLL_SECONDS)

    raise GateError("exact marker-bound portyu9 approval did not arrive inside the bounded native-gate window")


def self_test() -> None:
    base = "a" * 40
    head = "b" * 40
    marker = review_marker(base, head)

    require(
        classify_lane("dependabot[bot]", REPOSITORY, "dependabot/github_actions/group") == "dependabot",
        "Dependabot lane fixture changed",
    )
    require(
        classify_lane("github-actions[bot]", REPOSITORY, "codeql-autofix/alert-4/run-123") == "codeql-autofix",
        "CodeQL Autofix lane fixture changed",
    )
    require(
        classify_lane("github-actions[bot]", REPOSITORY, "automation/spotlight-links/" + "c" * 64) == "spotlight",
        "Spotlight lane fixture changed",
    )
    require(classify_lane("portyu9", REPOSITORY, "feature/x") is None, "human PR must be not-applicable")
    require(classify_lane("dependabot[bot]", "fork/example", "dependabot/github_actions/group") is None,
            "forked Dependabot PR must be not-applicable")

    approved = {
        "id": 10,
        "user": {"login": REVIEW_LOGIN},
        "commit_id": head,
        "state": "APPROVED",
        "body": marker + "\nAutomated exact-base/head approval.",
    }
    veto = {
        "id": 11,
        "user": {"login": REVIEW_LOGIN},
        "commit_id": head,
        "state": "CHANGES_REQUESTED",
        "body": "manual veto",
    }
    lift = {
        "id": 12,
        "user": {"login": REVIEW_LOGIN},
        "commit_id": head,
        "state": "APPROVED",
        "body": "manual reconsideration",
    }
    dismissed = {**approved, "state": "DISMISSED"}

    require(review_decision([], base, head) == "waiting", "empty review fixture changed")
    require(review_decision([approved], base, head) == "approved", "marker approval fixture changed")
    require(review_decision([approved, veto], base, head) == "veto", "manual veto must dominate marker approval")
    require(
        review_decision([approved, veto, lift], base, head) == "approved",
        "latest manual APPROVED must lift an earlier manual veto",
    )
    require(review_decision([dismissed], base, head) == "revoked", "dismissed marker review fixture changed")
    try:
        review_decision([approved, {**approved, "id": 13}], base, head)
    except GateError as exc:
        require("multiple marker-bound" in str(exc), "duplicate marker review failed for the wrong reason")
    else:
        raise GateError("duplicate marker reviews were accepted")

    other_head = {**veto, "commit_id": "d" * 40}
    require(review_decision([approved, other_head], base, head) == "approved", "stale-head veto affected exact head")
    print("Governed bot review gate self-test passed.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        else:
            run_gate()
        return 0
    except GateError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
