#!/usr/bin/env python3
"""Fail closed on GitHub closing-keyword side effects in pull-request descriptions."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Callable

import automation_github_read

CLOSING_REFERENCE = re.compile(
    r"(?i)(?<![A-Za-z0-9_])"
    r"(?P<keyword>close|closes|closed|fix|fixes|fixed|resolve|resolves|resolved)"
    r"\s*:?\s+"
    r"(?:(?P<qualified>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+))?"
    r"#(?P<number>[1-9][0-9]*)\b"
)
CANONICAL_PREFIX = re.compile(r"\ACloses #(?P<number>[1-9][0-9]*)(?=$|[\s.,;:!?)])")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def closing_references(body: str) -> list[re.Match[str]]:
    return list(CLOSING_REFERENCE.finditer(body))


def lookup_same_repository_pull_request(repository: str, number: int) -> dict[str, Any] | None:
    raw = automation_github_read.get_json_text(
        f"repos/{repository}/pulls/{number}",
        allow_not_found=True,
    )
    if raw is None:
        return None
    value = automation_github_read.strict_json(raw)
    require(isinstance(value, dict), "closing-target pull-request response must be an object")
    require(
        isinstance(value.get("number"), int)
        and not isinstance(value.get("number"), bool)
        and value["number"] == number,
        "closing-target pull-request response number mismatch",
    )
    return value


def validate_body(
    body: str | None,
    repository: str,
    *,
    lookup: Callable[[str, int], dict[str, Any] | None] = lookup_same_repository_pull_request,
) -> int | None:
    require(body is None or isinstance(body, str), "pull-request body must be null or string")
    if not body:
        return None

    references = closing_references(body)
    if not references:
        return None
    require(
        len(references) == 1,
        "pull-request body must contain at most one GitHub closing-keyword directive",
    )

    reference = references[0]
    canonical = CANONICAL_PREFIX.match(body)
    require(
        canonical is not None
        and reference.start() == 0
        and reference.group("keyword") == "Closes"
        and reference.group("qualified") is None
        and int(reference.group("number")) == int(canonical.group("number")),
        "GitHub closing-keyword references are allowed only as the canonical leading 'Closes #<issue>' declaration",
    )

    target = int(reference.group("number"))
    referenced_pull = lookup(repository, target)
    require(
        referenced_pull is None,
        f"canonical closing declaration targets pull request #{target}; PR descriptions may close issues, never pull requests",
    )
    return target


def validate_event(
    event: dict[str, Any],
    repository: str,
    *,
    lookup: Callable[[str, int], dict[str, Any] | None] = lookup_same_repository_pull_request,
) -> int | None:
    require(isinstance(event, dict), "GitHub event must be an object")
    require(
        re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository) is not None,
        "repository identity must be owner/name",
    )
    pr = event.get("pull_request")
    require(isinstance(pr, dict), "GitHub event pull_request must be an object")
    number = pr.get("number")
    require(
        isinstance(number, int) and not isinstance(number, bool) and number > 0,
        "GitHub event pull-request number must be a positive integer",
    )
    base = pr.get("base")
    require(
        isinstance(base, dict) and base.get("ref") == "main",
        "closing-directive guard applies only to default-branch pull requests",
    )
    require("body" in pr, "GitHub event pull_request must contain body")
    return validate_body(pr["body"], repository, lookup=lookup)


def self_test() -> None:
    calls: list[tuple[str, int]] = []

    def issue_only(repository: str, number: int) -> None:
        calls.append((repository, number))
        return None

    require(validate_body(None, "portyu9/portyu9", lookup=issue_only) is None,
            "null body self-test changed")
    require(validate_body("No closing directive.", "portyu9/portyu9", lookup=issue_only) is None,
            "ordinary prose self-test changed")
    require(validate_body("hotfix #1149 is descriptive prose", "portyu9/portyu9", lookup=issue_only) is None,
            "non-keyword token was misclassified as a closing directive")

    calls.clear()
    target = validate_body(
        "Closes #1156. Tracks #298.\n\nCanonical issue closure.",
        "portyu9/portyu9",
        lookup=issue_only,
    )
    require(target == 1156 and calls == [("portyu9/portyu9", 1156)],
            "canonical issue-closing declaration self-test changed")

    def must_not_lookup(_repository: str, _number: int) -> dict[str, Any] | None:
        raise AssertionError("non-canonical closing directive reached GitHub lookup")

    rejected = (
        "Prior authorization for runtime fix #1149 / issue #1148.",
        "Fixes #1156.",
        "fix: #1156",
        "CLOSES #1156",
        "Closes: #1156",
        "Prefix Closes #1156.",
        "Closes portyu9/portyu9#1156.",
        "Fixes other/repository#7.",
        "Closes #1156. Later resolves #1149.",
    )
    for body in rejected:
        try:
            validate_body(body, "portyu9/portyu9", lookup=must_not_lookup)
        except ValueError as exc:
            require(
                "closing-keyword" in str(exc) or "at most one" in str(exc),
                f"non-canonical closing self-test failed for wrong reason: {body!r}: {exc}",
            )
        else:
            raise ValueError(f"non-canonical GitHub closing directive was accepted: {body!r}")

    try:
        validate_body(
            "Closes #1149.\n\nLooks canonical but targets an existing PR.",
            "portyu9/portyu9",
            lookup=lambda repository, number: {
                "number": number,
                "state": "open",
                "base": {"repo": {"full_name": repository}},
            },
        )
    except ValueError as exc:
        require("targets pull request #1149" in str(exc),
                f"PR-target self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("canonical closing declaration was allowed to target a pull request")

    event = {
        "pull_request": {
            "number": 2000,
            "base": {"ref": "main"},
            "body": "Closes #1156.\n",
        }
    }
    require(
        validate_event(event, "portyu9/portyu9", lookup=issue_only) == 1156,
        "pull-request event binding self-test changed",
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--event", type=Path)
    value.add_argument("--repository")
    value.add_argument("--self-test", action="store_true")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.self_test:
            require(args.event is None and args.repository is None,
                    "--self-test does not accept event/repository arguments")
            self_test()
            print(
                "PR closing-directive guard self-test passed: incidental/cross-repository/"
                "multi-directive closers rejected; only leading Closes #<issue> is eligible; "
                "same-repository PR targets rejected."
            )
            return 0

        require(args.event is not None and args.repository is not None,
                "--event and --repository are required")
        event = automation_github_read.strict_json(args.event.read_text(encoding="utf-8"))
        target = validate_event(event, args.repository)
        if target is None:
            print("PR closing-directive guard passed: no GitHub closing keyword present.")
        else:
            print(f"PR closing-directive guard passed: canonical issue target #{target} is not a pull request.")
        return 0
    except (ValueError, json.JSONDecodeError, OSError) as exc:
        print(f"ERROR: {exc}", file=__import__("sys").stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
