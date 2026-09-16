#!/usr/bin/env python3
"""Combine trusted Dependabot identity, pin-diff, intent, and release provenance proofs.

This module is deliberately network-agnostic. Trusted callers supply the release-tag
resolver, which lets production admission reuse the repository's canonical public
release resolver without giving candidate-authored code any execution surface.
Candidate workflow bytes are data only.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
from typing import Any

from dependabot_pin_diff import classify_pin_only_update
from dependabot_pr_identity import classify_pr_identity, fixture as pr_fixture

ResolveTag = Callable[[str, str], str]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def evaluate_dependabot_admission(
    *,
    pr: Mapping[str, Any],
    repository: str,
    expected_head_sha: str,
    base_files: Mapping[str, str],
    candidate_files: Mapping[str, str],
    trusted_lock: Mapping[str, Mapping[str, str]],
    resolve_tag: ResolveTag,
) -> dict[str, object]:
    """Return deterministic not-applicable/allowed admission or fail closed.

    The function intentionally performs no I/O and never imports or executes candidate
    source. The caller must obtain PR metadata and exact base/candidate workflow blobs
    through a trusted channel and provide the canonical tag resolver separately.
    """
    identity = classify_pr_identity(
        pr,
        repository=repository,
        expected_head_sha=expected_head_sha,
    )
    if identity["classification"] == "not-applicable":
        return identity

    pin = classify_pin_only_update(base_files, candidate_files, trusted_lock)
    after = pin["after"]
    require(isinstance(after, Mapping), "Dependabot pin admission lost candidate identity")
    dependency_repository = pin["repository"]
    require(isinstance(dependency_repository, str) and dependency_repository,
            "Dependabot pin admission lost dependency repository identity")
    candidate_tag = after.get("tag")
    candidate_sha = after.get("sha")
    require(isinstance(candidate_tag, str) and isinstance(candidate_sha, str),
            "Dependabot pin admission lost candidate tag/SHA identity")

    resolved_sha = resolve_tag(dependency_repository, candidate_tag)
    require(
        resolved_sha == candidate_sha,
        "Dependabot candidate release provenance mismatch: "
        f"{dependency_repository}@{candidate_tag} resolves to {resolved_sha}, candidate pins {candidate_sha}",
    )

    return {
        "classification": "allowed",
        "repository": repository,
        "pullRequest": identity["pullRequest"],
        "headRef": identity["headRef"],
        "headSha": identity["headSha"],
        "dependencyRepository": dependency_repository,
        "before": pin["before"],
        "after": pin["after"],
        "actions": pin["actions"],
        "files": pin["files"],
        "occurrences": pin["occurrences"],
        "provenance": {
            "tag": candidate_tag,
            "resolvedSha": resolved_sha,
        },
    }


def expect_failure(call: Callable[[], object], fragment: str) -> None:
    try:
        call()
    except ValueError as exc:
        require(fragment in str(exc), f"Dependabot admission self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"Dependabot admission self-test accepted forbidden input: {fragment}")


def self_test() -> None:
    old = "a" * 40
    new = "b" * 40
    head = "c" * 40
    base = {
        ".github/workflows/codeql.yml": (
            "name: CodeQL\nsteps:\n"
            f"      - uses: github/codeql-action/init@{old} # v4.37.9\n"
            f"      - uses: github/codeql-action/analyze@{old} # v4.37.9\n"
        ),
    }
    candidate = {
        ".github/workflows/codeql.yml": (
            "name: CodeQL\nsteps:\n"
            f"      - uses: github/codeql-action/init@{new} # v4.38.0\n"
            f"      - uses: github/codeql-action/analyze@{new} # v4.38.0\n"
        ),
    }
    lock = {
        "github/codeql-action/init": {"sha": old, "tag": "v4.37.9"},
        "github/codeql-action/analyze": {"sha": old, "tag": "v4.37.9"},
    }
    pr = pr_fixture()
    pr["head"]["sha"] = head

    calls: list[tuple[str, str]] = []

    def resolver(repository: str, tag: str) -> str:
        calls.append((repository, tag))
        return new

    allowed = evaluate_dependabot_admission(
        pr=pr,
        repository="portyu9/portyu9",
        expected_head_sha=head,
        base_files=base,
        candidate_files=candidate,
        trusted_lock=lock,
        resolve_tag=resolver,
    )
    require(allowed["classification"] == "allowed", "canonical Dependabot admission did not allow")
    require(allowed["dependencyRepository"] == "github/codeql-action",
            "canonical Dependabot admission changed dependency repository")
    require(allowed["occurrences"] == 2, "canonical Dependabot admission lost atomic sub-action closure")
    require(calls == [("github/codeql-action", "v4.38.0")],
            "Dependabot admission must resolve exactly one candidate release identity")

    human = pr_fixture(login="portyu9", user_id=35150859)
    human["user"] = {
        "login": "portyu9",
        "id": 35150859,
        "node_id": "MDQ6VXNlcjM1MTUwODU5",
        "type": "User",
        "html_url": "https://github.com/portyu9",
        "url": "https://api.github.com/users/portyu9",
        "site_admin": False,
    }
    human["head"]["sha"] = head
    resolver_used = False

    def forbidden_resolver(_repository: str, _tag: str) -> str:
        nonlocal resolver_used
        resolver_used = True
        return new

    not_applicable = evaluate_dependabot_admission(
        pr=human,
        repository="portyu9/portyu9",
        expected_head_sha=head,
        base_files=base,
        candidate_files=candidate,
        trusted_lock=lock,
        resolve_tag=forbidden_resolver,
    )
    require(not_applicable == {"classification": "not-applicable", "reason": "actor-not-dependabot"},
            "ordinary human PR changed deterministic not-applicable result")
    require(not resolver_used, "not-applicable PR must not perform release provenance resolution")

    expect_failure(
        lambda: evaluate_dependabot_admission(
            pr=pr,
            repository="portyu9/portyu9",
            expected_head_sha=head,
            base_files=base,
            candidate_files=candidate,
            trusted_lock=lock,
            resolve_tag=lambda _repository, _tag: "d" * 40,
        ),
        "release provenance mismatch",
    )

    partial = dict(candidate)
    partial[".github/workflows/codeql.yml"] = (
        "name: CodeQL\nsteps:\n"
        f"      - uses: github/codeql-action/init@{new} # v4.38.0\n"
        f"      - uses: github/codeql-action/analyze@{old} # v4.37.9\n"
    )
    expect_failure(
        lambda: evaluate_dependabot_admission(
            pr=pr,
            repository="portyu9/portyu9",
            expected_head_sha=head,
            base_files=base,
            candidate_files=partial,
            trusted_lock=lock,
            resolve_tag=resolver,
        ),
        "every workflow occurrence",
    )


def main() -> int:
    self_test()
    print(
        "Dependabot combined admission self-test passed: exact bot identity, atomic immutable pin diff, "
        "forward SemVer intent, and injected canonical tag-to-SHA provenance are fail-closed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
