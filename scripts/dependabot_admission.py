#!/usr/bin/env python3
"""Combine trusted Dependabot identity, pin-diff, intent, and immutable release proofs.

This module is deliberately network-agnostic. Trusted callers supply one already parsed
repository/release/tag identity. Candidate workflow bytes remain data only.
"""
from __future__ import annotations

from collections.abc import Callable, Mapping
import re
from typing import Any

from dependabot_pin_diff import classify_pin_only_update
from dependabot_pr_identity import classify_pr_identity, fixture as pr_fixture
from dependabot_release import IDENTITY_KEYS

SHA40 = re.compile(r"^[0-9a-f]{40}$")
ResolveRelease = Callable[[str, str, str], Mapping[str, Any]]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def normalize_release_identity(value: Mapping[str, Any], label: str) -> dict[str, Any]:
    require(set(value) == set(IDENTITY_KEYS), f"{label} keys changed")
    repository_id = value.get("repositoryId")
    release_id = value.get("releaseId")
    sha = value.get("sha")
    tag = value.get("tag")
    tag_ref_sha = value.get("tagRefSha")
    tag_ref_type = value.get("tagRefType")
    require(type(repository_id) is int and repository_id > 0, f"{label} repositoryId is invalid")
    require(type(release_id) is int and release_id > 0, f"{label} releaseId is invalid")
    require(isinstance(sha, str) and SHA40.fullmatch(sha) is not None, f"{label} SHA is invalid")
    require(isinstance(tag, str) and tag, f"{label} tag is invalid")
    require(isinstance(tag_ref_sha, str) and SHA40.fullmatch(tag_ref_sha) is not None,
            f"{label} tagRefSha is invalid")
    require(tag_ref_type in {"commit", "tag"}, f"{label} tagRefType is invalid")
    if tag_ref_type == "commit":
        require(tag_ref_sha == sha, f"{label} lightweight tag does not point directly to release commit")
    else:
        require(tag_ref_sha != sha, f"{label} annotated tag object collapsed to release commit")
    return {key: value[key] for key in IDENTITY_KEYS}


def trusted_base_release(
    trusted_lock: Mapping[str, Mapping[str, Any]],
    actions: list[str],
) -> dict[str, Any]:
    require(actions, "Dependabot admission has no changed Action inventory")
    identity: dict[str, Any] | None = None
    for action in actions:
        entry = trusted_lock.get(action)
        require(isinstance(entry, Mapping), f"Dependabot base Action is absent from trusted lock: {action}")
        current = normalize_release_identity(entry, f"trusted lock {action}")
        require(identity is None or current == identity,
                "Dependabot base sub-actions do not share one immutable release identity")
        identity = current
    require(identity is not None, "Dependabot admission lost trusted base release identity")
    return identity


def evaluate_dependabot_admission(
    *,
    pr: Mapping[str, Any],
    repository: str,
    expected_head_sha: str,
    base_files: Mapping[str, str],
    candidate_files: Mapping[str, str],
    trusted_lock: Mapping[str, Mapping[str, Any]],
    resolve_release: ResolveRelease,
) -> dict[str, object]:
    """Return deterministic not-applicable/allowed admission or fail closed."""
    identity = classify_pr_identity(
        pr,
        repository=repository,
        expected_head_sha=expected_head_sha,
    )
    if identity["classification"] == "not-applicable":
        return identity

    pin = classify_pin_only_update(base_files, candidate_files, trusted_lock)
    after = pin["after"]
    before = pin["before"]
    actions = pin["actions"]
    require(isinstance(after, Mapping) and isinstance(before, Mapping),
            "Dependabot pin admission lost release identities")
    require(isinstance(actions, list) and all(isinstance(action, str) for action in actions),
            "Dependabot pin admission lost Action inventory")
    dependency_repository = pin["repository"]
    require(isinstance(dependency_repository, str) and dependency_repository,
            "Dependabot pin admission lost dependency repository identity")
    candidate_tag = after.get("tag")
    candidate_sha = after.get("sha")
    require(isinstance(candidate_tag, str) and isinstance(candidate_sha, str),
            "Dependabot pin admission lost candidate tag/SHA identity")

    base_release = trusted_base_release(trusted_lock, actions)
    require(base_release["sha"] == before.get("sha") and base_release["tag"] == before.get("tag"),
            "Dependabot trusted base release differs from pin-diff identity")

    candidate_release = normalize_release_identity(
        resolve_release(dependency_repository, candidate_tag, candidate_sha),
        "Dependabot candidate release",
    )
    require(candidate_release["sha"] == candidate_sha and candidate_release["tag"] == candidate_tag,
            "Dependabot candidate release provenance mismatch")
    require(candidate_release["repositoryId"] == base_release["repositoryId"],
            "Dependabot candidate Action repository ID changed across release update")
    require(candidate_release != base_release,
            "Dependabot candidate release identity did not change")

    return {
        "classification": "allowed",
        "repository": repository,
        "pullRequest": identity["pullRequest"],
        "headRef": identity["headRef"],
        "headSha": identity["headSha"],
        "dependencyRepository": dependency_repository,
        "before": base_release,
        "after": candidate_release,
        "actions": actions,
        "files": pin["files"],
        "occurrences": pin["occurrences"],
        "provenance": dict(candidate_release),
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
    old_tag_object = "d" * 40
    new_tag_object = "e" * 40
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
    old_identity = {
        "repositoryId": 259445878,
        "releaseId": 100,
        "sha": old,
        "tag": "v4.37.9",
        "tagRefSha": old_tag_object,
        "tagRefType": "tag",
    }
    new_identity = {
        "repositoryId": 259445878,
        "releaseId": 101,
        "sha": new,
        "tag": "v4.38.0",
        "tagRefSha": new_tag_object,
        "tagRefType": "tag",
    }
    lock = {
        "github/codeql-action/init": dict(old_identity),
        "github/codeql-action/analyze": dict(old_identity),
    }
    pr = pr_fixture()
    pr["head"]["sha"] = head

    calls: list[tuple[str, str, str]] = []

    def resolver(repository: str, tag: str, expected_sha: str) -> Mapping[str, Any]:
        calls.append((repository, tag, expected_sha))
        return dict(new_identity)

    allowed = evaluate_dependabot_admission(
        pr=pr,
        repository="portyu9/portyu9",
        expected_head_sha=head,
        base_files=base,
        candidate_files=candidate,
        trusted_lock=lock,
        resolve_release=resolver,
    )
    require(allowed["classification"] == "allowed", "canonical Dependabot admission did not allow")
    require(allowed["before"] == old_identity and allowed["after"] == new_identity,
            "canonical Dependabot admission lost immutable before/after release identity")
    require(allowed["occurrences"] == 2, "canonical Dependabot admission lost atomic sub-action closure")
    require(calls == [("github/codeql-action", "v4.38.0", new)],
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

    def forbidden_resolver(_repository: str, _tag: str, _sha: str) -> Mapping[str, Any]:
        nonlocal resolver_used
        resolver_used = True
        return dict(new_identity)

    not_applicable = evaluate_dependabot_admission(
        pr=human,
        repository="portyu9/portyu9",
        expected_head_sha=head,
        base_files=base,
        candidate_files=candidate,
        trusted_lock=lock,
        resolve_release=forbidden_resolver,
    )
    require(not_applicable == {"classification": "not-applicable", "reason": "actor-not-dependabot"},
            "ordinary human PR changed deterministic not-applicable result")
    require(not resolver_used, "not-applicable PR must not perform release provenance resolution")

    wrong_repository = dict(new_identity)
    wrong_repository["repositoryId"] = 999
    expect_failure(
        lambda: evaluate_dependabot_admission(
            pr=pr,
            repository="portyu9/portyu9",
            expected_head_sha=head,
            base_files=base,
            candidate_files=candidate,
            trusted_lock=lock,
            resolve_release=lambda _repository, _tag, _sha: wrong_repository,
        ),
        "repository ID changed",
    )

    wrong_sha = dict(new_identity)
    wrong_sha["sha"] = "f" * 40
    expect_failure(
        lambda: evaluate_dependabot_admission(
            pr=pr,
            repository="portyu9/portyu9",
            expected_head_sha=head,
            base_files=base,
            candidate_files=candidate,
            trusted_lock=lock,
            resolve_release=lambda _repository, _tag, _sha: wrong_sha,
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
            resolve_release=resolver,
        ),
        "every workflow occurrence",
    )


def main() -> int:
    self_test()
    print(
        "Dependabot combined admission self-test passed: exact bot identity, atomic immutable pin diff, "
        "forward SemVer intent, and full repository/release/tag-object provenance are fail-closed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
