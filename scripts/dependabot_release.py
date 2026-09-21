#!/usr/bin/env python3
"""Strict immutable public Action release identity proof.

Network access remains visible at trusted workflow/validator call sites. This module parses
captured direct/peeled Git tag refs plus GitHub repository/release JSON and binds them to one
canonical immutable release identity.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping

SHA40 = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
IDENTITY_KEYS = ("repositoryId", "releaseId", "sha", "tag", "tagRefSha", "tagRefType")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"public release JSON contains duplicate key: {key}")
        result[key] = value
    return result


def strict_json(text: str, label: str) -> Mapping[str, Any]:
    try:
        value = json.loads(text, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{label} is not valid JSON: {exc}") from exc
    require(isinstance(value, Mapping), f"{label} must be a JSON object")
    return value


def positive_int(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be a positive integer")
    return value


def parse_refs(output: str, *, repository: str, tag: str) -> dict[str, str]:
    """Parse exactly one direct tag ref and optional peeled ref without last-wins ambiguity."""
    direct = f"refs/tags/{tag}"
    peeled = f"{direct}^{{}}"
    refs: dict[str, str] = {}
    for raw in output.splitlines():
        fields = raw.split("\t", 1)
        require(len(fields) == 2, f"unexpected release-ref line for {repository}@{tag}")
        sha, ref = fields
        require(SHA40.fullmatch(sha) is not None, f"invalid release-ref SHA for {repository}@{tag}")
        require(ref in {direct, peeled}, f"unexpected release ref for {repository}@{tag}: {ref}")
        require(ref not in refs, f"duplicate release ref for {repository}@{tag}: {ref}")
        refs[ref] = sha
    require(direct in refs, f"candidate release tag does not exist: {repository}@{tag}")
    return refs


def resolve_identity(
    refs_output: str,
    repository_json: str,
    release_json: str,
    *,
    repository: str,
    tag: str,
    expected_sha: str,
) -> dict[str, Any]:
    require(REPOSITORY.fullmatch(repository) is not None, "release repository is invalid")
    require(TAG.fullmatch(tag) is not None, "release tag is invalid")
    require(SHA40.fullmatch(expected_sha) is not None, "expected release SHA is invalid")

    refs = parse_refs(refs_output, repository=repository, tag=tag)
    direct_ref = f"refs/tags/{tag}"
    peeled_ref = f"{direct_ref}^{{}}"
    direct_sha = refs[direct_ref]
    if peeled_ref in refs:
        resolved_sha = refs[peeled_ref]
        tag_ref_type = "tag"
        require(direct_sha != resolved_sha,
                f"annotated tag object unexpectedly equals peeled commit for {repository}@{tag}")
    else:
        resolved_sha = direct_sha
        tag_ref_type = "commit"
    require(
        resolved_sha == expected_sha,
        f"release provenance mismatch: {repository}@{tag} resolves to {resolved_sha}, candidate pins {expected_sha}",
    )

    repo = strict_json(repository_json, "public repository metadata")
    repository_id = positive_int(repo.get("id"), "public repository id")
    require(repo.get("full_name") == repository,
            f"public repository canonical name changed: expected {repository}, observed {repo.get('full_name')!r}")
    require(repo.get("url") == f"https://api.github.com/repos/{repository}",
            "public repository API identity URL changed")
    require(repo.get("private") is False, "reviewed GitHub Action repository is no longer public")
    require(repo.get("archived") is False, "reviewed GitHub Action repository is archived")
    require(repo.get("disabled") is False, "reviewed GitHub Action repository is disabled")

    release = strict_json(release_json, "public release metadata")
    release_id = positive_int(release.get("id"), "public release id")
    require(release.get("tag_name") == tag,
            f"public release tag changed: expected {tag}, observed {release.get('tag_name')!r}")
    require(release.get("url") == f"https://api.github.com/repos/{repository}/releases/{release_id}",
            "public release API identity URL changed")
    require(release.get("draft") is False, "reviewed public release became a draft")
    require(type(release.get("prerelease")) is bool, "public release prerelease flag is malformed")

    return {
        "repositoryId": repository_id,
        "releaseId": release_id,
        "sha": resolved_sha,
        "tag": tag,
        "tagRefSha": direct_sha,
        "tagRefType": tag_ref_type,
    }


def validate_expected_identity(
    observed: Mapping[str, Any],
    expected: Mapping[str, Any],
    *,
    label: str,
) -> None:
    require(set(observed) == set(IDENTITY_KEYS), f"{label}: observed release identity keys changed")
    require(set(expected) == set(IDENTITY_KEYS), f"{label}: expected release identity keys changed")
    for key in IDENTITY_KEYS:
        require(observed.get(key) == expected.get(key),
                f"{label}: immutable release identity mismatch for {key}: "
                f"expected={expected.get(key)!r} observed={observed.get(key)!r}")


def resolve(output: str, *, repository: str, tag: str, expected_sha: str) -> str:
    """Backward-compatible tag-to-commit parser used by older pure callers/self-tests."""
    refs = parse_refs(output, repository=repository, tag=tag)
    direct = f"refs/tags/{tag}"
    peeled = f"{direct}^{{}}"
    resolved = refs.get(peeled, refs[direct])
    require(
        resolved == expected_sha,
        f"release provenance mismatch: {repository}@{tag} resolves to {resolved}, candidate pins {expected_sha}",
    )
    return resolved


def expect_failure(call: Any, expected: str) -> None:
    try:
        call()
    except ValueError as exc:
        require(expected in str(exc), f"release identity self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"release identity self-test accepted forbidden input: {expected}")


def fixture_json(repository: str, tag: str) -> tuple[str, str]:
    repo = {
        "id": 123,
        "full_name": repository,
        "url": f"https://api.github.com/repos/{repository}",
        "private": False,
        "archived": False,
        "disabled": False,
    }
    release = {
        "id": 456,
        "tag_name": tag,
        "url": f"https://api.github.com/repos/{repository}/releases/456",
        "draft": False,
        "prerelease": False,
    }
    return json.dumps(repo), json.dumps(release)


def self_test() -> None:
    commit = "a" * 40
    tag_object = "b" * 40
    repository = "owner/repo"
    tag = "v1.2.3"
    repo_json, release_json = fixture_json(repository, tag)
    annotated = f"{tag_object}\trefs/tags/{tag}\n{commit}\trefs/tags/{tag}^{{}}\n"
    identity = resolve_identity(
        annotated,
        repo_json,
        release_json,
        repository=repository,
        tag=tag,
        expected_sha=commit,
    )
    require(identity == {
        "repositoryId": 123,
        "releaseId": 456,
        "sha": commit,
        "tag": tag,
        "tagRefSha": tag_object,
        "tagRefType": "tag",
    }, "annotated release self-test changed canonical identity")

    lightweight = f"{commit}\trefs/tags/{tag}\n"
    light_identity = resolve_identity(
        lightweight,
        repo_json,
        release_json,
        repository=repository,
        tag=tag,
        expected_sha=commit,
    )
    require(light_identity["tagRefType"] == "commit" and light_identity["tagRefSha"] == commit,
            "lightweight release self-test lost direct commit identity")

    for key, value in (
        ("repositoryId", 999),
        ("releaseId", 999),
        ("tagRefSha", "c" * 40),
        ("tagRefType", "commit"),
    ):
        changed = dict(identity)
        changed[key] = value
        expect_failure(
            lambda changed=changed: validate_expected_identity(changed, identity, label="self-test"),
            f"immutable release identity mismatch for {key}",
        )

    expect_failure(
        lambda: resolve_identity(
            annotated,
            repo_json,
            release_json,
            repository=repository,
            tag=tag,
            expected_sha="c" * 40,
        ),
        "release provenance mismatch",
    )
    expect_failure(
        lambda: parse_refs(
            f"{commit}\trefs/tags/{tag}\n{tag_object}\trefs/tags/{tag}\n",
            repository=repository,
            tag=tag,
        ),
        "duplicate release ref",
    )
    expect_failure(
        lambda: strict_json('{"id":1,"id":2}', "duplicate"),
        "duplicate key: id",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refs", type=Path, required=True)
    parser.add_argument("--repository-json", type=Path, required=True)
    parser.add_argument("--release-json", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        identity = resolve_identity(
            args.refs.read_text(encoding="utf-8"),
            args.repository_json.read_text(encoding="utf-8"),
            args.release_json.read_text(encoding="utf-8"),
            repository=args.repository,
            tag=args.tag,
            expected_sha=args.expected_sha,
        )
        args.out.write_text(json.dumps(identity, separators=(",", ":")) + "\n", encoding="utf-8")
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
