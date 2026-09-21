#!/usr/bin/env python3
"""Load the canonical reviewed GitHub Action release identity lock."""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / ".github/action-lock.json"
VERSION = "github-actions-identity-lock-v2"
SHA40 = re.compile(r"[0-9a-f]{40}")
SEMVER_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
ACTION_ID = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
ENTRY_KEYS = ["repositoryId", "releaseId", "sha", "tag", "tagRefSha", "tagRefType"]
TAG_REF_TYPES = {"commit", "tag"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Reject duplicate JSON members before dict construction can erase prior values."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"action identity lock JSON contains duplicate object key: {key}")
        result[key] = value
    return result


def parse_action_lock_json(text: str) -> Any:
    return json.loads(text, object_pairs_hook=unique_json_object)


def repository_for_action(action: str) -> str:
    parts = action.split("/")
    require(len(parts) >= 2, f"invalid GitHub Action identity: {action}")
    return "/".join(parts[:2])


def _positive_integer(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be a positive integer")
    return value


def _release_identity(entry: dict[str, Any], action: str) -> dict[str, Any]:
    require(isinstance(entry, dict) and set(entry) == set(ENTRY_KEYS),
            f"{action}: action identity lock entry keys changed")
    require(list(entry) == ENTRY_KEYS, f"{action}: action identity entry key ordering changed")
    repository_id = _positive_integer(entry.get("repositoryId"), f"{action}: repositoryId")
    release_id = _positive_integer(entry.get("releaseId"), f"{action}: releaseId")
    sha = entry.get("sha")
    tag = entry.get("tag")
    tag_ref_sha = entry.get("tagRefSha")
    tag_ref_type = entry.get("tagRefType")
    require(isinstance(sha, str) and SHA40.fullmatch(sha) is not None,
            f"{action}: locked SHA must be 40 lowercase hex characters")
    require(isinstance(tag, str) and SEMVER_TAG.fullmatch(tag) is not None,
            f"{action}: locked tag must be an exact semantic version")
    require(isinstance(tag_ref_sha, str) and SHA40.fullmatch(tag_ref_sha) is not None,
            f"{action}: tagRefSha must be 40 lowercase hex characters")
    require(isinstance(tag_ref_type, str) and tag_ref_type in TAG_REF_TYPES,
            f"{action}: tagRefType must be commit or tag")
    if tag_ref_type == "commit":
        require(tag_ref_sha == sha,
                f"{action}: lightweight tag ref must point directly to the pinned commit")
    else:
        require(tag_ref_sha != sha,
                f"{action}: annotated tag object identity must differ from the peeled commit")
    return {
        "repositoryId": repository_id,
        "releaseId": release_id,
        "sha": sha,
        "tag": tag,
        "tagRefSha": tag_ref_sha,
        "tagRefType": tag_ref_type,
    }


def validate_payload(payload: Any) -> dict[str, dict[str, Any]]:
    require(isinstance(payload, dict), "action identity lock must be a JSON object")
    require(set(payload) == {"version", "actions"}, "action identity lock top-level keys changed")
    require(payload.get("version") == VERSION, "action identity lock version changed")
    actions = payload.get("actions")
    require(isinstance(actions, dict) and actions, "action identity lock actions map is missing or empty")
    require(list(actions) == sorted(actions), "action identity lock must remain deterministically sorted")

    normalized: dict[str, dict[str, Any]] = {}
    repository_tags: dict[tuple[str, str], dict[str, Any]] = {}
    for action, entry in actions.items():
        require(isinstance(action, str) and ACTION_ID.fullmatch(action) is not None,
                f"invalid action identity lock key: {action!r}")
        identity = _release_identity(entry, action)
        repository = repository_for_action(action)
        key = (repository, identity["tag"])
        previous = repository_tags.get(key)
        require(previous is None or previous == identity,
                f"{repository}@{identity['tag']}: sub-actions map the same release tag to conflicting immutable identities")
        repository_tags[key] = identity
        normalized[action] = identity
    return normalized


def load_action_lock(path: Path = LOCK) -> dict[str, dict[str, Any]]:
    require(path.is_file(), f"action identity lock is missing: {path}")
    payload = parse_action_lock_json(path.read_text(encoding="utf-8"))
    return validate_payload(payload)


def action_identity(action: str, path: Path = LOCK) -> tuple[str, str]:
    actions = load_action_lock(path)
    require(action in actions, f"action is not present in canonical identity lock: {action}")
    entry = actions[action]
    return str(entry["sha"]), str(entry["tag"])


def action_release_identity(action: str, path: Path = LOCK) -> dict[str, Any]:
    actions = load_action_lock(path)
    require(action in actions, f"action is not present in canonical identity lock: {action}")
    return dict(actions[action])


def expect_json_failure(text: str, expected: str) -> None:
    try:
        parse_action_lock_json(text)
    except ValueError as exc:
        require(expected in str(exc), f"action-lock JSON self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"action-lock JSON self-test accepted ambiguous object members: {expected}")


def self_test() -> None:
    commit_sha = "a" * 40
    peeled_sha = "b" * 40
    tag_object = "c" * 40
    checkout = {
        "repositoryId": 1,
        "releaseId": 2,
        "sha": commit_sha,
        "tag": "v1.2.3",
        "tagRefSha": commit_sha,
        "tagRefType": "commit",
    }
    codeql = {
        "repositoryId": 3,
        "releaseId": 4,
        "sha": peeled_sha,
        "tag": "v4.5.6",
        "tagRefSha": tag_object,
        "tagRefType": "tag",
    }
    good = {
        "version": VERSION,
        "actions": {
            "actions/checkout": dict(checkout),
            "github/codeql-action/analyze": dict(codeql),
            "github/codeql-action/init": dict(codeql),
        },
    }
    parsed = validate_payload(good)
    require(parsed["actions/checkout"]["tag"] == "v1.2.3", "action lock self-test lost tag identity")
    require(parsed["github/codeql-action/init"]["tagRefSha"] == tag_object,
            "action lock self-test lost annotated tag-object identity")

    bad_sha = json.loads(json.dumps(good))
    bad_sha["actions"]["actions/checkout"]["sha"] = "A" * 40
    try:
        validate_payload(bad_sha)
    except ValueError:
        pass
    else:
        raise ValueError("action lock self-test accepted uppercase/noncanonical SHA")

    bad_repo_id = json.loads(json.dumps(good))
    bad_repo_id["actions"]["actions/checkout"]["repositoryId"] = True
    try:
        validate_payload(bad_repo_id)
    except ValueError:
        pass
    else:
        raise ValueError("action lock self-test accepted boolean repositoryId")

    bad_lightweight = json.loads(json.dumps(good))
    bad_lightweight["actions"]["actions/checkout"]["tagRefSha"] = "d" * 40
    try:
        validate_payload(bad_lightweight)
    except ValueError:
        pass
    else:
        raise ValueError("action lock self-test accepted lightweight tag ref not equal to commit")

    conflicting = json.loads(json.dumps(good))
    conflicting["actions"]["github/codeql-action/init"]["releaseId"] = 5
    try:
        validate_payload(conflicting)
    except ValueError:
        pass
    else:
        raise ValueError("action lock self-test accepted conflicting sub-action release identity")

    unsorted = {
        "version": VERSION,
        "actions": {
            "github/codeql-action/init": dict(codeql),
            "actions/checkout": dict(checkout),
        },
    }
    try:
        validate_payload(unsorted)
    except ValueError:
        pass
    else:
        raise ValueError("action lock self-test accepted nondeterministic action ordering")

    expect_json_failure(
        '{"version":"github-actions-identity-lock-v2","version":"other","actions":{}}',
        "duplicate object key: version",
    )
    expect_json_failure(
        '{"version":"github-actions-identity-lock-v2","actions":{"actions/checkout":{},"actions/checkout":{}}}',
        "duplicate object key: actions/checkout",
    )


if __name__ == "__main__":
    self_test()
    locked = load_action_lock()
    print(f"GitHub Action identity lock passed: {VERSION} · {len(locked)} exact action identities")
