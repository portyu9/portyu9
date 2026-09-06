#!/usr/bin/env python3
"""Load the canonical reviewed GitHub Action identity lock."""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / ".github/action-lock.json"
VERSION = "github-actions-identity-lock-v1"
SHA40 = re.compile(r"[0-9a-f]{40}")
SEMVER_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
ACTION_ID = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def repository_for_action(action: str) -> str:
    parts = action.split("/")
    require(len(parts) >= 2, f"invalid GitHub Action identity: {action}")
    return "/".join(parts[:2])


def validate_payload(payload: Any) -> dict[str, dict[str, str]]:
    require(isinstance(payload, dict), "action identity lock must be a JSON object")
    require(set(payload) == {"version", "actions"}, "action identity lock top-level keys changed")
    require(payload.get("version") == VERSION, "action identity lock version changed")
    actions = payload.get("actions")
    require(isinstance(actions, dict) and actions, "action identity lock actions map is missing or empty")
    require(list(actions) == sorted(actions), "action identity lock must remain deterministically sorted")

    normalized: dict[str, dict[str, str]] = {}
    repository_tags: dict[tuple[str, str], str] = {}
    for action, entry in actions.items():
        require(isinstance(action, str) and ACTION_ID.fullmatch(action) is not None,
                f"invalid action identity lock key: {action!r}")
        require(isinstance(entry, dict) and set(entry) == {"sha", "tag"},
                f"{action}: action identity lock entry keys changed")
        require(list(entry) == ["sha", "tag"], f"{action}: action identity entry key ordering changed")
        sha = entry.get("sha")
        tag = entry.get("tag")
        require(isinstance(sha, str) and SHA40.fullmatch(sha) is not None,
                f"{action}: locked SHA must be 40 lowercase hex characters")
        require(isinstance(tag, str) and SEMVER_TAG.fullmatch(tag) is not None,
                f"{action}: locked tag must be an exact semantic version")

        repository = repository_for_action(action)
        key = (repository, tag)
        previous = repository_tags.get(key)
        require(previous is None or previous == sha,
                f"{repository}@{tag}: sub-actions map the same release tag to conflicting SHAs")
        repository_tags[key] = sha
        normalized[action] = {"sha": sha, "tag": tag}
    return normalized


def load_action_lock(path: Path = LOCK) -> dict[str, dict[str, str]]:
    require(path.is_file(), f"action identity lock is missing: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    return validate_payload(payload)


def action_identity(action: str, path: Path = LOCK) -> tuple[str, str]:
    actions = load_action_lock(path)
    require(action in actions, f"action is not present in canonical identity lock: {action}")
    entry = actions[action]
    return entry["sha"], entry["tag"]


def self_test() -> None:
    good = {
        "version": VERSION,
        "actions": {
            "actions/checkout": {"sha": "a" * 40, "tag": "v1.2.3"},
            "github/codeql-action/analyze": {"sha": "b" * 40, "tag": "v4.5.6"},
            "github/codeql-action/init": {"sha": "b" * 40, "tag": "v4.5.6"},
        },
    }
    parsed = validate_payload(good)
    require(parsed["actions/checkout"]["tag"] == "v1.2.3", "action lock self-test lost tag identity")

    bad_sha = json.loads(json.dumps(good))
    bad_sha["actions"]["actions/checkout"]["sha"] = "A" * 40
    try:
        validate_payload(bad_sha)
    except ValueError:
        pass
    else:
        raise ValueError("action lock self-test accepted uppercase/noncanonical SHA")

    conflicting = json.loads(json.dumps(good))
    conflicting["actions"]["github/codeql-action/init"]["sha"] = "c" * 40
    try:
        validate_payload(conflicting)
    except ValueError:
        pass
    else:
        raise ValueError("action lock self-test accepted conflicting sub-action release identity")

    unsorted = {
        "version": VERSION,
        "actions": {
            "github/codeql-action/init": {"sha": "b" * 40, "tag": "v4.5.6"},
            "actions/checkout": {"sha": "a" * 40, "tag": "v1.2.3"},
        },
    }
    try:
        validate_payload(unsorted)
    except ValueError:
        pass
    else:
        raise ValueError("action lock self-test accepted nondeterministic action ordering")


if __name__ == "__main__":
    self_test()
    locked = load_action_lock()
    print(f"GitHub Action identity lock passed: {VERSION} · {len(locked)} exact action identities")
