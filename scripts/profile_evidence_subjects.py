#!/usr/bin/env python3
"""Load and validate the canonical generated profile-evidence subject contract."""
from __future__ import annotations

import fnmatch
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "scripts/profile-evidence-subjects-v1.json"
VERSION = "profile-evidence-subjects-v1"
NAME = "generated-profile-evidence"
EXPECTED_GROUPS = ("signal_field", "engineering_spotlight", "portfolio_evidence_ledger")
EXPECTED_GROUP_COUNTS = {
    "signal_field": 4,
    "engineering_spotlight": 6,
    "portfolio_evidence_ledger": 1,
}
EXPECTED_INTERNAL = ("engineering-spotlight/spotlight-manifest.json",)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def manifest_digest() -> str:
    require(MANIFEST.is_file(), f"profile evidence subject manifest is missing: {MANIFEST.relative_to(ROOT)}")
    return hashlib.sha256(MANIFEST.read_bytes()).hexdigest()


def _path_list(value: Any, label: str) -> tuple[str, ...]:
    require(isinstance(value, list) and value, f"{label} must be a non-empty array")
    paths = tuple(str(item) for item in value)
    require(all(path and not path.startswith("/") and ".." not in Path(path).parts for path in paths), f"{label} contains an invalid repository-relative path")
    require(len(paths) == len(set(paths)), f"{label} contains duplicate paths")
    return paths


def load_manifest() -> dict[str, Any]:
    require(MANIFEST.is_file(), f"profile evidence subject manifest is missing: {MANIFEST.relative_to(ROOT)}")
    payload = json.loads(MANIFEST.read_text(encoding="utf-8"))
    require(isinstance(payload, dict), "profile evidence subject manifest root must be an object")
    require(payload.get("version") == VERSION, "profile evidence subject manifest version changed")
    require(payload.get("name") == NAME, "profile evidence subject-set name changed")

    published = _path_list(payload.get("published_paths"), "published_paths")
    require(len(published) == 11, "profile evidence subject contract must contain exactly eleven published paths")

    groups = payload.get("groups")
    require(isinstance(groups, dict), "profile evidence subject groups must be an object")
    require(tuple(groups) == EXPECTED_GROUPS, "profile evidence subject group order/inventory changed")

    flattened: list[str] = []
    patterns: list[str] = []
    source_arguments: list[str] = []
    for name in EXPECTED_GROUPS:
        group = groups.get(name)
        require(isinstance(group, dict), f"subject group is invalid: {name}")
        group_paths = _path_list(group.get("published_paths"), f"groups.{name}.published_paths")
        require(len(group_paths) == EXPECTED_GROUP_COUNTS[name], f"{name} subject count changed")
        flattened.extend(group_paths)
        pattern = group.get("attestation_pattern")
        require(isinstance(pattern, str) and pattern, f"{name} attestation pattern is missing")
        matched = tuple(path for path in published if fnmatch.fnmatchcase(path, pattern))
        require(matched == group_paths, f"{name} attestation pattern does not resolve to its exact reviewed paths")
        patterns.append(pattern)
        source_argument = group.get("source_argument")
        require(isinstance(source_argument, str) and source_argument, f"{name} source argument is missing")
        source_arguments.append(source_argument)

    require(tuple(flattened) == published, "group subject paths must flatten to the exact canonical published path order")
    require(len(set(patterns)) == len(patterns), "attestation patterns must be distinct")
    require(len(set(source_arguments)) == len(source_arguments), "source arguments must be distinct")

    internal = _path_list(payload.get("internal_artifacts"), "internal_artifacts")
    require(internal == EXPECTED_INTERNAL, "internal generated-evidence artifact inventory changed")
    require(not (set(internal) & set(published)), "internal artifacts cannot also be published subjects")
    require(all(not any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns) for path in internal), "attestation patterns must exclude internal-only artifacts")

    return payload


def published_paths() -> tuple[str, ...]:
    return tuple(load_manifest()["published_paths"])


def group_paths(name: str) -> tuple[str, ...]:
    manifest = load_manifest()
    groups = manifest["groups"]
    require(name in groups, f"unknown profile evidence subject group: {name}")
    return tuple(groups[name]["published_paths"])


def attestation_patterns() -> tuple[str, ...]:
    manifest = load_manifest()
    return tuple(manifest["groups"][name]["attestation_pattern"] for name in EXPECTED_GROUPS)


def internal_artifacts() -> tuple[str, ...]:
    return tuple(load_manifest()["internal_artifacts"])


def relative_files(root: Path) -> tuple[str, ...]:
    require(root.is_dir(), f"subject root is missing: {root}")
    paths: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".git":
            continue
        paths.append(relative.as_posix())
    return tuple(sorted(paths))


def validate_published_root(root: Path) -> None:
    actual = set(relative_files(root))
    expected = set(published_paths())
    require(actual == expected, f"published profile evidence inventory mismatch: missing={sorted(expected - actual)} unexpected={sorted(actual - expected)}")


def source_basenames(group_name: str) -> tuple[str, ...]:
    return tuple(Path(path).name for path in group_paths(group_name))


def self_test() -> None:
    manifest = load_manifest()
    require(len(published_paths()) == 11, "subject contract self-test count changed")
    require(tuple(manifest["groups"]) == EXPECTED_GROUPS, "subject contract self-test group order changed")
    require(len(manifest_digest()) == 64, "subject contract digest is malformed")
    print(f"Profile evidence subject contract passed: {VERSION} · 11 published subjects · sha256:{manifest_digest()}")


if __name__ == "__main__":
    self_test()
