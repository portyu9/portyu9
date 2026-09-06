#!/usr/bin/env python3
"""Load and validate the canonical generated profile-evidence subject contract."""
from __future__ import annotations

import fnmatch
import hashlib
import json
from pathlib import Path
import stat
import tempfile
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


def source_basenames(group_name: str) -> tuple[str, ...]:
    return tuple(Path(path).name for path in group_paths(group_name))


def require_unaliased_directory(root: Path, label: str) -> Path:
    absolute = root.absolute()
    resolved = root.resolve(strict=True)
    require(absolute == resolved, f"{label} must not resolve through symlink/traversal aliases: {root}")
    mode = root.lstat().st_mode
    require(stat.S_ISDIR(mode) and not root.is_symlink(), f"{label} must be a real directory: {root}")
    return resolved


def require_regular_file(path: Path, label: str) -> None:
    require(path.exists() or path.is_symlink(), f"{label} is missing: {path}")
    mode = path.lstat().st_mode
    require(stat.S_ISREG(mode) and not path.is_symlink(), f"{label} must be a real regular file: {path}")


def regular_top_level_files(directory: Path, *, label: str) -> set[str]:
    """Return exact top-level regular files; reject aliases, directories, and devices."""
    require_unaliased_directory(directory, label)
    result: set[str] = set()
    for path in directory.iterdir():
        require_regular_file(path, f"{label} entry")
        result.add(path.name)
    return result


def published_parent_paths() -> set[str]:
    parents: set[str] = set()
    for value in published_paths():
        current = Path(value).parent
        while current != Path("."):
            parents.add(current.as_posix())
            current = current.parent
    return parents


def relative_files(root: Path) -> tuple[str, ...]:
    """Return published-root files while rejecting noncanonical filesystem objects."""
    require_unaliased_directory(root, "published profile evidence root")
    paths: list[str] = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".git":
            if len(relative.parts) == 1:
                mode = path.lstat().st_mode
                require(stat.S_ISDIR(mode) and not path.is_symlink(),
                        "published profile evidence .git entry must be a real directory")
            continue
        require(not path.is_symlink(), f"published profile evidence must not contain symlinks: {relative.as_posix()}")
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        require(stat.S_ISREG(mode), f"published profile evidence contains a non-regular object: {relative.as_posix()}")
        paths.append(relative.as_posix())
    return tuple(sorted(paths))


def validate_published_root(root: Path) -> None:
    expected = set(published_paths())
    allowed_directories = published_parent_paths()
    actual = set(relative_files(root))
    require(actual == expected,
            f"published profile evidence inventory mismatch: missing={sorted(expected - actual)} unexpected={sorted(actual - expected)}")

    observed_directories: set[str] = set()
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if relative.parts and relative.parts[0] == ".git":
            continue
        if stat.S_ISDIR(path.lstat().st_mode):
            observed_directories.add(relative.as_posix())
    require(observed_directories == allowed_directories,
            "published profile evidence directory topology mismatch: "
            f"missing={sorted(allowed_directories - observed_directories)} "
            f"unexpected={sorted(observed_directories - allowed_directories)}")

    for value in expected:
        path = root / value
        require_regular_file(path, "published profile evidence subject")
        require(path.stat().st_size > 0, f"published profile evidence subject is empty: {value}")


def expect_invalid_root(root: Path, expected: str) -> None:
    try:
        validate_published_root(root)
    except ValueError as exc:
        require(expected in str(exc), f"subject filesystem self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"subject filesystem self-test accepted unsafe published root: {expected}")


def fixture_published_root(root: Path) -> None:
    for value in published_paths():
        path = root / value
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"fixture:{value}\n", encoding="utf-8")


def filesystem_self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        root = base / "published"
        root.mkdir()
        fixture_published_root(root)
        validate_published_root(root)

        # Generated-branch metadata is allowed only as a real top-level directory.
        (root / ".git").mkdir()
        (root / ".git/config").write_text("fixture\n", encoding="utf-8")
        validate_published_root(root)

        subject = root / published_paths()[0]
        original = subject.read_bytes()
        external = base / "external-subject"
        external.write_bytes(original)
        subject.unlink()
        subject.symlink_to(external)
        expect_invalid_root(root, "must not contain symlinks")
        subject.unlink()
        subject.write_bytes(original)

        extra = root / "unexpected-empty-directory"
        extra.mkdir()
        expect_invalid_root(root, "directory topology mismatch")
        extra.rmdir()

        # A root alias must not gain trust through Path.is_dir().
        alias = base / "published-alias"
        alias.symlink_to(root, target_is_directory=True)
        expect_invalid_root(alias, "symlink/traversal aliases")
        alias.unlink()

        # A generated-branch metadata alias is not exempt from the no-symlink rule.
        shutil_target = base / "fake-git"
        shutil_target.mkdir()
        for child in (root / ".git").iterdir():
            child.unlink()
        (root / ".git").rmdir()
        (root / ".git").symlink_to(shutil_target, target_is_directory=True)
        expect_invalid_root(root, ".git entry must be a real directory")


def self_test() -> None:
    manifest = load_manifest()
    require(len(published_paths()) == 11, "subject contract self-test count changed")
    require(tuple(manifest["groups"]) == EXPECTED_GROUPS, "subject contract self-test group order changed")
    require(len(manifest_digest()) == 64, "subject contract digest is malformed")
    filesystem_self_test()
    print(
        f"Profile evidence subject contract passed: {VERSION} · 11 published subjects · "
        f"structural filesystem closure · sha256:{manifest_digest()}"
    )


if __name__ == "__main__":
    self_test()
