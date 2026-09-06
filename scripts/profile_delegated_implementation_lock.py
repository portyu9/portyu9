#!/usr/bin/env python3
"""Validate the reviewed local implementation closure behind delegated profile stages.

The canonical generation manifest locks top-level stage entrypoints. Some of those
entrypoints are compatibility/CLI adapters that delegate into local implementation
modules. This contract derives each adapter's reachable local scripts/data closure and
binds every member to its reviewed Git blob identity, so changing an implementation
cannot leave the stage authority looking unchanged merely because its wrapper filename
stayed stable.
"""
from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
LOCK_PATH = SCRIPTS / "profile-delegated-implementation-lock-v1.json"
GENERATION_MANIFEST = SCRIPTS / "profile-evidence-generation-v1.json"
VERSION = "profile-delegated-implementation-lock-v1"
DELEGATED_STAGE_IDS = (
    "engineering-spotlight-generate",
    "engineering-spotlight-validate",
    "portfolio-ledger-generate",
    "portfolio-ledger-validate",
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
LOCAL_SUFFIXES = {".py", ".json"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def require_real_repository_file(relative: str) -> Path:
    rel = Path(relative)
    require(not rel.is_absolute() and ".." not in rel.parts, f"implementation path escaped repository: {relative}")
    require(len(rel.parts) == 2 and rel.parts[0] == "scripts", f"implementation path must be one scripts/ file: {relative}")
    path = ROOT / rel
    require(path.exists() or path.is_symlink(), f"implementation file is missing: {relative}")
    require(path.absolute() == path.resolve(strict=True), f"implementation file resolves through an alias: {relative}")
    mode = path.lstat().st_mode
    require(stat.S_ISREG(mode) and not path.is_symlink(), f"implementation file must be a real regular file: {relative}")
    return path


def git_blob_oid(path: Path) -> str:
    data = path.read_bytes()
    payload = f"blob {len(data)}\0".encode() + data
    return hashlib.sha1(payload, usedforsecurity=False).hexdigest()


def local_module_path(module: str) -> str | None:
    root_name = module.split(".", 1)[0]
    candidate = SCRIPTS / f"{root_name}.py"
    if candidate.is_file() and not candidate.is_symlink():
        return f"scripts/{candidate.name}"
    return None


def local_literal_path(value: str) -> str | None:
    if not value or Path(value).name != value or Path(value).suffix not in LOCAL_SUFFIXES:
        return None
    candidate = SCRIPTS / value
    if candidate.is_file() and not candidate.is_symlink():
        return f"scripts/{value}"
    return None


def walk_json_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from walk_json_strings(item)
    elif isinstance(value, dict):
        for item in value.values():
            yield from walk_json_strings(item)


def local_references(relative: str) -> set[str]:
    path = require_real_repository_file(relative)
    references: set[str] = set()
    if path.suffix == ".py":
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    candidate = local_module_path(alias.name)
                    if candidate:
                        references.add(candidate)
            elif isinstance(node, ast.ImportFrom) and node.module:
                candidate = local_module_path(node.module)
                if candidate:
                    references.add(candidate)
            elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                candidate = local_literal_path(node.value)
                if candidate:
                    references.add(candidate)
    elif path.suffix == ".json":
        payload = json.loads(path.read_text(encoding="utf-8"))
        for value in walk_json_strings(payload):
            candidate = local_literal_path(value)
            if candidate:
                references.add(candidate)
    references.discard(relative)
    return references


def derive_closure(entrypoint: str) -> tuple[str, ...]:
    pending = [entrypoint]
    discovered: set[str] = set()
    while pending:
        relative = pending.pop()
        if relative in discovered:
            continue
        require_real_repository_file(relative)
        discovered.add(relative)
        for referenced in sorted(local_references(relative), reverse=True):
            if referenced not in discovered:
                pending.append(referenced)
    return tuple(sorted(discovered))


def generation_entrypoints() -> dict[str, str]:
    payload = json.loads(GENERATION_MANIFEST.read_text(encoding="utf-8"))
    require(isinstance(payload, dict) and isinstance(payload.get("stages"), list), "generation manifest is malformed")
    result: dict[str, str] = {}
    for stage in payload["stages"]:
        require(isinstance(stage, dict), "generation manifest stage is malformed")
        stage_id = stage.get("id")
        script = stage.get("script")
        if stage_id in DELEGATED_STAGE_IDS:
            require(isinstance(script, str) and Path(script).name == script, f"{stage_id}: delegated entrypoint is malformed")
            result[str(stage_id)] = f"scripts/{script}"
    require(tuple(sorted(result)) == DELEGATED_STAGE_IDS, "delegated generation stage inventory changed")
    return result


def validate_lock(payload: Any, *, verify_blobs: bool = True) -> dict[str, Any]:
    require(isinstance(payload, dict), "implementation lock root must be an object")
    require(set(payload) == {"version", "files", "stages"}, "implementation lock keys changed")
    require(payload.get("version") == VERSION, "implementation lock version changed")
    files = payload.get("files")
    stages = payload.get("stages")
    require(isinstance(files, dict) and files, "implementation file identities are missing")
    require(isinstance(stages, dict), "implementation stage closures are missing")
    require(list(files) == sorted(files), "implementation file identities must remain sorted")
    require(tuple(stages) == DELEGATED_STAGE_IDS, "delegated implementation stage inventory changed")

    entrypoints = generation_entrypoints()
    used_files: set[str] = set()
    for stage_id in DELEGATED_STAGE_IDS:
        closure = stages.get(stage_id)
        require(isinstance(closure, list) and closure, f"{stage_id}: implementation closure is missing")
        require(all(isinstance(item, str) for item in closure), f"{stage_id}: implementation closure paths must be strings")
        require(closure == sorted(set(closure)), f"{stage_id}: implementation closure must be sorted and unique")
        expected_entrypoint = entrypoints[stage_id]
        require(expected_entrypoint in closure, f"{stage_id}: manifest entrypoint is absent from implementation closure")
        derived = derive_closure(expected_entrypoint)
        require(tuple(closure) == derived, f"{stage_id}: delegated implementation closure changed; derived={list(derived)!r}")
        used_files.update(closure)

    require(set(files) == used_files, "implementation lock contains stale or missing file identities")
    for relative, expected_oid in files.items():
        require(isinstance(expected_oid, str) and SHA40.fullmatch(expected_oid) is not None,
                f"implementation Git blob identity is malformed: {relative}")
        path = require_real_repository_file(relative)
        if verify_blobs:
            actual_oid = git_blob_oid(path)
            require(actual_oid == expected_oid,
                    f"implementation Git blob identity changed: {relative} expected={expected_oid} actual={actual_oid}")
    return payload


def load_lock() -> dict[str, Any]:
    require(LOCK_PATH.is_file() and not LOCK_PATH.is_symlink(), "delegated implementation lock is missing or aliased")
    payload = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    return validate_lock(payload)


def lock_digest() -> str:
    return hashlib.sha256(LOCK_PATH.read_bytes()).hexdigest()


def expect_failure(payload: dict[str, Any], expected: str, *, verify_blobs: bool = True) -> None:
    try:
        validate_lock(payload, verify_blobs=verify_blobs)
    except ValueError as exc:
        require(expected in str(exc), f"implementation-lock self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"implementation-lock self-test accepted drift: {expected}")


def self_test() -> None:
    payload = load_lock()
    encoded = json.dumps(payload)

    closure_drift = json.loads(encoded)
    closure_drift["stages"]["portfolio-ledger-generate"].remove("scripts/portfolio_evidence_ledger.py")
    expect_failure(closure_drift, "delegated implementation closure changed", verify_blobs=False)

    blob_drift = json.loads(encoded)
    blob_drift["files"]["scripts/portfolio_evidence_ledger.py"] = "0" * 40
    expect_failure(blob_drift, "Git blob identity changed")

    stage_drift = json.loads(encoded)
    stage_drift["stages"]["unexpected-stage"] = list(stage_drift["stages"]["portfolio-ledger-generate"])
    expect_failure(stage_drift, "stage inventory changed", verify_blobs=False)

    print(
        f"Delegated implementation authority passed: {VERSION} · {len(payload['stages'])} stages · "
        f"{len(payload['files'])} exact local files · lock_sha256={lock_digest()}"
    )


def main() -> int:
    try:
        self_test()
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError, SyntaxError) as exc:
        print(f"ERROR: delegated implementation authority failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
