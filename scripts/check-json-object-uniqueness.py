#!/usr/bin/env python3
"""Fail closed on duplicate object members in source-controlled JSON contracts.

Python's default JSON decoder accepts duplicate object names and silently keeps the
last value. That behavior is unsuitable for reviewed authority/configuration files
because the bytes a reviewer sees can encode two competing values while downstream
code observes only one. This read-only gate closes the repository's JSON source
surface under ``.github`` and ``scripts`` and rejects duplicate object members at
any nesting depth before ordinary dict construction can erase them.
"""
from __future__ import annotations

import json
from pathlib import Path
import stat
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOTS = (ROOT / ".github", ROOT / "scripts")
VERSION = "source-json-object-uniqueness-v1"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def strict_json_loads(text: str) -> Any:
    return json.loads(text, object_pairs_hook=unique_json_object)


def require_real_json(path: Path) -> None:
    relative = path.relative_to(ROOT)
    require(path.exists() or path.is_symlink(), f"JSON source is missing: {relative}")
    require(path.absolute() == path.resolve(strict=True), f"JSON source resolves through an alias: {relative}")
    mode = path.lstat().st_mode
    require(stat.S_ISREG(mode) and not path.is_symlink(), f"JSON source must be a real regular file: {relative}")


def source_json_files() -> tuple[Path, ...]:
    files: list[Path] = []
    for source_root in SOURCE_ROOTS:
        require(source_root.is_dir() and not source_root.is_symlink(),
                f"JSON source root is missing or aliased: {source_root.relative_to(ROOT)}")
        for path in source_root.rglob("*.json"):
            require_real_json(path)
            files.append(path)
    ordered = tuple(sorted(files, key=lambda path: path.relative_to(ROOT).as_posix()))
    require(ordered, "source-controlled JSON inventory is empty")
    require(len(ordered) == len(set(ordered)), "source-controlled JSON inventory contains duplicate paths")
    return ordered


def validate_file(path: Path) -> None:
    require_real_json(path)
    try:
        strict_json_loads(path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError(f"{path.relative_to(ROOT)}: {exc}") from exc


def expect_json_failure(text: str, expected: str) -> None:
    try:
        strict_json_loads(text)
    except ValueError as exc:
        require(expected in str(exc), f"JSON uniqueness self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"JSON uniqueness self-test accepted ambiguous members: {expected}")


def self_test() -> None:
    parsed = strict_json_loads('{"outer":{"inner":1},"items":[{"id":"a"},{"id":"b"}]}')
    require(parsed["outer"]["inner"] == 1, "strict JSON parser changed ordinary object semantics")
    expect_json_failure('{"version":1,"version":2}', "duplicate JSON object key: version")
    expect_json_failure('{"outer":{"id":1,"id":2}}', "duplicate JSON object key: id")
    expect_json_failure('{"items":[{"name":"a","name":"b"}]}', "duplicate JSON object key: name")

    # File-shape validation must also reject aliases rather than following them.
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        target = root / "target.json"
        target.write_text("{}\n", encoding="utf-8")
        alias = root / "alias.json"
        alias.symlink_to(target)
        mode = alias.lstat().st_mode
        require(not stat.S_ISREG(mode) and alias.is_symlink(), "JSON alias fixture is malformed")


def main() -> int:
    try:
        self_test()
        files = source_json_files()
        for path in files:
            validate_file(path)
        print(
            f"Source-controlled JSON uniqueness passed: {VERSION} · {len(files)} exact .json files · "
            "duplicate object members rejected at every nesting depth"
        )
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: source-controlled JSON uniqueness failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
