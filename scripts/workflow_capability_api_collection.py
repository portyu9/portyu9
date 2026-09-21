#!/usr/bin/env python3
"""Fail-closed validation for privileged paginated GitHub REST collections."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any, Callable

PAGE_SIZE = 100
MAX_PAGES = 30
SHA40 = re.compile(r"^[0-9a-f]{40}$")
FILE_STATUSES = {"added", "removed", "modified", "renamed", "copied", "changed", "unchanged"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def load(path: Path) -> Any:
    require(path.is_file() and not path.is_symlink(), f"API evidence is missing or aliased: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"API evidence JSON is invalid: {exc}") from exc


def positive_int(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be a positive integer")
    return value


def nonempty_string(value: Any, label: str) -> str:
    require(isinstance(value, str) and value != "", f"{label} must be a non-empty string")
    return value


def sha40(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None,
            f"{label} must be a lowercase SHA-40")
    return value


def flatten_pages(value: Any, *, label: str, require_items: bool) -> list[Any]:
    require(isinstance(value, list), f"{label} slurped response must be an array")
    require(1 <= len(value) <= MAX_PAGES,
            f"{label} page count must be between 1 and {MAX_PAGES}")
    flattened: list[Any] = []
    for index, page in enumerate(value):
        require(isinstance(page, list), f"{label} page {index + 1} must be an array")
        require(len(page) <= PAGE_SIZE, f"{label} page {index + 1} exceeds {PAGE_SIZE} items")
        if index < len(value) - 1:
            require(len(page) == PAGE_SIZE,
                    f"{label} non-final page {index + 1} is incomplete")
        flattened.extend(page)
    if require_items:
        require(flattened, f"{label} must contain at least one item")
    return flattened


def normalize_pull_requests(value: Any) -> list[dict[str, Any]]:
    entries = flatten_pages(value, label="pull-request collection", require_items=False)
    result: list[dict[str, Any]] = []
    seen: set[int] = set()
    for index, raw in enumerate(entries, start=1):
        require(isinstance(raw, dict), f"pull request item {index} must be an object")
        number = positive_int(raw.get("number"), f"pull request item {index} number")
        require(number not in seen, f"duplicate pull request number: {number}")
        seen.add(number)

        user = raw.get("user")
        base = raw.get("base")
        head = raw.get("head")
        require(isinstance(user, dict), f"pull request {number} user must be an object")
        require(isinstance(base, dict), f"pull request {number} base must be an object")
        require(isinstance(head, dict), f"pull request {number} head must be an object")
        head_repo = head.get("repo")
        require(isinstance(head_repo, dict), f"pull request {number} head repo must be an object")

        login = nonempty_string(user.get("login"), f"pull request {number} user.login")
        state = nonempty_string(raw.get("state"), f"pull request {number} state")
        require(state == "open", f"pull request {number} state must be open")
        require(type(raw.get("draft")) is bool, f"pull request {number} draft must be boolean")
        base_ref = nonempty_string(base.get("ref"), f"pull request {number} base.ref")
        base_sha = sha40(base.get("sha"), f"pull request {number} base.sha")
        head_ref = nonempty_string(head.get("ref"), f"pull request {number} head.ref")
        head_sha = sha40(head.get("sha"), f"pull request {number} head.sha")
        full_name = nonempty_string(head_repo.get("full_name"), f"pull request {number} head.repo.full_name")
        title = nonempty_string(raw.get("title"), f"pull request {number} title")
        body = raw.get("body")
        require(body is None or isinstance(body, str), f"pull request {number} body must be null or string")

        result.append({
            "number": number,
            "user": {"login": login},
            "state": state,
            "draft": raw["draft"],
            "base": {"ref": base_ref, "sha": base_sha},
            "head": {"ref": head_ref, "sha": head_sha, "repo": {"full_name": full_name}},
            "title": title,
            "body": body,
        })
    return result


def validate_filename(value: Any, label: str) -> str:
    filename = nonempty_string(value, label)
    require(not filename.startswith("/"), f"{label} must be repository-relative")
    require("\x00" not in filename and "\n" not in filename and "\r" not in filename,
            f"{label} contains a forbidden control character")
    require(all(part not in {"", ".", ".."} for part in filename.split("/")),
            f"{label} contains an invalid path segment")
    return filename


def normalize_files(value: Any) -> list[str]:
    entries = flatten_pages(value, label="pull-request file collection", require_items=True)
    result: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(entries, start=1):
        require(isinstance(raw, dict), f"file item {index} must be an object")
        filename = validate_filename(raw.get("filename"), f"file item {index} filename")
        status = raw.get("status")
        require(isinstance(status, str) and status in FILE_STATUSES,
                f"file item {index} status is invalid")
        require(filename not in seen, f"duplicate changed filename: {filename}")
        seen.add(filename)
        result.append(filename)
    return sorted(result)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"


def expect_failure(fn: Callable[[], Any], expected: str) -> None:
    try:
        fn()
    except ValueError as exc:
        require(expected in str(exc), f"self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"self-test accepted invalid API evidence: {expected}")


def pr(number: int) -> dict[str, Any]:
    return {
        "number": number,
        "user": {"login": "dependabot[bot]"},
        "state": "open",
        "draft": False,
        "base": {"ref": "main", "sha": "a" * 40},
        "head": {
            "ref": f"dependabot/github_actions/example-{number}",
            "sha": "b" * 40,
            "repo": {"full_name": "portyu9/portyu9"},
        },
        "title": f"PR {number}",
        "body": None,
    }


def file_entry(number: int) -> dict[str, Any]:
    return {"filename": f"path/{number}.txt", "status": "modified"}


def self_test() -> None:
    require(normalize_pull_requests([[]]) == [], "empty PR collection self-test changed")
    require([item["number"] for item in normalize_pull_requests([[pr(1)]])] == [1],
            "single-page PR collection self-test changed")
    full = [pr(i) for i in range(1, 101)]
    require(len(normalize_pull_requests([full, [pr(101)]])) == 101,
            "multi-page PR collection self-test changed")
    require(normalize_files([[file_entry(2), file_entry(1)]]) == ["path/1.txt", "path/2.txt"],
            "file collection canonicalization self-test changed")

    cases: list[tuple[Callable[[], Any], str]] = [
        (lambda: normalize_pull_requests({}), "slurped response must be an array"),
        (lambda: normalize_pull_requests([]), "page count must be between"),
        (lambda: normalize_pull_requests([{}]), "page 1 must be an array"),
        (lambda: normalize_pull_requests([[pr(i) for i in range(1, 100)], [pr(100)]]),
         "non-final page 1 is incomplete"),
        (lambda: normalize_pull_requests([[*full, pr(101)]]), "page 1 exceeds"),
        (lambda: normalize_pull_requests([[pr(1), pr(1)]]), "duplicate pull request number"),
        (lambda: normalize_pull_requests([[{**pr(1), "draft": "false"}]]), "draft must be boolean"),
        (lambda: normalize_pull_requests([[{**pr(1), "state": None}]]), "state must be a non-empty string"),
        (lambda: normalize_files([[]]), "must contain at least one item"),
        (lambda: normalize_files([[None]]), "must be an object"),
        (lambda: normalize_files([[{"filename": "", "status": "modified"}]]), "must be a non-empty string"),
        (lambda: normalize_files([[{"filename": "a", "status": "mystery"}]]), "status is invalid"),
        (lambda: normalize_files([[{"filename": "a", "status": "modified"},
                                   {"filename": "a", "status": "modified"}]]),
         "duplicate changed filename"),
    ]
    for fn, expected in cases:
        expect_failure(fn, expected)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    sub = value.add_subparsers(dest="command", required=True)
    pulls = sub.add_parser("pull-requests")
    pulls.add_argument("--input", type=Path, required=True)
    pulls.add_argument("--out", type=Path, required=True)
    files = sub.add_parser("files")
    files.add_argument("--input", type=Path, required=True)
    files.add_argument("--out", type=Path, required=True)
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        self_test()
        payload = load(args.input)
        if args.command == "pull-requests":
            args.out.write_text(canonical_json(normalize_pull_requests(payload)), encoding="utf-8")
        else:
            paths = normalize_files(payload)
            args.out.write_text("".join(path + "\n" for path in paths), encoding="utf-8")
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
