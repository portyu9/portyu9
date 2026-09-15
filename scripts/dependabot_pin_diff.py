#!/usr/bin/env python3
"""Classify exact GitHub Actions pin-only updates for trusted Dependabot admission.

This module is deliberately network-free. It proves the structural diff class only:
workflow source may change solely by replacing immutable external Action identities,
with one dependency repository per candidate and exact trusted-base lock binding.
Live PR/bot identity and public release provenance are separate admission layers.
"""
from __future__ import annotations

from pathlib import Path
import re
from typing import Mapping

from action_identity_lock import repository_for_action

SHA40 = re.compile(r"[0-9a-f]{40}")
SEMVER_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
ACTION = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
USES = re.compile(
    r"^(?P<prefix>\s*(?:-\s*)?(?:['\"]?uses['\"]?)\s*:\s*)"
    r"(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)"
    r"@(?P<sha>[0-9a-f]{40})(?P<comment>\s+#\s*)"
    r"(?P<tag>v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)(?P<suffix>\s*)$"
)
WORKFLOW_PATH = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def parse_uses(line: str, label: str) -> dict[str, str]:
    match = USES.fullmatch(line)
    require(match is not None, f"{label}: changed line is not one canonical immutable external Action identity")
    result = match.groupdict()
    require(ACTION.fullmatch(result["action"]) is not None, f"{label}: invalid Action path")
    require(SHA40.fullmatch(result["sha"]) is not None, f"{label}: Action ref must be exact lowercase SHA-40")
    require(SEMVER_TAG.fullmatch(result["tag"]) is not None, f"{label}: release annotation must be exact semver")
    return result


def workflow_occurrences(files: Mapping[str, str]) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for path in sorted(files):
        require(WORKFLOW_PATH.fullmatch(path) is not None, f"unsupported workflow path in pin-diff corpus: {path}")
        for line_number, line in enumerate(files[path].splitlines(), start=1):
            match = USES.fullmatch(line)
            if match is None:
                continue
            value = match.groupdict()
            result.append({
                "path": path,
                "line": line_number,
                "action": value["action"],
                "repository": repository_for_action(value["action"]),
                "sha": value["sha"],
                "tag": value["tag"],
            })
    return result


def classify_pin_only_update(
    base_files: Mapping[str, str],
    candidate_files: Mapping[str, str],
    trusted_lock: Mapping[str, Mapping[str, str]],
) -> dict[str, object]:
    """Return one canonical pin-update record or fail closed on any other source change."""
    require(base_files and candidate_files, "workflow pin-diff corpus must be non-empty")
    require(set(base_files) == set(candidate_files), "Dependabot pin update may not add/delete/rename workflow files")

    changed_paths = sorted(path for path in base_files if base_files[path] != candidate_files[path])
    require(changed_paths, "Dependabot pin update contains no workflow source change")

    changes: list[dict[str, object]] = []
    for path in changed_paths:
        require(WORKFLOW_PATH.fullmatch(path) is not None, f"Dependabot pin update changed unsupported path: {path}")
        base_lines = base_files[path].splitlines()
        candidate_lines = candidate_files[path].splitlines()
        require(len(base_lines) == len(candidate_lines), f"{path}: pin-only update changed workflow line cardinality")
        for index, (before_line, after_line) in enumerate(zip(base_lines, candidate_lines), start=1):
            if before_line == after_line:
                continue
            before = parse_uses(before_line, f"{path}:{index}:base")
            after = parse_uses(after_line, f"{path}:{index}:candidate")
            require(before["prefix"] == after["prefix"] and before["comment"] == after["comment"] and before["suffix"] == after["suffix"],
                    f"{path}:{index}: pin-only update changed uses-line syntax/whitespace")
            require(before["action"] == after["action"], f"{path}:{index}: Dependabot may not substitute the Action path")
            require(before["sha"] != after["sha"], f"{path}:{index}: candidate Action SHA did not change")
            require(before["tag"] != after["tag"], f"{path}:{index}: changed SHA under the same release tag is not an admissible update")

            action = before["action"]
            locked = trusted_lock.get(action)
            require(isinstance(locked, Mapping), f"{path}:{index}: base Action is absent from trusted action lock: {action}")
            require(locked.get("sha") == before["sha"] and locked.get("tag") == before["tag"],
                    f"{path}:{index}: base Action identity differs from trusted action lock: {action}")
            changes.append({
                "path": path,
                "line": index,
                "action": action,
                "repository": repository_for_action(action),
                "before": {"sha": before["sha"], "tag": before["tag"]},
                "after": {"sha": after["sha"], "tag": after["tag"]},
            })

    require(changes, "Dependabot pin update contained no changed Action identity")
    repositories = {str(change["repository"]) for change in changes}
    require(len(repositories) == 1, "Dependabot admission accepts exactly one Action repository per PR")
    repository = next(iter(repositories))

    base_identities = {(str(change["before"]["sha"]), str(change["before"]["tag"])) for change in changes}  # type: ignore[index]
    candidate_identities = {(str(change["after"]["sha"]), str(change["after"]["tag"])) for change in changes}  # type: ignore[index]
    require(len(base_identities) == 1, f"{repository}: trusted base sub-actions do not share one release identity")
    require(len(candidate_identities) == 1, f"{repository}: candidate sub-actions do not share one release identity")
    before_sha, before_tag = next(iter(base_identities))
    after_sha, after_tag = next(iter(candidate_identities))

    base_occurrences = [item for item in workflow_occurrences(base_files) if item["repository"] == repository]
    candidate_occurrences = [item for item in workflow_occurrences(candidate_files) if item["repository"] == repository]
    require(len(base_occurrences) == len(candidate_occurrences) == len(changes),
            f"{repository}: every workflow occurrence of the selected Action repository must update atomically")
    require(all(item["sha"] == before_sha and item["tag"] == before_tag for item in base_occurrences),
            f"{repository}: base workflow occurrences are not one trusted release identity")
    require(all(item["sha"] == after_sha and item["tag"] == after_tag for item in candidate_occurrences),
            f"{repository}: candidate workflow occurrences are not one release identity")

    actions = sorted({str(change["action"]) for change in changes})
    return {
        "classification": "github-actions-pin-update",
        "repository": repository,
        "before": {"sha": before_sha, "tag": before_tag},
        "after": {"sha": after_sha, "tag": after_tag},
        "actions": actions,
        "files": changed_paths,
        "occurrences": len(changes),
    }


def expect_failure(
    base: Mapping[str, str],
    candidate: Mapping[str, str],
    lock: Mapping[str, Mapping[str, str]],
    expected: str,
) -> None:
    try:
        classify_pin_only_update(base, candidate, lock)
    except ValueError as exc:
        require(expected in str(exc), f"pin-diff self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"pin-diff self-test accepted forbidden drift: {expected}")


def self_test() -> None:
    a = "a" * 40
    b = "b" * 40
    c = "c" * 40
    checkout_old = f"      - uses: actions/checkout@{a} # v7.0.1"
    checkout_new = f"      - uses: actions/checkout@{b} # v7.1.0"
    setup_old = f"      - uses: actions/setup-python@{a} # v7.0.0"
    setup_new = f"      - uses: actions/setup-python@{c} # v7.1.0"
    lock = {
        "actions/checkout": {"sha": a, "tag": "v7.0.1"},
        "actions/setup-python": {"sha": a, "tag": "v7.0.0"},
        "github/codeql-action/init": {"sha": a, "tag": "v4.37.9"},
        "github/codeql-action/analyze": {"sha": a, "tag": "v4.37.9"},
    }

    base = {".github/workflows/a.yml": "name: A\nsteps:\n" + checkout_old + "\n"}
    candidate = {".github/workflows/a.yml": "name: A\nsteps:\n" + checkout_new + "\n"}
    result = classify_pin_only_update(base, candidate, lock)
    require(result == {
        "classification": "github-actions-pin-update",
        "repository": "actions/checkout",
        "before": {"sha": a, "tag": "v7.0.1"},
        "after": {"sha": b, "tag": "v7.1.0"},
        "actions": ["actions/checkout"],
        "files": [".github/workflows/a.yml"],
        "occurrences": 1,
    }, "pin-diff self-test changed canonical classification")

    codeql_base = {
        ".github/workflows/a.yml": f"steps:\n      - uses: github/codeql-action/init@{a} # v4.37.9\n",
        ".github/workflows/b.yml": f"steps:\n      - uses: github/codeql-action/analyze@{a} # v4.37.9\n",
    }
    codeql_candidate = {
        ".github/workflows/a.yml": f"steps:\n      - uses: github/codeql-action/init@{b} # v4.38.0\n",
        ".github/workflows/b.yml": f"steps:\n      - uses: github/codeql-action/analyze@{b} # v4.38.0\n",
    }
    codeql = classify_pin_only_update(codeql_base, codeql_candidate, lock)
    require(codeql["repository"] == "github/codeql-action" and codeql["occurrences"] == 2,
            "pin-diff self-test failed multi-sub-action repository update")

    expect_failure(base, {".github/workflows/a.yml": "name: B\nsteps:\n" + checkout_new + "\n"}, lock,
                   "changed line is not one canonical")
    expect_failure(base, {".github/workflows/a.yml": "name: A\nsteps:\n" + setup_new + "\n"}, lock,
                   "may not substitute the Action path")
    expect_failure(base, {".github/workflows/a.yml": f"name: A\nsteps:\n      - uses: actions/checkout@{b} # v7.0.1\n"}, lock,
                   "same release tag")
    bad_lock = dict(lock)
    bad_lock["actions/checkout"] = {"sha": c, "tag": "v7.0.1"}
    expect_failure(base, candidate, bad_lock, "differs from trusted action lock")

    partial_base = {
        ".github/workflows/a.yml": "steps:\n" + checkout_old + "\n",
        ".github/workflows/b.yml": "steps:\n" + checkout_old + "\n",
    }
    partial_candidate = {
        ".github/workflows/a.yml": "steps:\n" + checkout_new + "\n",
        ".github/workflows/b.yml": "steps:\n" + checkout_old + "\n",
    }
    expect_failure(partial_base, partial_candidate, lock, "must update atomically")

    mixed_base = {".github/workflows/a.yml": "steps:\n" + checkout_old + "\n" + setup_old + "\n"}
    mixed_candidate = {".github/workflows/a.yml": "steps:\n" + checkout_new + "\n" + setup_new + "\n"}
    expect_failure(mixed_base, mixed_candidate, lock, "exactly one Action repository")

    added = dict(candidate)
    added[".github/workflows/new.yml"] = "name: new\n"
    expect_failure(base, added, lock, "may not add/delete/rename")


def main() -> int:
    self_test()
    print("Dependabot pin-diff self-test passed: exact single-repository immutable Action updates only.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
