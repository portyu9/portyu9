#!/usr/bin/env python3
"""Pure deterministic reconciliation for split native Dependabot Action-pin PRs.

The reconciler grants no repository/API authority. Trusted callers provide exact-base
workflow source and candidate file corpora from already identity-bound native Dependabot
PRs. Each fragment may update only canonical immutable uses-lines. Fragments are combined
only when they converge on one Action repository and one exact release identity, and the
combined candidate then has to pass the repository's existing atomic pin classifier.
"""
from __future__ import annotations

import copy
from typing import Mapping

from action_identity_lock import repository_for_action
from dependabot_pin_diff import classify_pin_only_update, compare_semver, parse_uses, require


def reconcile_fragments(
    base_files: Mapping[str, str],
    fragments: Mapping[int, Mapping[str, str]],
    trusted_lock: Mapping[str, Mapping[str, str]],
) -> dict[str, object]:
    require(base_files, "Dependabot reconciliation base corpus must be non-empty")
    require(len(fragments) >= 2, "Dependabot reconciliation requires at least two native fragments")

    expected_paths = set(base_files)
    reconciled = dict(base_files)
    occupied: set[tuple[str, int]] = set()
    repository: str | None = None
    target_identity: tuple[str, str] | None = None
    fragment_records: list[dict[str, object]] = []

    for pr_number in sorted(fragments):
        require(isinstance(pr_number, int) and not isinstance(pr_number, bool) and pr_number > 0,
                "Dependabot reconciliation fragment key must be a positive PR number")
        candidate = fragments[pr_number]
        require(set(candidate) == expected_paths,
                f"Dependabot fragment #{pr_number} changed workflow file inventory")

        changes: list[dict[str, object]] = []
        for path in sorted(base_files):
            base_lines = base_files[path].splitlines()
            candidate_lines = candidate[path].splitlines()
            require(len(base_lines) == len(candidate_lines),
                    f"Dependabot fragment #{pr_number} changed line cardinality in {path}")
            for line_number, (before_line, after_line) in enumerate(zip(base_lines, candidate_lines), start=1):
                if before_line == after_line:
                    continue
                coordinate = (path, line_number)
                require(coordinate not in occupied,
                        f"Dependabot fragments overlap at {path}:{line_number}")
                before = parse_uses(before_line, f"fragment #{pr_number} {path}:{line_number}:base")
                after = parse_uses(after_line, f"fragment #{pr_number} {path}:{line_number}:candidate")
                require(before["prefix"] == after["prefix"] and before["comment"] == after["comment"] and before["suffix"] == after["suffix"],
                        f"Dependabot fragment #{pr_number} changed uses-line syntax/whitespace")
                require(before["action"] == after["action"],
                        f"Dependabot fragment #{pr_number} substituted an Action path")
                require(before["sha"] != after["sha"],
                        f"Dependabot fragment #{pr_number} did not change the Action SHA")
                require(compare_semver(after["tag"], before["tag"]) > 0,
                        f"Dependabot fragment #{pr_number} did not advance SemVer")

                action = before["action"]
                locked = trusted_lock.get(action)
                require(isinstance(locked, Mapping),
                        f"Dependabot fragment #{pr_number} base Action is absent from trusted lock: {action}")
                require(locked.get("sha") == before["sha"] and locked.get("tag") == before["tag"],
                        f"Dependabot fragment #{pr_number} base identity differs from trusted lock: {action}")

                current_repository = repository_for_action(action)
                current_target = (after["sha"], after["tag"])
                if repository is None:
                    repository = current_repository
                    target_identity = current_target
                else:
                    require(current_repository == repository,
                            "Dependabot fragments target more than one Action repository")
                    require(current_target == target_identity,
                            f"{repository}: Dependabot fragments do not converge on one target release identity")

                occupied.add(coordinate)
                changes.append({
                    "path": path,
                    "line": line_number,
                    "action": action,
                    "after": {"sha": after["sha"], "tag": after["tag"]},
                })

                reconciled_lines = reconciled[path].splitlines()
                require(reconciled_lines[line_number - 1] == before_line,
                        f"Dependabot reconciliation base drifted at {path}:{line_number}")
                reconciled_lines[line_number - 1] = after_line
                reconciled[path] = "\n".join(reconciled_lines) + ("\n" if reconciled[path].endswith("\n") else "")

        require(changes, f"Dependabot fragment #{pr_number} contains no Action-pin change")
        fragment_records.append({"pullRequest": pr_number, "changes": changes})

    require(repository is not None and target_identity is not None,
            "Dependabot reconciliation produced no target release identity")
    atomic = classify_pin_only_update(base_files, reconciled, trusted_lock)
    require(atomic["repository"] == repository,
            "Dependabot reconciled candidate changed dependency repository identity")
    require((atomic["after"]["sha"], atomic["after"]["tag"]) == target_identity,  # type: ignore[index]
            "Dependabot reconciled candidate changed target release identity")

    return {
        "classification": "reconciled-github-actions-pin-update",
        "repository": repository,
        "before": copy.deepcopy(atomic["before"]),
        "after": copy.deepcopy(atomic["after"]),
        "actions": copy.deepcopy(atomic["actions"]),
        "files": copy.deepcopy(atomic["files"]),
        "occurrences": atomic["occurrences"],
        "sourcePullRequests": [record["pullRequest"] for record in fragment_records],
        "fragments": fragment_records,
        "candidateFiles": copy.deepcopy(reconciled),
    }


def expect_failure(call, fragment: str) -> None:
    try:
        call()
    except ValueError as exc:
        require(fragment in str(exc), f"reconciliation self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"reconciliation self-test accepted forbidden input: {fragment}")


def self_test() -> None:
    old = "a" * 40
    new = "b" * 40
    divergent = "c" * 40
    path = ".github/workflows/codeql.yml"
    base_text = (
        "name: CodeQL\nsteps:\n"
        f"  - uses: github/codeql-action/init@{old} # v4.37.9\n"
        f"  - uses: github/codeql-action/analyze@{old} # v4.37.9\n"
    )
    base = {path: base_text}
    init_fragment = {path: base_text.replace(
        f"github/codeql-action/init@{old} # v4.37.9",
        f"github/codeql-action/init@{new} # v4.38.0",
    )}
    analyze_fragment = {path: base_text.replace(
        f"github/codeql-action/analyze@{old} # v4.37.9",
        f"github/codeql-action/analyze@{new} # v4.38.0",
    )}
    lock = {
        "github/codeql-action/init": {"sha": old, "tag": "v4.37.9"},
        "github/codeql-action/analyze": {"sha": old, "tag": "v4.37.9"},
    }

    result = reconcile_fragments(base, {460: init_fragment, 461: analyze_fragment}, lock)
    require(result["classification"] == "reconciled-github-actions-pin-update",
            "reconciliation self-test changed classification")
    require(result["repository"] == "github/codeql-action" and result["occurrences"] == 2,
            "reconciliation self-test lost atomic CodeQL closure")
    require(result["sourcePullRequests"] == [460, 461],
            "reconciliation self-test changed source PR ordering")
    candidate = result["candidateFiles"][path]  # type: ignore[index]
    require(candidate.count(new) == 2 and candidate.count("v4.38.0") == 2,
            "reconciliation self-test failed to produce one atomic candidate release")

    divergent_fragment = {path: base_text.replace(
        f"github/codeql-action/analyze@{old} # v4.37.9",
        f"github/codeql-action/analyze@{divergent} # v4.39.0",
    )}
    expect_failure(
        lambda: reconcile_fragments(base, {460: init_fragment, 461: divergent_fragment}, lock),
        "do not converge on one target release identity",
    )
    expect_failure(
        lambda: reconcile_fragments(base, {460: init_fragment, 462: init_fragment}, lock),
        "overlap",
    )
    incomplete_base = {path: base_text + f"  - uses: github/codeql-action/upload-sarif@{old} # v4.37.9\n"}
    incomplete_init = {path: incomplete_base[path].replace(
        f"github/codeql-action/init@{old} # v4.37.9",
        f"github/codeql-action/init@{new} # v4.38.0",
    )}
    incomplete_analyze = {path: incomplete_base[path].replace(
        f"github/codeql-action/analyze@{old} # v4.37.9",
        f"github/codeql-action/analyze@{new} # v4.38.0",
    )}
    incomplete_lock = dict(lock)
    incomplete_lock["github/codeql-action/upload-sarif"] = {"sha": old, "tag": "v4.37.9"}
    expect_failure(
        lambda: reconcile_fragments(incomplete_base, {460: incomplete_init, 461: incomplete_analyze}, incomplete_lock),
        "every workflow occurrence",
    )


def main() -> int:
    self_test()
    print(
        "Dependabot reconciliation self-test passed: split native fragments may combine only when they are disjoint, "
        "trusted-base-bound, one Action repository, one target release identity, and collectively atomic across every occurrence."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
