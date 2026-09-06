#!/usr/bin/env python3
"""Verify every external GitHub Action against one canonical reviewed identity lock.

Workflow-local exact SHAs still prevent floating execution, but the repository now keeps
one versioned lock for every allowed external Action path, reviewed semantic-version tag,
and immutable commit SHA. This validator requires exact closure between that lock and all
workflow ``uses:`` entries, resolves each locked public release tag, and verifies legacy
governance constants cannot silently disagree with the canonical lock.
"""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys

from action_identity_lock import (
    LOCK,
    action_identity,
    load_action_lock,
    repository_for_action,
    self_test as action_lock_self_test,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
QUALITY = WORKFLOWS / "profile-quality.yml"
GOVERNANCE = ROOT / ".github/GOVERNANCE.md"
GOVERNANCE_VALIDATOR = ROOT / "scripts/validate-governance-contract.py"
CODEQL_VALIDATOR = ROOT / "scripts/validate-codeql-contract.py"
DEPENDENCY_REVIEW_VALIDATOR = ROOT / "scripts/validate-dependency-review-contract.py"

SHA40 = re.compile(r"[0-9a-f]{40}")
ACTION_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*")
SEMVER_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
USES_LINE = re.compile(r"^\s*(?:-\s*)?(?:['\"]?uses['\"]?)\s*:\s*(.+?)\s*$")
PROVENANCE_VALUE = re.compile(
    r"(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*)"
    r"@(?P<sha>[0-9a-f]{40})\s+#\s*(?P<tag>v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)"
)
STRING_ASSIGNMENT = re.compile(r'(?m)^(?P<name>[A-Z][A-Z0-9_]*)\s*=\s*"(?P<value>[^"]+)"\s*$')


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def parse_uses_text(text: str, label: str) -> dict[str, tuple[str, str]]:
    """Return {full_action_path: (pinned_commit_sha, reviewed_release_tag)}."""
    observed: dict[str, tuple[str, str]] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = USES_LINE.match(line)
        if not match:
            continue
        value = match.group(1).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1].strip()
        if value.startswith("./"):
            continue
        require(not value.startswith("docker://"),
                f"{label}:{line_number}: external Docker action is outside the canonical identity lock")

        provenance = PROVENANCE_VALUE.fullmatch(value)
        require(
            provenance is not None,
            f"{label}:{line_number}: external action must use exact SHA plus same-line exact release tag comment (# vX.Y.Z): {value}",
        )
        action = provenance.group("action")
        sha = provenance.group("sha")
        tag = provenance.group("tag")
        require(ACTION_NAME.fullmatch(action) is not None,
                f"{label}:{line_number}: invalid external action name: {action}")
        require(SHA40.fullmatch(sha) is not None,
                f"{label}:{line_number}: invalid action SHA: {sha}")
        require(SEMVER_TAG.fullmatch(tag) is not None,
                f"{label}:{line_number}: release annotation is not an exact semantic version: {tag}")

        identity = (sha, tag)
        previous = observed.get(action)
        require(previous is None or previous == identity,
                f"{label}:{line_number}: action path is mapped to conflicting identities: {action}")
        observed[action] = identity
    return observed


def discover_workflow_identities() -> dict[str, tuple[str, str]]:
    require(WORKFLOWS.is_dir(), ".github/workflows is missing")
    paths = sorted({*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")})
    require(paths, "No GitHub Actions workflows found")
    observed: dict[str, tuple[str, str]] = {}
    for path in paths:
        entries = parse_uses_text(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT)))
        for action, identity in entries.items():
            previous = observed.get(action)
            require(previous is None or previous == identity,
                    f"Action identity conflicts across workflows for {action}")
            observed[action] = identity
    require(observed, "No external action identities were discovered")
    return observed


def validate_lock_closure(
    observed: dict[str, tuple[str, str]],
    locked: dict[str, dict[str, str]],
) -> None:
    observed_actions = set(observed)
    locked_actions = set(locked)
    require(observed_actions == locked_actions,
            "workflow/action-lock closure changed: "
            f"unlocked={sorted(observed_actions - locked_actions)} unused={sorted(locked_actions - observed_actions)}")
    for action in sorted(locked):
        expected = (locked[action]["sha"], locked[action]["tag"])
        require(observed[action] == expected,
                f"canonical action identity mismatch for {action}: workflow={observed[action]} lock={expected}")


def resolve_public_tag(repository: str, tag: str) -> str:
    url = f"https://github.com/{repository}.git"
    direct_ref = f"refs/tags/{tag}"
    peeled_ref = f"{direct_ref}^{{}}"
    try:
        completed = subprocess.run(
            ["git", "ls-remote", "--tags", url, direct_ref, peeled_ref],
            check=False,
            capture_output=True,
            text=True,
            timeout=25,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(f"Could not resolve public release tag {repository}@{tag}: {exc}")
    require(
        completed.returncode == 0,
        f"git ls-remote failed for {repository}@{tag}: {completed.stderr.strip() or 'unknown error'}",
    )

    refs: dict[str, str] = {}
    for raw in completed.stdout.splitlines():
        fields = raw.split("\t", 1)
        require(len(fields) == 2, f"Unexpected ls-remote output for {repository}@{tag}: {raw}")
        sha, ref = fields
        require(SHA40.fullmatch(sha) is not None, f"Invalid remote SHA for {repository}@{tag}: {sha}")
        require(ref in {direct_ref, peeled_ref}, f"Unexpected remote ref for {repository}@{tag}: {ref}")
        refs[ref] = sha

    require(direct_ref in refs, f"Reviewed release tag does not exist: {repository}@{tag}")
    return refs.get(peeled_ref, refs[direct_ref])


def validate_live_provenance(locked: dict[str, dict[str, str]]) -> None:
    repository_tags: dict[tuple[str, str], str] = {}
    for action, identity in sorted(locked.items()):
        key = (repository_for_action(action), identity["tag"])
        previous = repository_tags.get(key)
        require(previous is None or previous == identity["sha"],
                f"canonical lock maps {key[0]}@{key[1]} to conflicting SHAs")
        repository_tags[key] = identity["sha"]

    for (repository, tag), pinned_sha in sorted(repository_tags.items()):
        resolved = resolve_public_tag(repository, tag)
        require(resolved == pinned_sha,
                f"Release provenance mismatch for {repository}@{tag}: tag resolves to {resolved}, lock pins {pinned_sha}")
        print(f"verified {repository}@{tag} -> {pinned_sha}")


def assignments(text: str) -> dict[str, str]:
    return {match.group("name"): match.group("value") for match in STRING_ASSIGNMENT.finditer(text)}


def validate_governance_identity_bindings() -> None:
    general = assignments(GOVERNANCE_VALIDATOR.read_text(encoding="utf-8"))
    codeql = assignments(CODEQL_VALIDATOR.read_text(encoding="utf-8"))
    dependency = assignments(DEPENDENCY_REVIEW_VALIDATOR.read_text(encoding="utf-8"))

    general_bindings = {
        "CHECKOUT_SHA": "actions/checkout",
        "SETUP_PYTHON_SHA": "actions/setup-python",
        "UPLOAD_SHA": "actions/upload-artifact",
        "DOWNLOAD_SHA": "actions/download-artifact",
        "UPSTREAM_SHA": "shinpr/github-profile-stats",
        "ATTEST_SHA": "actions/attest",
    }
    for constant, action in general_bindings.items():
        expected_sha, _ = action_identity(action)
        require(general.get(constant) == expected_sha,
                f"validate-governance-contract.py {constant} drifted from canonical action lock")

    checkout_sha, _ = action_identity("actions/checkout")
    codeql_sha, codeql_tag = action_identity("github/codeql-action/init")
    analyze_sha, analyze_tag = action_identity("github/codeql-action/analyze")
    require((codeql_sha, codeql_tag) == (analyze_sha, analyze_tag),
            "CodeQL init/analyze lock entries must share one reviewed release identity")
    require(codeql.get("CHECKOUT_SHA") == checkout_sha,
            "validate-codeql-contract.py checkout identity drifted from canonical action lock")
    require(codeql.get("CODEQL_SHA") == codeql_sha,
            "validate-codeql-contract.py CodeQL SHA drifted from canonical action lock")
    require(codeql.get("CODEQL_RELEASE") == codeql_tag,
            "validate-codeql-contract.py CodeQL release drifted from canonical action lock")

    dependency_sha, dependency_tag = action_identity("actions/dependency-review-action")
    require(dependency.get("CHECKOUT_SHA") == checkout_sha,
            "validate-dependency-review-contract.py checkout identity drifted from canonical action lock")
    require(dependency.get("DEPENDENCY_REVIEW_SHA") == dependency_sha,
            "validate-dependency-review-contract.py Action SHA drifted from canonical action lock")
    require(dependency.get("DEPENDENCY_REVIEW_RELEASE") == dependency_tag,
            "validate-dependency-review-contract.py Action release drifted from canonical action lock")


def validate_quality_contract(text: str) -> None:
    require("python3 scripts/validate-action-release-provenance.py" in text,
            "Profile Quality must execute action release provenance verification")
    require('- ".github/workflows/**"' in text,
            "Profile Quality push paths must cover workflow action identity changes")
    require('- ".github/action-lock.json"' in text,
            "Profile Quality push paths must cover the canonical action identity lock")


def validate_governance(text: str) -> None:
    for phrase in (
        "## Action release provenance",
        "same-line",
        "exact semantic-version",
        "annotated tags",
        "git ls-remote",
        "does not replace",
    ):
        require(phrase in text, f"Action release provenance governance documentation is missing: {phrase}")


def expect_parse_failure(text: str, expected_fragment: str) -> None:
    try:
        parse_uses_text(text, "self-test.yml")
    except ValueError as exc:
        require(expected_fragment in str(exc), f"Parser self-test failed for wrong reason: {exc}")
    else:
        fail(f"Parser self-test accepted forbidden provenance drift: {expected_fragment}")


def self_test() -> None:
    action_lock_self_test()
    a = "a" * 40
    b = "b" * 40
    good = (
        f"steps:\n  - uses: actions/checkout@{a} # v7.0.1\n"
        f"  - uses: github/codeql-action/init@{b} # v4.37.9\n"
        "  - uses: ./.github/actions/local\n"
    )
    observed = parse_uses_text(good, "self-test-good.yml")
    require(observed == {
        "actions/checkout": (a, "v7.0.1"),
        "github/codeql-action/init": (b, "v4.37.9"),
    }, "Parser self-test did not preserve full action/tag/SHA identity")
    expect_parse_failure(f"steps:\n  - uses: actions/checkout@{a}\n", "same-line exact release tag")
    expect_parse_failure("steps:\n  - uses: actions/checkout@v7\n", "same-line exact release tag")
    expect_parse_failure(f"steps:\n  - uses: actions/checkout@{a} # v7\n", "same-line exact release tag")
    expect_parse_failure(
        f"steps:\n  - uses: actions/checkout@{a} # v7.0.1\n  - uses: actions/checkout@{b} # v7.0.1\n",
        "conflicting identities",
    )

    locked = {
        "actions/checkout": {"sha": a, "tag": "v7.0.1"},
        "github/codeql-action/init": {"sha": b, "tag": "v4.37.9"},
    }
    validate_lock_closure(observed, locked)
    try:
        validate_lock_closure(observed, {"actions/checkout": locked["actions/checkout"]})
    except ValueError as exc:
        require("unlocked=" in str(exc), f"lock-closure self-test failed for wrong reason: {exc}")
    else:
        fail("lock-closure self-test accepted an unlocked workflow action")


def main() -> int:
    try:
        for path in (
            LOCK,
            QUALITY,
            GOVERNANCE,
            GOVERNANCE_VALIDATOR,
            CODEQL_VALIDATOR,
            DEPENDENCY_REVIEW_VALIDATOR,
        ):
            require(path.is_file(), f"Action provenance input is missing: {path.relative_to(ROOT)}")
        self_test()
        locked = load_action_lock()
        observed = discover_workflow_identities()
        validate_lock_closure(observed, locked)
        validate_governance_identity_bindings()
        validate_live_provenance(locked)
        validate_quality_contract(QUALITY.read_text(encoding="utf-8"))
        validate_governance(GOVERNANCE.read_text(encoding="utf-8"))
        print(
            f"Action release provenance validation passed for {len(locked)} exact action paths: "
            "workflow identities are closed to the canonical lock, governance constants are bound to it, "
            "and every unique public release tag resolves to the locked immutable SHA."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
