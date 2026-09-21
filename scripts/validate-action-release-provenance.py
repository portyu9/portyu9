#!/usr/bin/env python3
"""Verify every GitHub Action execution surface against one immutable release identity policy.

Workflow-local exact SHAs still prevent floating external execution. The canonical action
lock binds each allowed Action path to repository ID, GitHub release ID, semantic-version tag,
direct tag-ref object identity/type, and peeled immutable commit SHA. This validator proves
exact closure between workflow uses-lines and that lock, then re-reads every unique public
release through Git plus strict public GitHub REST metadata before accepting the identity.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from action_identity_lock import (
    LOCK,
    action_identity,
    load_action_lock,
    repository_for_action,
    self_test as action_lock_self_test,
)
from action_provenance_witness import self_test as action_provenance_witness_self_test
from dependabot_release import (
    resolve_identity,
    self_test as release_identity_self_test,
    validate_expected_identity,
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
PUBLIC_API_MAX_BYTES = 2_000_000


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def parse_uses_text(text: str, label: str) -> dict[str, tuple[str, str]]:
    """Return full Action path -> (pinned commit SHA, reviewed release tag)."""
    observed: dict[str, tuple[str, str]] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = USES_LINE.match(line)
        if not match:
            continue
        value = match.group(1).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1].strip()
        require(
            not value.startswith("./"),
            f"{label}:{line_number}: local action execution is forbidden until a reviewed local-action contract exists: {value}",
        )
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
    locked: dict[str, dict[str, Any]],
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


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def public_api_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "portyu9-action-release-provenance-v2",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token is None:
        return headers
    require(bool(token) and token == token.strip(),
            "GH_TOKEN must be non-empty and free of surrounding whitespace")
    require(len(token) <= 1024 and all(0x21 <= ord(character) <= 0x7E for character in token),
            "GH_TOKEN contains invalid characters")
    headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_public_api(url: str, label: str) -> str:
    request = urllib.request.Request(
        url,
        method="GET",
        headers=public_api_headers(os.environ.get("GH_TOKEN")),
    )
    opener = urllib.request.build_opener(NoRedirect())
    try:
        with opener.open(request, timeout=20) as response:
            require(response.status == 200, f"{label}: unexpected HTTP status {response.status}")
            require(response.geturl() == url, f"{label}: public API request was redirected")
            raw = response.read(PUBLIC_API_MAX_BYTES + 1)
            require(len(raw) <= PUBLIC_API_MAX_BYTES, f"{label}: public API response exceeds size bound")
            content_type = response.headers.get_content_type()
            require(content_type == "application/json",
                    f"{label}: unexpected public API content type: {content_type}")
    except urllib.error.HTTPError as exc:
        fail(f"{label}: public GitHub API returned HTTP {exc.code}")
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        fail(f"{label}: public GitHub API read failed: {exc}")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        fail(f"{label}: public GitHub API response is not UTF-8: {exc}")


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
    return completed.stdout


def validate_live_provenance(locked: dict[str, dict[str, Any]]) -> None:
    repository_tags: dict[tuple[str, str], dict[str, Any]] = {}
    for action, identity in sorted(locked.items()):
        key = (repository_for_action(action), str(identity["tag"]))
        previous = repository_tags.get(key)
        require(previous is None or previous == identity,
                f"canonical lock maps {key[0]}@{key[1]} to conflicting immutable identities")
        repository_tags[key] = identity

    for (repository, tag), expected in sorted(repository_tags.items()):
        encoded_tag = urllib.parse.quote(tag, safe="")
        repository_json = fetch_public_api(
            f"https://api.github.com/repos/{repository}",
            f"{repository}: repository identity",
        )
        release_json = fetch_public_api(
            f"https://api.github.com/repos/{repository}/releases/tags/{encoded_tag}",
            f"{repository}@{tag}: release identity",
        )
        observed = resolve_identity(
            resolve_public_tag(repository, tag),
            repository_json,
            release_json,
            repository=repository,
            tag=tag,
            expected_sha=str(expected["sha"]),
        )
        validate_expected_identity(observed, expected, label=f"{repository}@{tag}")
        print(
            f"verified {repository}@{tag} repo={observed['repositoryId']} release={observed['releaseId']} "
            f"tag-ref={observed['tagRefType']}:{observed['tagRefSha']} -> {observed['sha']}"
        )


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
    require("python3 scripts/validate-action-release-provenance.py --local-only" in text,
            "Profile Quality must execute immutable local Action provenance closure before witness reuse")
    require("python3 scripts/validate-action-release-provenance.py --live-only" in text,
            "Profile Quality must retain the full live upstream Action provenance fallback")
    require(text.count(
        "    permissions:\n"
        "      actions: read\n"
        "      attestations: read\n"
        "      contents: read\n"
    ) == 1, "Profile Quality witness consumer read authority changed")
    for phrase in (
        "Discover exact fresh signed Action provenance witness",
        'gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/action-provenance-witness.yml/runs?branch=main&status=success&per_page=100"',
        'gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/attempts/${RUN_ATTEMPT}"',
        'gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/artifacts?per_page=100"',
        "python3 scripts/action_provenance_witness.py select-run",
        "python3 scripts/action_provenance_witness.py select-artifact",
        "uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1",
        "name: action-provenance-witness-v1",
        "github-token: ${{ github.token }}",
        "digest-mismatch: error",
        'gh attestation verify "$SUBJECT"',
        "--predicate-type https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/action-provenance-witness-v1.schema.json",
        '--signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/action-provenance-witness.yml"',
        '--signer-digest "$SOURCE_SHA"',
        '--source-digest "$SOURCE_SHA"',
        "--source-ref refs/heads/main",
        "--deny-self-hosted-runners",
        "python3 scripts/action_provenance_witness.py consume-evidence",
        "if: steps.action_provenance_witness_verify.outcome != 'success'",
    ):
        require(phrase in text, f"Profile Quality witness consumer contract is missing: {phrase}")
    require('- ".github/workflows/**"' in text,
            "Profile Quality push paths must cover workflow action identity changes")
    require('- ".github/action-lock.json"' in text,
            "Profile Quality push paths must cover the canonical action identity lock")


def validate_governance(text: str) -> None:
    for phrase in (
        "## Action release provenance",
        "same-line",
        "exact semantic-version",
        "repository ID",
        "release ID",
        "tag-object",
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
    release_identity_self_test()
    action_provenance_witness_self_test()
    anonymous_headers = public_api_headers(None)
    require("Authorization" not in anonymous_headers,
            "anonymous public API headers unexpectedly contain authorization")
    authenticated_headers = public_api_headers("test-token")
    require(authenticated_headers.get("Authorization") == "Bearer test-token",
            "authenticated public API headers lost bearer binding")
    try:
        public_api_headers(" bad-token")
    except ValueError as exc:
        require("GH_TOKEN" in str(exc), "invalid GH_TOKEN self-test raised the wrong error")
    else:
        raise ValueError("public API header self-test accepted malformed GH_TOKEN")
    a = "a" * 40
    b = "b" * 40
    good = (
        f"steps:\n  - uses: actions/checkout@{a} # v7.0.1\n"
        f"  - uses: github/codeql-action/init@{b} # v4.37.9\n"
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
        "steps:\n  - uses: ./.github/actions/local\n",
        "local action execution is forbidden",
    )
    expect_parse_failure(
        f"steps:\n  - uses: actions/checkout@{a} # v7.0.1\n  - uses: actions/checkout@{b} # v7.0.1\n",
        "conflicting identities",
    )


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    mode = value.add_mutually_exclusive_group()
    mode.add_argument(
        "--local-only",
        action="store_true",
        help="Validate immutable local workflow/action-lock/governance closure without upstream reads.",
    )
    mode.add_argument(
        "--live-only",
        action="store_true",
        help="Re-prove only the exact current locked release identities from public upstreams.",
    )
    return value


def main() -> int:
    args = parser().parse_args()
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

        if not args.live_only:
            observed = discover_workflow_identities()
            validate_lock_closure(observed, locked)
            validate_governance_identity_bindings()
            validate_quality_contract(QUALITY.read_text(encoding="utf-8"))
            validate_governance(GOVERNANCE.read_text(encoding="utf-8"))

        if not args.local_only:
            validate_live_provenance(locked)

        if args.local_only:
            print(
                f"Action release provenance local closure passed for {len(locked)} exact action paths: "
                "workflow identities are closed to action-lock v2, local action execution is forbidden, "
                "and governance constants remain bound without using upstream availability."
            )
        elif args.live_only:
            print(
                f"Action release provenance live fallback passed for {len(locked)} exact action paths: "
                "every unique public release matches its immutable repository/release/tag-ref/commit identity."
            )
        else:
            print(
                f"Action release provenance validation passed for {len(locked)} exact action paths: "
                "workflow identities are closed to action-lock v2, local action execution is forbidden, governance constants are bound, "
                "and every unique public release matches its immutable repository/release/tag-ref/commit identity."
            )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
