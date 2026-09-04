#!/usr/bin/env python3
"""Verify that every external GitHub Action SHA is bound to its reviewed release tag.

Exact commit SHAs prevent floating execution, but a SHA alone does not prove that the
human-readable release annotation beside it is truthful. This validator discovers all
external workflow actions, requires a same-line exact semantic-version tag annotation,
and resolves that tag from the public action repository. Lightweight and annotated tags
are both supported; annotated tags are peeled to their commit before comparison.
"""
from __future__ import annotations

from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github/workflows"
QUALITY = WORKFLOWS / "profile-quality.yml"
GOVERNANCE = ROOT / ".github/GOVERNANCE.md"

SHA40 = re.compile(r"[0-9a-fA-F]{40}")
ACTION_NAME = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.\-/]+)?")
SEMVER_TAG = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?")
USES_LINE = re.compile(r"^\s*(?:-\s*)?(?:['\"]?uses['\"]?)\s*:\s*(.+?)\s*$")
PROVENANCE_VALUE = re.compile(
    r"(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.\-/]+)?)"
    r"@(?P<sha>[0-9a-fA-F]{40})\s+#\s*(?P<tag>v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?)"
)


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def repository_for_action(action: str) -> str:
    parts = action.split("/")
    require(len(parts) >= 2, f"External action is not owner/repository syntax: {action}")
    return "/".join(parts[:2])


def parse_uses_text(text: str, label: str) -> dict[tuple[str, str], str]:
    """Return {(repository, release_tag): pinned_commit_sha} for external actions."""
    observed: dict[tuple[str, str], str] = {}
    for line_number, line in enumerate(text.splitlines(), start=1):
        match = USES_LINE.match(line)
        if not match:
            continue
        value = match.group(1).strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1].strip()
        if value.startswith("./"):
            continue
        require(not value.startswith("docker://"), f"{label}:{line_number}: external Docker action is outside release-tag provenance policy")

        provenance = PROVENANCE_VALUE.fullmatch(value)
        require(
            provenance is not None,
            f"{label}:{line_number}: external action must use exact SHA plus same-line exact release tag comment (# vX.Y.Z): {value}",
        )
        action = provenance.group("action")
        sha = provenance.group("sha").lower()
        tag = provenance.group("tag")
        require(ACTION_NAME.fullmatch(action) is not None, f"{label}:{line_number}: invalid external action name: {action}")
        require(SHA40.fullmatch(sha) is not None, f"{label}:{line_number}: invalid action SHA: {sha}")
        require(SEMVER_TAG.fullmatch(tag) is not None, f"{label}:{line_number}: release annotation is not an exact semantic version: {tag}")

        repo = repository_for_action(action)
        key = (repo, tag)
        previous = observed.get(key)
        require(
            previous is None or previous == sha,
            f"{label}:{line_number}: the same release tag is mapped to conflicting SHAs for {repo}@{tag}",
        )
        observed[key] = sha
    return observed


def discover_provenance() -> dict[tuple[str, str], str]:
    require(WORKFLOWS.is_dir(), ".github/workflows is missing")
    paths = sorted({*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")})
    require(paths, "No GitHub Actions workflows found")
    observed: dict[tuple[str, str], str] = {}
    for path in paths:
        entries = parse_uses_text(path.read_text(encoding="utf-8"), str(path.relative_to(ROOT)))
        for key, sha in entries.items():
            previous = observed.get(key)
            require(
                previous is None or previous == sha,
                f"Release provenance conflicts across workflows for {key[0]}@{key[1]}",
            )
            observed[key] = sha
    require(observed, "No external action release provenance entries were discovered")
    return observed


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
        refs[ref] = sha.lower()

    require(direct_ref in refs, f"Reviewed release tag does not exist: {repository}@{tag}")
    return refs.get(peeled_ref, refs[direct_ref])


def validate_live_provenance(entries: dict[tuple[str, str], str]) -> None:
    for (repository, tag), pinned_sha in sorted(entries.items()):
        resolved = resolve_public_tag(repository, tag)
        require(
            resolved == pinned_sha,
            f"Release provenance mismatch for {repository}@{tag}: tag resolves to {resolved}, workflow pins {pinned_sha}",
        )
        print(f"verified {repository}@{tag} -> {pinned_sha}")


def validate_quality_contract(text: str) -> None:
    require(
        "python3 scripts/validate-action-release-provenance.py" in text,
        "Profile Quality must execute action release provenance verification",
    )
    require(
        '- ".github/workflows/**"' in text,
        "Profile Quality push paths must cover action provenance changes",
    )


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
    a = "a" * 40
    b = "b" * 40
    good = (
        f"steps:\n  - uses: actions/checkout@{a} # v7.0.1\n"
        f"  - uses: github/codeql-action/init@{b} # v4.37.9\n"
        "  - uses: ./.github/actions/local\n"
    )
    observed = parse_uses_text(good, "self-test-good.yml")
    require(
        observed == {
            ("actions/checkout", "v7.0.1"): a,
            ("github/codeql-action", "v4.37.9"): b,
        },
        "Parser self-test did not preserve repository/tag/SHA provenance",
    )
    expect_parse_failure(f"steps:\n  - uses: actions/checkout@{a}\n", "same-line exact release tag")
    expect_parse_failure("steps:\n  - uses: actions/checkout@v7\n", "same-line exact release tag")
    expect_parse_failure(f"steps:\n  - uses: actions/checkout@{a} # v7\n", "same-line exact release tag")
    expect_parse_failure(
        f"steps:\n  - uses: actions/checkout@{a} # v7.0.1\n  - uses: actions/checkout@{b} # v7.0.1\n",
        "conflicting SHAs",
    )


def main() -> int:
    try:
        for path in (QUALITY, GOVERNANCE):
            require(path.is_file(), f"Action provenance input is missing: {path.relative_to(ROOT)}")
        self_test()
        entries = discover_provenance()
        validate_live_provenance(entries)
        validate_quality_contract(QUALITY.read_text(encoding="utf-8"))
        validate_governance(GOVERNANCE.read_text(encoding="utf-8"))
        print(
            f"Action release provenance validation passed for {len(entries)} unique repository/tag pairs: "
            "every executable SHA resolves from its reviewed exact release tag."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
