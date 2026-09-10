#!/usr/bin/env python3
"""Lock mutation-authority and required-assurance workflows to exact reviewed Git blobs.

Granular workflow validators remain responsible for useful structural diagnostics, but
raw source scans cannot prove that reviewed command-looking lines are the exact bytes
GitHub Actions will execute. Profile stats and Spotlight sync contain terminal mutation
authority, while Profile Quality defines the required repository-authored validation
path. Their complete workflow bytes are therefore part of the reviewed authority and
assurance contract. Any future workflow-byte change must deliberately advance this lock
in the same review.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
VERSION = "governed-workflow-byte-identity-v10"
EXPECTED = {
    ".github/workflows/profile-quality.yml": "d196c4eddb4b8f24c2f0823dfd355cf62386f1ee",
    ".github/workflows/profile-stats.yml": "820066fcd49d59fdb8849ece0d2528c2d2d691e6",
    ".github/workflows/spotlight-link-sync.yml": "ec466f2b5aab6cbf2dc01af89dbbf975ea20410b",
}

PROFILE_STATS_FRESHNESS_SEQUENCE = (
    'source_sha: ${{ steps.seal.outputs.source_sha }}',
    'source_sha="$(git -C source rev-parse HEAD)"',
    'test "$source_sha" = "$GITHUB_SHA"',
    "      - name: Publish sealed artifact commit\n"
    "        if: needs.stage.outputs.changed == 'true'\n"
    "        env:\n"
    "          GITHUB_TOKEN: ${{ github.token }}\n"
    "          SOURCE_SHA: ${{ needs.stage.outputs.source_sha }}",
    'REMOTE_MAIN="$(git -C artifacts ls-remote --exit-code origin refs/heads/main)"',
    '[[ "$REMOTE_MAIN" =~ ^([0-9a-f]{40})[[:space:]]refs/heads/main$ ]]',
    'test "${BASH_REMATCH[1]}" = "$SOURCE_SHA"',
    'push origin HEAD:generated',
)

SPOTLIGHT_PROVENANCE_SEQUENCE = (
    'codeql_check_suite_id: ${{ steps.authorize.outputs.codeql_check_suite_id }}',
    "RUNS_TOTAL=\"$(jq -r '.total_count // empty' <<<\"$RUNS\")\"",
    'test "$RUNS_TOTAL" = "$RUNS_COUNT" || {',
    'test "$RUNS_TOTAL" -le 3 || {',
    'test "$(jq -r .head_sha <<<"$RUN")" = "$HEAD_SHA"',
    'test "$(jq -r .repository.full_name <<<"$RUN")" = "$GITHUB_REPOSITORY"',
    'echo "codeql_check_suite_id=$CODEQL_CHECK_SUITE_ID" >> "$GITHUB_OUTPUT"',
    'CODEQL_CHECK_SUITE_ID: ${{ needs.approve.outputs.codeql_check_suite_id }}',
    "CHECKS_TOTAL=\"$(jq -r '.total_count // empty' <<<\"$CHECKS\")\"",
    'test "$CHECKS_TOTAL" = "$CHECKS_COUNT" || {',
    'check_suite_id:.check_suite.id',
    'test "$OBSERVED_CHECKS" = "$EXPECTED_CHECKS"',
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def git_blob_sha_bytes(payload: bytes) -> str:
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload).hexdigest()


def git_blob_sha(path: Path) -> str:
    relative = path.relative_to(ROOT)
    require(path.exists() or path.is_symlink(), f"governed workflow is missing: {relative}")
    require(path.absolute() == path.resolve(strict=True),
            f"governed workflow resolves through an alias: {relative}")
    mode = path.lstat().st_mode
    require(stat.S_ISREG(mode) and not path.is_symlink(),
            f"governed workflow must be a real regular file: {relative}")
    return git_blob_sha_bytes(path.read_bytes())


def validate_ordered_contract(text: str, fragments: tuple[str, ...], label: str) -> None:
    cursor = -1
    for fragment in fragments:
        require(text.count(fragment) == 1,
                f"{label} must contain exactly one reviewed fragment: {fragment}")
        position = text.index(fragment)
        require(position > cursor, f"{label} is out of reviewed order: {fragment}")
        cursor = position


def validate_profile_stats_freshness(text: str) -> None:
    """Keep the source-generation epoch bound to the final generated-branch push."""
    validate_ordered_contract(text, PROFILE_STATS_FRESHNESS_SEQUENCE,
                              "profile-stats source-freshness contract")


def validate_spotlight_provenance(text: str) -> None:
    """Bind exact canonical workflow runs to the required checks consumed by merge authority."""
    validate_ordered_contract(text, SPOTLIGHT_PROVENANCE_SEQUENCE,
                              "Spotlight workflow/check provenance contract")


def self_test() -> None:
    require(git_blob_sha_bytes(b"") == "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391",
            "Git blob identity self-test failed for empty bytes")
    require(git_blob_sha_bytes(b"test\n") == "9daeafb9864cf43055ae93beb0afd6c7d144bfa4",
            "Git blob identity self-test failed for canonical text bytes")
    require(git_blob_sha_bytes(b"test") != git_blob_sha_bytes(b"test\n"),
            "Git blob identity self-test lost byte-level sensitivity")

    synthetic = "\n".join(PROFILE_STATS_FRESHNESS_SEQUENCE)
    validate_profile_stats_freshness(synthetic)
    try:
        validate_profile_stats_freshness(synthetic.replace(PROFILE_STATS_FRESHNESS_SEQUENCE[-2], "", 1))
    except ValueError:
        pass
    else:
        raise ValueError("profile-stats source-freshness self-test accepted a missing terminal equality guard")

    synthetic = "\n".join(SPOTLIGHT_PROVENANCE_SEQUENCE)
    validate_spotlight_provenance(synthetic)
    try:
        validate_spotlight_provenance(synthetic.replace(SPOTLIGHT_PROVENANCE_SEQUENCE[-1], "", 1))
    except ValueError:
        pass
    else:
        raise ValueError("Spotlight provenance self-test accepted a missing exact check-map equality guard")


def main() -> int:
    try:
        self_test()
        observed: dict[str, str] = {}
        for relative, expected in EXPECTED.items():
            actual = git_blob_sha(ROOT / relative)
            require(actual == expected,
                    f"{relative}: governed workflow bytes changed; expected Git blob {expected}, got {actual}")
            observed[relative] = actual
        require(set(observed) == set(EXPECTED), "governed workflow identity inventory changed")
        validate_profile_stats_freshness(
            (ROOT / ".github/workflows/profile-stats.yml").read_text(encoding="utf-8")
        )
        validate_spotlight_provenance(
            (ROOT / ".github/workflows/spotlight-link-sync.yml").read_text(encoding="utf-8")
        )
        print(
            f"Governed workflow byte identity passed: {VERSION} · "
            f"{len(observed)} exact reviewed workflow blobs · mutation/required-check source is byte-locked · "
            "generated publication is source-epoch freshness bound · Spotlight merge checks are exact-run/suite provenance bound"
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
