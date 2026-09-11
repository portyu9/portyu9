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
VERSION = "governed-workflow-byte-identity-v17"
EXPECTED = {
    ".github/workflows/profile-quality.yml": "492608168b403137621a5e66fd1190c35193af00",
    ".github/workflows/profile-stats.yml": "8f518c3718732efed42af0f39fea87dd5fe694fc",
    ".github/workflows/spotlight-link-sync.yml": "56491024b61c6c05b1761b796a1837f08e85c0cc",
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

SPOTLIGHT_RECONCILIATION_SEQUENCE = (
    "  reconcile:\n"
    "    name: reconcile-stale-candidates-write\n"
    "    needs: [plan, lease]",
    "    timeout-minutes: 3\n"
    "    concurrency:\n"
    "      group: spotlight-link-sync-terminal\n"
    "      cancel-in-progress: false\n"
    "      queue: max\n"
    "    permissions:\n      contents: write\n      pull-requests: write",
    'EXPECTED_CANDIDATE_BRANCH=""',
    'STALE_AFTER_SECONDS=1800',
    'REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${BOT_BRANCH_PREFIX}")"',
    'test "$REF_COUNT" -le 20 || {',
    '(.ref | test("^refs/heads/automation/spotlight-links/[0-9a-f]{64}$") | not)',
    'CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"\n'
    '            test "$(jq \' .parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"\n'
    '            PARENT_SHA="$(jq -r \'.parents[0].sha\' <<<"$CANDIDATE_COMMIT")"'.replace("' .parents", "'.parents"),
    'if [ "$AGE_SECONDS" -lt "$STALE_AFTER_SECONDS" ]; then',
    'COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${PARENT_SHA}...${HEAD_SHA}")"',
    'PRS="$(gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:${BRANCH}&base=main&per_page=2")"',
    'test "$(jq -r .user.login <<<"$PR")" = "github-actions[bot]"',
    'CLOSED_PR="$(gh api --method PATCH "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}" --input close-pr.json)"',
    'gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${BRANCH}" >/dev/null',
    'test "$REMAINING_EXACT" = "0"',
    'needs: [plan, lease, reconcile, budget]',
)

SPOTLIGHT_MUTATION_BUDGET_SEQUENCE = (
    'name: spotlight-link-plan-${{ steps.render.outputs.base_sha }}-${{ steps.render.outputs.generated_sha }}',
    "  budget:\n"
    "    if: needs.plan.outputs.changed == 'true'\n"
    "    name: mutation-budget-read-only",
    "    permissions:\n"
    "      actions: read\n"
    "    outputs:\n"
    "      allowed: ${{ steps.admit.outputs.allowed }}",
    'ARTIFACT_NAME="spotlight-link-plan-${BASE_SHA}-${GENERATED_SHA}"',
    "MAX_ATTEMPTS=2",
    'ARTIFACTS="$(gh api "repos/${GITHUB_REPOSITORY}/actions/artifacts?name=${ARTIFACT_NAME}&per_page=100")"',
    'test "$TOTAL" = "$COUNT" || {',
    'test "$CURRENT" = "1" || {',
    'echo "allowed=$ALLOWED" >> "$GITHUB_OUTPUT"',
    "  quarantine:\n"
    "    if: always() && needs.plan.outputs.changed == 'true' && needs.budget.result == 'success' && needs.budget.outputs.allowed != 'true'\n"
    "    name: mutation-budget-quarantine-read-only",
    "    if: needs.plan.outputs.changed == 'true' && needs.budget.outputs.allowed == 'true'\n"
    "    name: propose-readme-only-write",
    'APPROVAL_REQUESTED_RUN_IDS=""',
    'case " $APPROVAL_REQUESTED_RUN_IDS " in',
    'APPROVAL_REQUESTED_RUN_IDS="${APPROVAL_REQUESTED_RUN_IDS} ${RUN_ID}"',
    "    if: needs.plan.outputs.changed == 'true' && needs.budget.outputs.allowed == 'true' && needs.propose.result == 'success' && needs.approve.result == 'success'\n"
    "    name: merge-readme-only-terminal-write",
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

SPOTLIGHT_IMMUTABLE_CANDIDATE_SEQUENCE = (
    'BOT_BRANCH_PREFIX: "automation/spotlight-links/"',
    'readme_sha256_after: ${{ steps.render.outputs.readme_sha256_after }}',
    'candidate_branch: ${{ steps.propose.outputs.candidate_branch }}',
    'CANDIDATE_ID="$(printf \'%s\\n%s\\n%s\\n\' "$SOURCE_SHA" "$GENERATED_SHA" "$README_SHA256_AFTER" | sha256sum | cut -d\' \' -f1)"',
    'MATCHING_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"',
    'BLOB="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/blobs" --input blob.json)"',
    'TREE="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/trees" --input tree.json)"',
    'CANDIDATE_COMMIT="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/commits" --input commit.json)"',
    '# Validate the complete candidate object before first publication or retry reuse.',
    'CREATED_REF="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" --input ref.json)"',
    'echo "candidate_branch=$CANDIDATE_BRANCH" >> "$GITHUB_OUTPUT"',
    'test "$(jq -r .head_branch <<<"$RUN")" = "$CANDIDATE_BRANCH"',
    'CANDIDATE_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"',
    'gh api --method DELETE "repos/${GITHUB_REPOSITORY}/git/refs/heads/${CANDIDATE_BRANCH}" >/dev/null',
    'test "$AFTER_EXACT" = "0"',
)

MUTATION_LEASE_SEQUENCE = (
    'name: mint-mutation-lease-read-only',
    'LEASE_TTL_SECONDS=1800',
    'test "$GITHUB_WORKFLOW_REF" = "$EXPECTED_WORKFLOW_REF"',
    'RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}")"',
    'test "$(jq -r .run_attempt <<<"$RUN")" = "$GITHUB_RUN_ATTEMPT"',
    'EXPIRES_AT=$((ISSUED_AT + LEASE_TTL_SECONDS))',
    'echo "lease_id=$LEASE_ID" >> "$GITHUB_OUTPUT"',
    '# Verify exact short-lived mutation lease.',
    'test "$NOW_EPOCH" -lt "$LEASE_EXPIRES_AT"',
    'test "$EXPECTED_LEASE_ID" = "$LEASE_ID"',
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


def validate_ordered_presence(text: str, fragments: tuple[str, ...], label: str) -> None:
    cursor = -1
    for fragment in fragments:
        position = text.find(fragment, cursor + 1)
        require(position >= 0, f"{label} is missing reviewed fragment: {fragment}")
        require(position > cursor, f"{label} is out of reviewed order: {fragment}")
        cursor = position


def validate_profile_stats_freshness(text: str) -> None:
    validate_ordered_contract(text, PROFILE_STATS_FRESHNESS_SEQUENCE,
                              "profile-stats source-freshness contract")


def validate_spotlight_reconciliation(text: str) -> None:
    validate_ordered_contract(text, SPOTLIGHT_RECONCILIATION_SEQUENCE,
                              "Spotlight stale-candidate reconciliation contract")


def validate_spotlight_mutation_budget(text: str) -> None:
    validate_ordered_contract(text, SPOTLIGHT_MUTATION_BUDGET_SEQUENCE,
                              "Spotlight source-epoch mutation-budget contract")


def validate_spotlight_provenance(text: str) -> None:
    validate_ordered_contract(text, SPOTLIGHT_PROVENANCE_SEQUENCE,
                              "Spotlight workflow/check provenance contract")


def validate_spotlight_immutable_candidates(text: str) -> None:
    validate_ordered_contract(text, SPOTLIGHT_IMMUTABLE_CANDIDATE_SEQUENCE,
                              "Spotlight immutable-candidate contract")
    for forbidden in (
        'gh api --method PATCH "repos/${GITHUB_REPOSITORY}/git/refs/heads/',
        '-F force=true',
        'gh api --method PUT "repos/${GITHUB_REPOSITORY}/contents/README.md"',
        'BOT_BRANCH: "automation/spotlight-links"',
    ):
        require(forbidden not in text,
                f"Spotlight immutable-candidate contract regained mutable branch publication: {forbidden}")


def validate_mutation_leases(profile: str, spotlight: str) -> None:
    validate_ordered_presence(profile, MUTATION_LEASE_SEQUENCE[:7],
                              "Profile Stats mutation-lease mint contract")
    validate_ordered_presence(spotlight, MUTATION_LEASE_SEQUENCE,
                              "Spotlight mutation-lease contract")
    require(profile.count("- name: Verify exact short-lived mutation lease") == 3,
            "Profile Stats write jobs must each verify the exact lease")
    require(spotlight.count("# Verify exact short-lived mutation lease.") == 4,
            "Spotlight mutation jobs must each verify the exact lease inline")


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

    synthetic = "\n".join(SPOTLIGHT_RECONCILIATION_SEQUENCE)
    validate_spotlight_reconciliation(synthetic)
    try:
        validate_spotlight_reconciliation(synthetic.replace(SPOTLIGHT_RECONCILIATION_SEQUENCE[12], "", 1))
    except ValueError:
        pass
    else:
        raise ValueError("Spotlight reconciliation self-test accepted missing PR-close authority binding")

    synthetic = "\n".join(SPOTLIGHT_MUTATION_BUDGET_SEQUENCE)
    validate_spotlight_mutation_budget(synthetic)
    try:
        validate_spotlight_mutation_budget(synthetic.replace(SPOTLIGHT_MUTATION_BUDGET_SEQUENCE[7], "", 1))
    except ValueError:
        pass
    else:
        raise ValueError("Spotlight mutation-budget self-test accepted a missing current-run attempt binding")

    synthetic = "\n".join(SPOTLIGHT_PROVENANCE_SEQUENCE)
    validate_spotlight_provenance(synthetic)
    try:
        validate_spotlight_provenance(synthetic.replace(SPOTLIGHT_PROVENANCE_SEQUENCE[-1], "", 1))
    except ValueError:
        pass
    else:
        raise ValueError("Spotlight provenance self-test accepted a missing exact check-map equality guard")

    synthetic = "\n".join(SPOTLIGHT_IMMUTABLE_CANDIDATE_SEQUENCE)
    validate_spotlight_immutable_candidates(synthetic)
    try:
        validate_spotlight_immutable_candidates(
            synthetic + '\ngh api --method PATCH "repos/${GITHUB_REPOSITORY}/git/refs/heads/x"'
        )
    except ValueError:
        pass
    else:
        raise ValueError("Spotlight immutable-candidate self-test accepted mutable ref PATCH authority")


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
        profile = (ROOT / ".github/workflows/profile-stats.yml").read_text(encoding="utf-8")
        validate_profile_stats_freshness(profile)
        spotlight = (ROOT / ".github/workflows/spotlight-link-sync.yml").read_text(encoding="utf-8")
        validate_spotlight_reconciliation(spotlight)
        validate_spotlight_mutation_budget(spotlight)
        validate_spotlight_provenance(spotlight)
        validate_spotlight_immutable_candidates(spotlight)
        validate_mutation_leases(profile, spotlight)
        print(
            f"Governed workflow byte identity passed: {VERSION} · "
            f"{len(observed)} exact reviewed workflow blobs · mutation/required-check source is byte-locked · "
            "generated publication is source-epoch freshness bound · autonomous planning/terminal concurrency bytes are locked · "
            "short-lived mutation leases bind the exact run/base/candidate transaction · Spotlight retains stale-only reconciliation, "
            "source-epoch constructive-mutation admission, immutable candidates, and exact-run/suite authorization"
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
