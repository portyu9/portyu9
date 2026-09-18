#!/usr/bin/env python3
"""Lock privileged workflow bytes and item-10/11 terminal authorization semantics."""
from __future__ import annotations

from pathlib import Path
import sys

import privileged_workflow_identity_v21_core as v21

ROOT = Path(__file__).resolve().parents[1]
VERSION = "governed-workflow-byte-identity-v31"
EXPECTED = {
    ".github/workflows/bot-pr-user-approval.yml": "fd54544e436a5a5845b614fe85d60fd796839c51",
    ".github/workflows/profile-quality.yml": "ee94b8ca68d8c033638da28d17054a0053fa80f0",
    ".github/workflows/profile-stats.yml": "627ecd3d7a5d9ca4e7051acf3c64d3edab914af0",
    ".github/workflows/spotlight-link-sync.yml": "244c11ae9bd11b94424df95de9dcf122a828806c",
}

OLD_MERGE_IF = (
    "    if: needs.plan.outputs.changed == 'true' && needs.budget.outputs.allowed == 'true' && "
    "needs.propose.result == 'success' && needs.approve.result == 'success'\n"
    "    name: merge-readme-only-terminal-write"
)
NEW_MERGE_IF = (
    "    if: needs.plan.outputs.changed == 'true' && needs.budget.outputs.allowed == 'true' && "
    "needs.propose.result == 'success' && needs.approve.result == 'success' && "
    "needs.authorize.result == 'success' && needs.authorize_attest.result == 'success'\n"
    "    name: merge-readme-only-terminal-write"
)
ADR_PREDICATE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "automation-decision-receipt-v1.schema.json"
)
IMMUTABLE_COMMENT = "# Validate the complete candidate object before first publication or retry reuse."
IMMUTABLE_ANCHOR = (
    '          fi\n\n'
    '          CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"\n'
    '          test "$(jq \'.parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"\n'
)
IMMUTABLE_PROJECTED = (
    '          fi\n\n'
    f'          {IMMUTABLE_COMMENT}\n'
    '          CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"\n'
    '          test "$(jq \'.parents | length\' <<<"$CANDIDATE_COMMIT")" = "1"\n'
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def job_block(text: str, job: str, next_job: str | None) -> str:
    start_marker = f"  {job}:\n"
    require(text.count(start_marker) == 1, f"governed workflow must contain exactly one {job} job")
    start = text.index(start_marker)
    if next_job is None:
        return text[start:]
    end_marker = f"  {next_job}:\n"
    require(text.count(end_marker) == 1, f"governed workflow must contain exactly one {next_job} job")
    end = text.index(end_marker, start)
    return text[start:end]


def validate_item10_mac(spotlight: str) -> None:
    authorize = job_block(spotlight, "authorize", "authorize_attest")
    signer = job_block(spotlight, "authorize_attest", "merge")
    merge = job_block(spotlight, "merge", "decision_receipt")

    require("name: prepare-merge-authorization-read-only" in authorize,
            "Spotlight MAC preparer identity changed")
    require("needs: [plan, lease, reconcile, budget, propose, approve]" in authorize,
            "Spotlight MAC preparer dependency closure changed")
    require(
        "permissions:\n      contents: read\n      pull-requests: read\n      checks: read\n      actions: read" in authorize,
        "Spotlight MAC preparer must remain read-only",
    )
    for fragment in (
        "python3 source/scripts/prepare-spotlight-merge-authorization.py merge-authorization-state.json",
        "python3 source/scripts/build-spotlight-merge-authorization.py",
        "name: spotlight-merge-authorization-${{ needs.propose.outputs.head_sha }}",
        "retention-days: 1",
    ):
        require(fragment in authorize, f"Spotlight MAC preparer contract is missing: {fragment}")
    for forbidden in ("--method POST", "--method PUT", "--method PATCH", "--method DELETE"):
        require(forbidden not in authorize, f"Spotlight MAC preparer acquired mutation authority: {forbidden}")

    require("name: attest-merge-authorization-write-only" in signer,
            "Spotlight MAC signer identity changed")
    require("needs: [authorize, lease, plan, propose, approve]" in signer,
            "Spotlight MAC signer dependency closure changed")
    require(
        "permissions:\n      contents: read\n      id-token: write\n      attestations: write" in signer,
        "Spotlight MAC signer authority changed",
    )
    require("timeout-minutes: 2" in signer and "LEASE_MIN_REMAINING_SECONDS=180" in signer,
            "Spotlight MAC signer lease reserve no longer covers its hard timeout")
    for fragment in (
        "- name: Verify exact short-lived mutation lease",
        "- name: Download exact merge authorization artifact",
        "- name: Verify exact merge authorization artifact identity",
        "- name: Attest exact Spotlight merge authorization certificate",
        "uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2",
        "subject-path: merge-authorization-input/spotlight-merge-authorization.subject.json",
        "predicate-type: https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/spotlight-merge-authorization-v1.schema.json",
        "predicate-path: merge-authorization-input/spotlight-merge-authorization.json",
    ):
        require(fragment in signer, f"Spotlight MAC signer contract is missing: {fragment}")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "python3 ", "gh api ", "--method "):
        require(forbidden not in signer, f"Spotlight MAC signer acquired unreviewed execution surface: {forbidden}")

    require(NEW_MERGE_IF in merge, "Spotlight terminal merge is not gated by MAC preparation/signing")
    require(
        "needs: [plan, lease, reconcile, budget, propose, approve, authorize, authorize_attest]" in merge,
        "Spotlight terminal merge MAC dependency closure changed",
    )
    require(
        "permissions:\n      contents: write\n      pull-requests: read\n      checks: read\n      attestations: read" in merge,
        "Spotlight terminal merge must retain only merge authority plus read-only certificate verification",
    )
    for fragment in (
        "- name: Download attested merge authorization artifact",
        "EXPECTED_CERTIFICATE_SHA256: ${{ needs.authorize.outputs.certificate_sha256 }}",
        "EXPECTED_SUBJECT_SHA256: ${{ needs.authorize.outputs.subject_sha256 }}",
        'test "$(printf \'%s\\n\' "$CODEQL_RUN_ID" "$DEPENDENCY_RUN_ID" "$PROFILE_RUN_ID" | LC_ALL=C sort -u | wc -l)" = "3"',
        'test "$(printf \'%s\\n\' "$CODEQL_CHECK_SUITE_ID" "$DEPENDENCY_CHECK_SUITE_ID" "$PROFILE_CHECK_SUITE_ID" | LC_ALL=C sort -u | wc -l)" = "3"',
        '[[ "$CHECKS_TOTAL" =~ ^[0-9]+$ ]]',
        '[[ "$CHECKS_COUNT" =~ ^[0-9]+$ ]]',
        '[[ "$EXPECTED_CERTIFICATE_SHA256" =~ ^[0-9a-f]{64}$ ]]',
        '[[ "$EXPECTED_SUBJECT_SHA256" =~ ^[0-9a-f]{64}$ ]]',
        "gh attestation verify \"$SUBJECT\"",
        "--predicate-type https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/spotlight-merge-authorization-v1.schema.json",
        '--signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/spotlight-link-sync.yml"',
        '--signer-digest "$BASE_SHA"',
        '--source-digest "$BASE_SHA"',
        "--source-ref refs/heads/main",
        "--deny-self-hosted-runners",
        "jq -cS '.workflowRuns | sort_by(.name)'",
        'jq -cS . <<<"$EXPECTED_CERTIFICATE_RUNS"',
        "jq -cS '.checkRuns | sort_by(.name)'",
        'jq -cS . <<<"$EXPECTED_CERTIFICATE_CHECKS"',
        'echo "Spotlight terminal stage: certificate-provenance-verified" >&2',
        '.verificationResult.statement',
        '.subject[0].digest.sha256 == $subject_digest',
        'test "$MATCHING_STATEMENTS" = "$VERIFIED_COUNT"',
        'echo "Spotlight terminal stage: attestation-cryptographic-verified" >&2',
        'echo "Spotlight terminal stage: attestation-statement-verified" >&2',
        'REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${BASE_SHA} head=${HEAD_SHA} -->"',
        'repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/reviews?per_page=100',
        '.user.login == "portyu9"',
        '.state == "APPROVED"',
        '.commit_id == $head',
        '--arg marker "$REVIEW_MARKER"',
        'contains($marker)',
        'echo "Spotlight terminal stage: exact-base-head-portyu9-approval-verified" >&2',
        'RESULT="$(gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge" --input merge.json)"',
    ):
        require(fragment in merge, f"Spotlight terminal MAC verification contract is missing: {fragment}")
    require("jq -c '.workflowRuns | sort_by(.name)'" not in merge and
            "jq -c '.checkRuns | sort_by(.name)'" not in merge,
            "Spotlight terminal provenance equality must canonicalize object-key order before byte comparison")
    require("[.. | objects" not in merge,
            "Spotlight terminal MAC verification must not recursively search untrusted verifier JSON")
    provenance_pos = merge.index('echo "Spotlight terminal stage: certificate-provenance-verified" >&2')
    verify_pos = merge.index('gh attestation verify "$SUBJECT"')
    statement_pos = merge.index('.verificationResult.statement')
    merge_pos = merge.index('RESULT="$(gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge"')
    require(provenance_pos < verify_pos < statement_pos < merge_pos,
            "Spotlight terminal merge mutation moved before canonical provenance and verified-statement MAC binding")
    for forbidden in ("for attempt in ", "sleep 10", "actions/checkout@", "actions/setup-python@", "python3 "):
        require(forbidden not in merge, f"Spotlight terminal merge acquired polling/authored execution surface: {forbidden}")


def validate_item11_receipts(profile: str, spotlight: str) -> None:
    profile_prepare = job_block(profile, "decision_receipt", "decision_receipt_attest")
    profile_signer = job_block(profile, "decision_receipt_attest", None)
    require("name: prepare-automation-decision-receipt-read-only" in profile_prepare,
            "Profile ADR preparer identity changed")
    require("needs: [dispatch, lease]" in profile_prepare,
            "Profile ADR preparer dependency closure changed")
    require("permissions:\n      contents: read\n      actions: read" in profile_prepare,
            "Profile ADR preparer must remain read-only")
    require("python3 source/scripts/prepare-profile-stats-decision-receipt.py" in profile_prepare and
            "python3 source/scripts/automation_decision_receipt.py" in profile_prepare,
            "Profile ADR preparer lost independent reproof/build boundary")

    require("name: attest-automation-decision-receipt-write-only" in profile_signer,
            "Profile ADR signer identity changed")
    require("needs: [decision_receipt, lease, attest]" in profile_signer,
            "Profile ADR signer dependency closure changed")
    require("permissions:\n      contents: read\n      id-token: write\n      attestations: write" in profile_signer,
            "Profile ADR signer authority changed")
    require(f"predicate-type: {ADR_PREDICATE}" in profile_signer,
            "Profile ADR signer predicate changed")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "python3 ", "gh api ", "--method "):
        require(forbidden not in profile_signer,
                f"Profile ADR signer acquired unreviewed execution surface: {forbidden}")

    spotlight_prepare = job_block(spotlight, "decision_receipt", "decision_receipt_attest")
    spotlight_signer = job_block(spotlight, "decision_receipt_attest", None)
    require("if: always() && needs.lease.result == 'success'" in spotlight_prepare,
            "Spotlight ADR preparer lost safe always() recovery entry")
    require("name: prepare-automation-decision-receipt-read-only" in spotlight_prepare,
            "Spotlight ADR preparer identity changed")
    require("needs: [plan, lease, reconcile, propose, approve, merge]" in spotlight_prepare,
            "Spotlight ADR preparer dependency closure changed")
    require("permissions:\n      contents: read\n      pull-requests: read\n      actions: read" in spotlight_prepare,
            "Spotlight ADR preparer must remain read-only")
    for fragment in (
        "python3 source/scripts/spotlight_decision_journal.py",
        "python3 source/scripts/prepare-spotlight-decision-receipt.py",
        "python3 source/scripts/automation_decision_receipt.py",
        "STALE_CLEANUPS_JSON:",
        "APPROVAL_RUNS_JSON:",
        "MERGE_EFFECT_PRESENT:",
    ):
        require(fragment in spotlight_prepare, f"Spotlight ADR recovery contract is missing: {fragment}")

    require("if: always() && needs.lease.result == 'success' && needs.decision_receipt.result == 'success'" in spotlight_signer,
            "Spotlight ADR signer lost recovery/success gate")
    require("name: attest-automation-decision-receipt-write-only" in spotlight_signer,
            "Spotlight ADR signer identity changed")
    require("needs: [decision_receipt, lease, plan]" in spotlight_signer,
            "Spotlight ADR signer dependency closure changed")
    require("permissions:\n      contents: read\n      id-token: write\n      attestations: write" in spotlight_signer,
            "Spotlight ADR signer authority changed")
    require(f"predicate-type: {ADR_PREDICATE}" in spotlight_signer,
            "Spotlight ADR signer predicate changed")
    require("EXPECTED_CANDIDATE_ID=\"$(printf '%s\\n%s\\n%s\\n'" in spotlight_signer,
            "Spotlight ADR signer must independently reconstruct the leased candidate")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "python3 ", "gh api ", "--method "):
        require(forbidden not in spotlight_signer,
                f"Spotlight ADR signer acquired unreviewed execution surface: {forbidden}")


def validate_leases(profile: str, spotlight: str) -> None:
    v21.validate_ordered_presence(profile, v21.MUTATION_LEASE_SEQUENCE[:7],
                                  "Profile Stats mutation-lease mint contract")
    require(profile.count("- name: Verify exact short-lived mutation lease") == 5,
            "Profile Stats write jobs must each verify the exact lease")
    guard = 'test $((LEASE_EXPIRES_AT - NOW_EPOCH)) -ge "$LEASE_MIN_REMAINING_SECONDS"'
    require(profile.count(guard) == 5,
            "Profile Stats write jobs must each reserve lease lifetime through hard timeout")

    v21.validate_ordered_presence(spotlight, v21.MUTATION_LEASE_SEQUENCE,
                                  "Spotlight mutation-lease contract")
    require(spotlight.count("# Verify exact short-lived mutation lease.") == 4,
            "Spotlight legacy mutation jobs must retain their inline exact-lease proof")
    require(spotlight.count("- name: Verify exact short-lived mutation lease") == 2,
            "Spotlight attestation signers must each retain one exact-lease proof step")
    require(spotlight.count(guard) == 6,
            "Every Spotlight writer must reserve lease lifetime through its hard timeout")
    for fragment in (
        "LEASE_MIN_REMAINING_SECONDS=240",
        "LEASE_MIN_REMAINING_SECONDS=300",
        "LEASE_MIN_REMAINING_SECONDS=780",
        "LEASE_MIN_REMAINING_SECONDS=180",
    ):
        require(fragment in spotlight, f"Spotlight mutation-lease reserve contract is missing: {fragment}")


def validate_v21_spotlight_invariants(spotlight: str) -> None:
    legacy = spotlight[:spotlight.index("  decision_receipt:\n")]
    v21.validate_spotlight_reconciliation(legacy)
    require(
        'PR_NUMBER="$(jq -r \'.[0].number\' <<<"$PRS")"' in legacy and
        'PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"' in legacy,
        "Spotlight stale reconciliation must use list results only for bounded PR discovery and re-fetch the exact full PR object",
    )
    for fragment in (
        'CANDIDATE_ID="$(printf \'%s\\n%s\\n%s\\n\' "$SOURCE_SHA" "$GENERATED_SHA" "$README_SHA256_AFTER" | sha256sum | cut -d\' \' -f1)"',
        'MATCHING_REFS="$(gh api "repos/${GITHUB_REPOSITORY}/git/matching-refs/heads/${CANDIDATE_BRANCH}")"',
        'CANDIDATE_COMMIT="$(gh api "repos/${GITHUB_REPOSITORY}/git/commits/${HEAD_SHA}")"',
        'test "$(jq -r .message <<<"$CANDIDATE_COMMIT")" = "chore: sync rotating Spotlight links"',
        'COMPARE="$(gh api "repos/${GITHUB_REPOSITORY}/compare/${SOURCE_SHA}...${HEAD_SHA}")"',
        'test "$(jq -r .total_commits <<<"$COMPARE")" = "1"',
        'test "$(jq -r \'.files[0].filename\' <<<"$COMPARE")" = "README.md"',
        'CREATED_REF="$(gh api --method POST "repos/${GITHUB_REPOSITORY}/git/refs" --input ref.json)"',
    ):
        require(fragment in legacy, f"Spotlight current immutable-candidate proof is missing: {fragment}")
    require(legacy.count(IMMUTABLE_ANCHOR) == 1,
            "Spotlight v21 immutable-candidate projection anchor changed")
    projected_immutable = legacy.replace(IMMUTABLE_ANCHOR, IMMUTABLE_PROJECTED, 1)
    v21.validate_spotlight_immutable_candidates(projected_immutable)
    projected = projected_immutable.replace(NEW_MERGE_IF, OLD_MERGE_IF, 1)
    require(projected != projected_immutable,
            "Spotlight v21 mutation-budget projection could not isolate item-10 merge gating")
    v21.validate_spotlight_mutation_budget(projected)


def validate_bot_review_liveness(bot_review: str, dependabot: str, autofix: str, spotlight: str) -> None:
    for fragment in (
        'local -a required=(validate-contracts integration-pinned-upstream analyze-actions analyze-python dependency-review)',
        'dependabot|codeql-autofix)',
        'required+=(trusted-capability-admission)',
        'LANE="dependabot"',
        'LANE="codeql-autofix"',
        'LANE="spotlight"',
        'Skipping governed bot PR #${PR_NUMBER}: base is stale relative to current main.',
        'check_required_contexts "$HEAD_SHA" "$LANE"',
        'all lane-required protected gates completed successfully',
        'REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${MAIN_SHA} head=${HEAD_SHA} -->"',
        '--arg marker "$REVIEW_MARKER"',
        'contains($marker)',
        'exact-base/head marker-bound portyu9 approval',
        'grep -Fxc "$REVIEW_MARKER"',
    ):
        require(fragment in bot_review, f"Bot PR user approval liveness/proof contract is missing: {fragment}")
    require(
        'for name in validate-contracts integration-pinned-upstream analyze-actions analyze-python dependency-review trusted-capability-admission; do'
        not in bot_review,
        "Bot PR user approval regressed to one global six-check set instead of lane-specific gates",
    )
    require(
        bot_review.count('check_required_contexts "$HEAD_SHA" "$LANE"') == 2,
        "Bot PR user approval must re-prove the lane-specific gate set before and immediately before review mutation",
    )
    require(
        'test "$(jq -r .base.sha <<<"$PR")" = "$MAIN_SHA"' not in bot_review,
        "Bot PR user approval must skip stale-base candidates instead of globally failing the reviewer pass",
    )
    require(
        '.state == "APPROVED" and .commit_id == $head)] | length' not in bot_review,
        "Bot PR user approval must not treat GitHub commit_id alone as immutable exact-head proof",
    )

    consumers = (
        ("Dependabot", dependabot, 'REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${BASE_SHA} head=${HEAD_SHA} -->"'),
        ("CodeQL Autofix", autofix, 'REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${ADMITTED_BASE_SHA} head=${ADMITTED_HEAD_SHA} -->"'),
        ("Spotlight", spotlight, 'REVIEW_MARKER="<!-- portyu9-bot-review:v2 base=${BASE_SHA} head=${HEAD_SHA} -->"'),
    )
    for label, workflow, marker in consumers:
        for fragment in (
            marker,
            '--arg marker "$REVIEW_MARKER"',
            '.user.login == "portyu9"',
            '.state == "APPROVED"',
            '.commit_id == $head',
            'contains($marker)',
            'marker-bound APPROVED review by portyu9',
        ):
            require(fragment in workflow, f"{label} marker-bound portyu9 review proof is missing: {fragment}")
        require(
            '.state == "APPROVED" and .commit_id == $head)] | length' not in workflow,
            f"{label} regressed to mutable GitHub commit_id-only review proof",
        )


def self_test() -> None:
    v21.self_test()


def main() -> int:
    try:
        self_test()
        observed: dict[str, str] = {}
        for relative, expected in EXPECTED.items():
            actual = v21.git_blob_sha(ROOT / relative)
            require(actual == expected,
                    f"{relative}: governed workflow bytes changed; expected Git blob {expected}, got {actual}")
            observed[relative] = actual
        require(set(observed) == set(EXPECTED), "governed workflow identity inventory changed")

        bot_review = (ROOT / ".github/workflows/bot-pr-user-approval.yml").read_text(encoding="utf-8")
        dependabot = (ROOT / ".github/workflows/dependabot-controller.yml").read_text(encoding="utf-8")
        autofix = (ROOT / ".github/workflows/codeql-autofix.yml").read_text(encoding="utf-8")
        spotlight = (ROOT / ".github/workflows/spotlight-link-sync.yml").read_text(encoding="utf-8")
        validate_bot_review_liveness(bot_review, dependabot, autofix, spotlight)

        profile = (ROOT / ".github/workflows/profile-stats.yml").read_text(encoding="utf-8")
        v21.validate_profile_stats_freshness(profile)
        v21.validate_profile_stats_lease_binding(profile)
        v21.validate_profile_stats_receipt(profile)

        validate_v21_spotlight_invariants(spotlight)
        validate_item10_mac(spotlight)
        validate_item11_receipts(profile, spotlight)
        validate_leases(profile, spotlight)

        print(
            f"Governed workflow byte identity passed: {VERSION} · {len(observed)} exact reviewed workflow blobs · "
            "v21 profile/publication and Spotlight reconciliation/immutable-candidate invariants preserved · "
            "bot-review lane-specific liveness plus immutable base/head marker proof locked · item-10 MAC ordering and terminal proof guards retained · "
            "item-11 ADR recovery/preparation/signing boundaries byte-locked with exact lease closure and no signer-side authored execution surface."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
