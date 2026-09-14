#!/usr/bin/env python3
"""Extend frozen item-9/item-10 workflow authority proofs with item-11 ADR authority."""
from __future__ import annotations

import json
import sys

import automation_policy
import workflow_authority_contract_item9_core as item9

ROOT = item9.ROOT
QUALITY = item9.QUALITY
PROFILE_STATS = item9.PROFILE_STATS
SYNC = item9.SYNC
GOVERNANCE = item9.GOVERNANCE
README = item9.README
MAC_PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "spotlight-merge-authorization-v1.schema.json"
)
ADR_PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "automation-decision-receipt-v1.schema.json"
)
NEW_MERGE_IF = (
    "    if: needs.plan.outputs.changed == 'true' && needs.budget.outputs.allowed == 'true' && "
    "needs.propose.result == 'success' && needs.approve.result == 'success' && "
    "needs.authorize.result == 'success' && needs.authorize_attest.result == 'success'\n"
)
OLD_MERGE_IF = (
    "    if: needs.plan.outputs.changed == 'true' && needs.budget.outputs.allowed == 'true' && "
    "needs.propose.result == 'success' && needs.approve.result == 'success'\n"
)
NEW_MERGE_NEEDS = "    needs: [plan, lease, reconcile, budget, propose, approve, authorize, authorize_attest]\n"
OLD_MERGE_NEEDS = "    needs: [plan, lease, reconcile, budget, propose, approve]\n"
DOWNLOAD_STEP = (
    "      - name: Download attested merge authorization artifact\n"
    "        uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1\n"
    "        with:\n"
    "          name: spotlight-merge-authorization-${{ needs.propose.outputs.head_sha }}\n"
    "          path: merge-authorization-input\n"
    "          digest-mismatch: error\n\n"
)
ITEM10_CANDIDATE_REPROOF = (
    '          test "$(jq -r .message <<<"$CANDIDATE_COMMIT")" = "chore: sync rotating Spotlight links"\n'
    '          gh api "repos/${GITHUB_REPOSITORY}/contents/README.md?ref=${HEAD_SHA}" --jq .content \\\n'
    "            | tr -d '\\n' | base64 --decode > candidate-readme.md\n"
    '          test "$(sha256sum candidate-readme.md | cut -d\' \' -f1)" = "$README_SHA256_AFTER"\n'
)
NEW_RECONCILE_PR_READ = (
    "              PR_NUMBER=\"$(jq -r '.[0].number' <<<\"$PRS\")\"\n"
    "              [[ \"$PR_NUMBER\" =~ ^[1-9][0-9]*$ ]]\n"
    "              PR=\"$(gh api \"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}\")\"\n"
)
OLD_RECONCILE_PR_READ = (
    "              PR=\"$(jq -c '.[0]' <<<\"$PRS\")\"\n"
    "              PR_NUMBER=\"$(jq -r .number <<<\"$PR\")\"\n"
    "              [[ \"$PR_NUMBER\" =~ ^[1-9][0-9]*$ ]]\n"
)
ADR_SIGNER_PERMISSIONS = "permissions:\n      contents: read\n      id-token: write\n      attestations: write"


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def strip_adr_tail(workflow: str, label: str) -> str:
    marker = "  decision_receipt:\n"
    require(workflow.count(marker) == 1, f"{label} item-11 projection cannot isolate ADR preparer")
    preparer_start = workflow.index(marker)
    tail = workflow[preparer_start:]
    require(tail.count("  decision_receipt_attest:\n") == 1,
            f"{label} item-11 projection cannot isolate ADR signer")
    return workflow[:preparer_start]


def project_item9_sync(sync: str) -> str:
    """Remove item-10 overlays after item-11 jobs have already been projected away."""
    authorize_start = sync.index("  authorize:\n")
    merge_start = sync.index("  merge:\n", authorize_start)
    projected = sync[:authorize_start] + sync[merge_start:]

    require(projected.count(NEW_RECONCILE_PR_READ) == 1,
            "item-10 production-fix projection lost exact reconciler PR-read overlay")
    projected = projected.replace(NEW_RECONCILE_PR_READ, OLD_RECONCILE_PR_READ, 1)

    for current, legacy, label in (
        (NEW_MERGE_IF, OLD_MERGE_IF, "merge condition"),
        (NEW_MERGE_NEEDS, OLD_MERGE_NEEDS, "merge dependency overlay"),
    ):
        require(projected.count(current) == 1, f"item-10 projection lost exact {label}")
        projected = projected.replace(current, legacy, 1)

    require(projected.count("      attestations: read\n") == 1,
            "item-10 projection lost terminal attestation-read permission")
    projected = projected.replace("      attestations: read\n", "", 1)
    require(projected.count(DOWNLOAD_STEP) == 1,
            "item-10 projection lost terminal certificate download")
    projected = projected.replace(DOWNLOAD_STEP, "", 1)

    certificate_env = (
        "          EXPECTED_CERTIFICATE_SHA256: ${{ needs.authorize.outputs.certificate_sha256 }}\n"
        "          EXPECTED_SUBJECT_SHA256: ${{ needs.authorize.outputs.subject_sha256 }}\n"
    )
    require(projected.count(certificate_env) == 1,
            "item-10 projection lost certificate identity inputs")
    projected = projected.replace(certificate_env, "", 1)

    require(projected.count(ITEM10_CANDIDATE_REPROOF) == 1,
            "item-10 projection lost candidate content reproof")
    projected = projected.replace(ITEM10_CANDIDATE_REPROOF, "", 1)

    mac_start = '          CERTIFICATE="merge-authorization-input/spotlight-merge-authorization.json"\n'
    require(projected.count(mac_start) == 1,
            "item-10 projection lost terminal MAC proof boundary")
    start = projected.index(mac_start)
    final_reproof = (
        '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" '
        '--jq .object.sha)" = "$BASE_SHA"\n'
    )
    end = projected.index(final_reproof, start)
    return projected[:start] + projected[end:]


def validate_item10_authority(sync: str) -> None:
    """Validate the exact item-10 authority surface after only item-11 projection."""
    for forbidden in ("pull_request_target", "  workflow_run:", "repository_dispatch", "issues: write"):
        require(forbidden not in sync,
                f"Spotlight item-10 workflow contains forbidden authority/trigger: {forbidden.strip()}")
    require(sync.count("      id-token: write\n") == 1,
            "Spotlight item-10 OIDC authority must exist in exactly one job")
    require(sync.count("      attestations: write\n") == 1,
            "Spotlight item-10 attestation-write authority must exist in exactly one job")
    require(sync.count("      attestations: read\n") == 1,
            "Spotlight item-10 attestation-read authority must exist in exactly one job")

    approve = item9.core.job_block(sync, "approve", "authorize")
    authorize = item9.core.job_block(sync, "authorize", "authorize_attest")
    signer = item9.core.job_block(sync, "authorize_attest", "merge")
    merge = item9.core.job_block(sync, "merge", None)
    reconcile = item9.core.job_block(sync, "reconcile", "budget")

    require("id-token:" not in approve and "attestations:" not in approve,
            "Spotlight Actions approval job acquired attestation authority")
    require(
        'PRS="$(gh api "repos/${GITHUB_REPOSITORY}/pulls?state=open&head=portyu9:${BRANCH}&base=main&per_page=2")"' in reconcile and
        'PR_NUMBER="$(jq -r \'.[0].number\' <<<"$PRS")"' in reconcile and
        'PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"' in reconcile,
        "Spotlight stale reconciler must use bounded PR discovery followed by an exact full-object GET",
    )
    require(
        reconcile.index('PR_NUMBER="$(jq -r \'.[0].number\' <<<"$PRS")"') <
        reconcile.index('PR="$(gh api "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}")"') <
        reconcile.index('CLOSED_PR="$(gh api --method PATCH'),
        "Spotlight stale reconciler must validate the exact full PR object before close mutation",
    )

    require("name: prepare-merge-authorization-read-only" in authorize and
            "needs: [plan, lease, reconcile, budget, propose, approve]" in authorize,
            "Spotlight MAC preparer identity/dependency closure changed")
    require("permissions:\n      contents: read\n      pull-requests: read\n      checks: read\n      actions: read" in authorize,
            "Spotlight MAC preparer must remain read-only")
    for fragment in (
        "python3 source/scripts/prepare-spotlight-merge-authorization.py merge-authorization-state.json",
        "python3 source/scripts/build-spotlight-merge-authorization.py",
        "name: spotlight-merge-authorization-${{ needs.propose.outputs.head_sha }}",
    ):
        require(fragment in authorize, f"Spotlight MAC preparer lost reviewed proof surface: {fragment}")
    for forbidden in ("--method POST", "--method PUT", "--method PATCH", "--method DELETE",
                      "id-token: write", "attestations: write"):
        require(forbidden not in authorize,
                f"Spotlight MAC preparer acquired mutation/signing authority: {forbidden}")

    require("name: attest-merge-authorization-write-only" in signer and
            "needs: [authorize, lease, plan, propose, approve]" in signer,
            "Spotlight MAC signer identity/dependency closure changed")
    require(ADR_SIGNER_PERMISSIONS in signer, "Spotlight MAC signer authority changed")
    for fragment in (
        "LEASE_MIN_REMAINING_SECONDS=180",
        "uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2",
        f"predicate-type: {MAC_PREDICATE_TYPE}",
        "predicate-path: merge-authorization-input/spotlight-merge-authorization.json",
    ):
        require(fragment in signer, f"Spotlight MAC signer lost reviewed authority surface: {fragment}")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "python3 ", "gh api ",
                      "contents: write", "pull-requests:", "checks:", "actions: write"):
        require(forbidden not in signer,
                f"Spotlight MAC signer acquired unrelated authority/execution surface: {forbidden}")

    require(NEW_MERGE_IF in merge and NEW_MERGE_NEEDS in merge,
            "Spotlight terminal merge can bypass MAC preparation/signing")
    require("permissions:\n      contents: write\n      pull-requests: read\n      checks: read\n      attestations: read" in merge,
            "Spotlight terminal merge authority changed beyond read-only attestation verification")
    for forbidden in ("id-token: write", "attestations: write"):
        require(forbidden not in merge, f"Spotlight terminal merge acquired signer authority: {forbidden}")

    verify = 'gh attestation verify "$SUBJECT"'
    statement = '.verificationResult.statement'
    mutation = 'gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge"'
    require(verify in merge and statement in merge and mutation in merge and
            merge.index(verify) < merge.index(statement) < merge.index(mutation),
            "Spotlight terminal merge mutation is not downstream of direct cryptographic MAC statement verification")
    for fragment in (
        f"--predicate-type {MAC_PREDICATE_TYPE}",
        '--signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/spotlight-link-sync.yml"',
        '--signer-digest "$BASE_SHA"',
        '--source-digest "$BASE_SHA"',
        "--source-ref refs/heads/main",
        "--deny-self-hosted-runners",
        '.predicateType == $predicate_type',
        '.predicate == $expected[0]',
        '.subject[0].digest.sha256 == $subject_digest',
        'test "$MATCHING_STATEMENTS" = "$VERIFIED_COUNT"',
    ):
        require(fragment in merge, f"Spotlight terminal attestation verification drifted: {fragment}")
    require("[.. | objects" not in merge,
            "Spotlight terminal attestation verification must not recursively search arbitrary JSON")

    api_start_marker = '          CODEQL_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${CODEQL_RUN_ID}")"\n'
    api_end_marker = '          EXPECTED_CERTIFICATE_CHECKS="$(jq -cn '
    require(merge.count(api_start_marker) == 1 and merge.count(api_end_marker) == 1,
            "Spotlight item-10 terminal certificate API proof boundary changed")
    api_start = merge.index(api_start_marker)
    api_end = merge.index(api_end_marker, api_start)
    item9.core.require_exact_gh_api_surface(
        merge[api_start:api_end],
        label="Spotlight item-10 terminal certificate API proof",
        expected_lines=(
            'CODEQL_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${CODEQL_RUN_ID}")"',
            'DEPENDENCY_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${DEPENDENCY_RUN_ID}")"',
            'PROFILE_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${PROFILE_RUN_ID}")"',
        ),
    )


def _validate_adr_pair(workflow: str, workflow_id: str) -> None:
    preparer = item9.core.job_block(workflow, "decision_receipt", "decision_receipt_attest")
    signer = item9.core.job_block(workflow, "decision_receipt_attest", None)
    require("name: prepare-automation-decision-receipt-read-only" in preparer,
            f"{workflow_id} ADR preparer identity changed")
    require("name: attest-automation-decision-receipt-write-only" in signer,
            f"{workflow_id} ADR signer identity changed")
    require(ADR_SIGNER_PERMISSIONS in signer, f"{workflow_id} ADR signer authority changed")
    require(f"predicate-type: {ADR_PREDICATE_TYPE}" in signer,
            f"{workflow_id} ADR signer predicate changed")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "python3 ", "gh api ",
                      "git ", "curl ", "wget ", "contents: write", "actions: write",
                      "pull-requests: write", "checks: write"):
        require(forbidden not in signer,
                f"{workflow_id} ADR signer acquired unrelated execution/authority surface: {forbidden}")

    if workflow_id == "Profile Stats":
        require("needs: [dispatch, lease]" in preparer,
                "Profile Stats ADR preparer dependency closure changed")
        require("permissions:\n      contents: read\n      actions: read" in preparer,
                "Profile Stats ADR preparer authority changed")
        require("needs: [decision_receipt, lease, attest]" in signer,
                "Profile Stats ADR signer dependency closure changed")
        require("python3 source/scripts/prepare-profile-stats-decision-receipt.py" in preparer and
                "python3 source/scripts/automation_decision_receipt.py" in preparer,
                "Profile Stats ADR preparer lost reviewed independent reproof/build roots")
    else:
        require("if: always() && needs.lease.result == 'success'" in preparer,
                "Spotlight ADR preparer lost safe recovery gate")
        require("needs: [plan, lease, reconcile, propose, approve, merge]" in preparer,
                "Spotlight ADR preparer dependency closure changed")
        require("permissions:\n      contents: read\n      pull-requests: read\n      actions: read" in preparer,
                "Spotlight ADR preparer authority changed")
        require("if: always() && needs.lease.result == 'success' && needs.decision_receipt.result == 'success'" in signer,
                "Spotlight ADR signer lost safe recovery/success gate")
        require("needs: [decision_receipt, lease, plan]" in signer,
                "Spotlight ADR signer dependency closure changed")
        for fragment in (
            "python3 source/scripts/spotlight_decision_journal.py",
            "python3 source/scripts/prepare-spotlight-decision-receipt.py",
            "python3 source/scripts/automation_decision_receipt.py",
        ):
            require(fragment in preparer, f"Spotlight ADR preparer lost reviewed root: {fragment}")

    for forbidden in ("id-token: write", "attestations: write", "contents: write",
                      "actions: write", "pull-requests: write", "checks: write",
                      "--method POST", "--method PUT", "--method PATCH", "--method DELETE"):
        require(forbidden not in preparer,
                f"{workflow_id} ADR preparer acquired mutation/signing authority: {forbidden}")


def validate_item11_authority(profile_stats: str, sync: str) -> None:
    _validate_adr_pair(profile_stats, "Profile Stats")
    _validate_adr_pair(sync, "Spotlight")
    require(profile_stats.count("      id-token: write\n") == 3,
            "Profile Stats current OIDC writer inventory changed")
    require(profile_stats.count("      attestations: write\n") == 3,
            "Profile Stats current attestation-writer inventory changed")
    require(sync.count("      id-token: write\n") == 2,
            "Spotlight current OIDC writer inventory changed")
    require(sync.count("      attestations: write\n") == 2,
            "Spotlight current attestation-writer inventory changed")


def self_test_item10(sync: str) -> None:
    validate_item10_authority(sync)
    failures = (
        (sync.replace("      id-token: write\n", "      actions: write\n", 1), "OIDC authority"),
        (sync.replace("      attestations: read\n", "      attestations: write\n", 1), "attestation-write authority"),
        (sync.replace('gh attestation verify "$SUBJECT"', 'echo "$SUBJECT"', 1), "not downstream of direct cryptographic"),
        (sync.replace('.verificationResult.statement', '.attestation', 1), "not downstream of direct cryptographic"),
    )
    for malformed, expected in failures:
        try:
            validate_item10_authority(malformed)
        except ValueError as exc:
            require(expected in str(exc), f"item-10 workflow authority self-test failed for wrong reason: {exc}")
        else:
            fail(f"item-10 workflow authority self-test accepted forbidden drift: {expected}")


def self_test_item11(profile_stats: str, sync: str) -> None:
    validate_item11_authority(profile_stats, sync)
    malformed = sync.replace(
        "permissions:\n      contents: read\n      id-token: write\n      attestations: write",
        "permissions:\n      contents: write\n      id-token: write\n      attestations: write",
        2,
    )
    try:
        validate_item11_authority(profile_stats, malformed)
    except ValueError as exc:
        require("ADR signer authority changed" in str(exc) or "writer inventory changed" in str(exc),
                f"item-11 signer authority self-test failed for wrong reason: {exc}")
    else:
        fail("item-11 workflow authority self-test accepted ADR signer authority expansion")


def main() -> int:
    try:
        for path in (automation_policy.POLICY_PATH, QUALITY, PROFILE_STATS, GOVERNANCE, README, SYNC):
            require(path.is_file() and not path.is_symlink(),
                    f"Workflow authority input is missing or aliased: {path.relative_to(ROOT)}")
        policy = automation_policy.load_policy()
        item9.core.self_test(policy)
        item9.core.validate_inventory(policy)

        profile_stats = PROFILE_STATS.read_text(encoding="utf-8")
        sync = SYNC.read_text(encoding="utf-8")
        readme = README.read_text(encoding="utf-8")
        profile_item10 = strip_adr_tail(profile_stats, "Profile Stats")
        sync_item10 = strip_adr_tail(sync, "Spotlight")
        projected_sync = project_item9_sync(sync_item10)

        item9.validate_policy_cross_contracts(policy, profile_item10, sync_item10)
        item9.core.validate_quality_contract(QUALITY.read_text(encoding="utf-8"))
        item9.core.validate_profile_stats_contract(item9.project_legacy_profile_stats_source(profile_item10))
        item9.self_test_current_sync(projected_sync, readme)
        item9.core.validate_governance(GOVERNANCE.read_text(encoding="utf-8"))
        self_test_item10(sync_item10)
        self_test_item11(profile_stats, sync)

        print(
            f"Workflow authority validation passed: {policy['policyId']} retains frozen item-9/item-10 projections and "
            "exact MAC signer counts, while item-11 adds only independently validated read-only ADR preparers and "
            "lease-bound attestations-only signers with no authored mutation client surface."
        )
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
