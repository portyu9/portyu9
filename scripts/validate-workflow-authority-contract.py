#!/usr/bin/env python3
"""Extend the frozen item-9 workflow authority firewall with item-10 MAC authority."""
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
PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "spotlight-merge-authorization-v1.schema.json"
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


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def project_item9_sync(sync: str) -> str:
    """Remove only item-10 authority so the frozen item-9 firewall can re-prove itself."""
    authorize_start = sync.index("  authorize:\n")
    merge_start = sync.index("  merge:\n", authorize_start)
    projected = sync[:authorize_start] + sync[merge_start:]

    require(projected.count(NEW_MERGE_IF) == 1,
            "item-10 authority projection lost exact merge condition")
    projected = projected.replace(NEW_MERGE_IF, OLD_MERGE_IF, 1)
    require(projected.count(NEW_MERGE_NEEDS) == 1,
            "item-10 authority projection lost exact merge dependency overlay")
    projected = projected.replace(NEW_MERGE_NEEDS, OLD_MERGE_NEEDS, 1)

    require(projected.count("      attestations: read\n") == 1,
            "item-10 authority projection lost terminal attestation-read permission")
    projected = projected.replace("      attestations: read\n", "", 1)
    require(projected.count(DOWNLOAD_STEP) == 1,
            "item-10 authority projection lost terminal certificate download")
    projected = projected.replace(DOWNLOAD_STEP, "", 1)

    certificate_env = (
        "          EXPECTED_CERTIFICATE_SHA256: ${{ needs.authorize.outputs.certificate_sha256 }}\n"
        "          EXPECTED_SUBJECT_SHA256: ${{ needs.authorize.outputs.subject_sha256 }}\n"
    )
    require(projected.count(certificate_env) == 1,
            "item-10 authority projection lost terminal certificate identity inputs")
    projected = projected.replace(certificate_env, "", 1)

    mac_start = '          CERTIFICATE="merge-authorization-input/spotlight-merge-authorization.json"\n'
    require(projected.count(mac_start) == 1,
            "item-10 authority projection lost terminal MAC proof boundary")
    start = projected.index(mac_start)
    final_reproof = (
        '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" '
        '--jq .object.sha)" = "$BASE_SHA"\n'
    )
    end = projected.index(final_reproof, start)
    projected = projected[:start] + projected[end:]
    return projected


def validate_item10_authority(sync: str) -> None:
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

    require("id-token:" not in approve and "attestations:" not in approve,
            "Spotlight Actions approval job acquired attestation authority")

    require("name: prepare-merge-authorization-read-only" in authorize and
            "needs: [plan, lease, reconcile, budget, propose, approve]" in authorize,
            "Spotlight MAC preparer identity/dependency closure changed")
    require(
        "permissions:\n      contents: read\n      pull-requests: read\n      checks: read\n      actions: read" in authorize,
        "Spotlight MAC preparer must remain read-only",
    )
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
    require(
        "permissions:\n      contents: read\n      id-token: write\n      attestations: write" in signer,
        "Spotlight MAC signer authority changed",
    )
    for fragment in (
        "LEASE_MIN_REMAINING_SECONDS=180",
        "uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2",
        "subject-path: merge-authorization-input/spotlight-merge-authorization.subject.json",
        f"predicate-type: {PREDICATE_TYPE}",
        "predicate-path: merge-authorization-input/spotlight-merge-authorization.json",
    ):
        require(fragment in signer, f"Spotlight MAC signer lost reviewed authority surface: {fragment}")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "python3 ", "gh api ",
                      "contents: write", "pull-requests:", "checks:", "actions: write"):
        require(forbidden not in signer,
                f"Spotlight MAC signer acquired unrelated authority/execution surface: {forbidden}")

    require(NEW_MERGE_IF in merge and NEW_MERGE_NEEDS in merge,
            "Spotlight terminal merge can bypass MAC preparation/signing")
    require(
        "permissions:\n      contents: write\n      pull-requests: read\n      checks: read\n      attestations: read" in merge,
        "Spotlight terminal merge authority changed beyond read-only attestation verification",
    )
    for forbidden in ("id-token: write", "attestations: write"):
        require(forbidden not in merge,
                f"Spotlight terminal merge acquired signer authority: {forbidden}")
    verify = 'gh attestation verify "$SUBJECT"'
    mutation = 'gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge"'
    require(verify in merge and mutation in merge and merge.index(verify) < merge.index(mutation),
            "Spotlight terminal merge mutation is not downstream of cryptographic MAC verification")

    mac_start = merge.index('          CERTIFICATE="merge-authorization-input/spotlight-merge-authorization.json"\n')
    final_reproof = merge.index(
        '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"\n',
        mac_start,
    )
    mac_block = merge[mac_start:final_reproof]
    item9.core.require_exact_gh_api_surface(
        mac_block,
        label="Spotlight item-10 terminal certificate proof",
        expected_lines=(
            'CODEQL_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${CODEQL_RUN_ID}")"',
            'DEPENDENCY_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${DEPENDENCY_RUN_ID}")"',
            'PROFILE_RUN="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${PROFILE_RUN_ID}")"',
        ),
    )


def self_test_item10(sync: str) -> None:
    validate_item10_authority(sync)
    failures = (
        (sync.replace("      id-token: write\n", "      actions: write\n", 1), "OIDC authority"),
        (sync.replace("      attestations: read\n", "      attestations: write\n", 1), "attestation-write authority"),
        (sync.replace('gh attestation verify "$SUBJECT"', 'echo "$SUBJECT"', 1), "not downstream of cryptographic"),
    )
    for malformed, expected in failures:
        try:
            validate_item10_authority(malformed)
        except ValueError as exc:
            require(expected in str(exc), f"item-10 workflow authority self-test failed for wrong reason: {exc}")
        else:
            fail(f"item-10 workflow authority self-test accepted forbidden drift: {expected}")


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
        projected_sync = project_item9_sync(sync)

        item9.validate_policy_cross_contracts(policy, profile_stats, sync)
        item9.core.validate_quality_contract(QUALITY.read_text(encoding="utf-8"))
        item9.core.validate_profile_stats_contract(item9.project_legacy_profile_stats_source(profile_stats))
        item9.self_test_current_sync(projected_sync, readme)
        item9.core.validate_governance(GOVERNANCE.read_text(encoding="utf-8"))
        self_test_item10(sync)

        print(
            f"Workflow authority validation passed: {policy['policyId']} remains the executable semantic authority graph for "
            f"{len(policy['workflows'])} workflows and {sum(len(workflow['jobs']) for workflow in policy['workflows'].values())} jobs; "
            "the frozen item-9 Spotlight firewall re-proves the exact projected legacy transaction, while item 10 confines "
            "OIDC/attestation-write to one lease-bound signer and attestation-read to the terminal merger after an independently "
            "read-only MAC preparation boundary."
        )
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
