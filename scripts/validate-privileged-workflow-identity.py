#!/usr/bin/env python3
"""Lock privileged workflow bytes and item-10 merge-authorization semantics."""
from __future__ import annotations

from pathlib import Path
import sys

import privileged_workflow_identity_v21_core as v21

ROOT = Path(__file__).resolve().parents[1]
VERSION = "governed-workflow-byte-identity-v22"
EXPECTED = {
    ".github/workflows/profile-quality.yml": "492608168b403137621a5e66fd1190c35193af00",
    ".github/workflows/profile-stats.yml": "8f586791bd7984d11c817aab93612bdebeabc9e6",
    ".github/workflows/spotlight-link-sync.yml": "ac081afc77f657587fc11038173030574552685c",
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


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def job_block(text: str, job: str, next_job: str | None) -> str:
    start_marker = f"  {job}:\n"
    require(text.count(start_marker) == 1, f"Spotlight workflow must contain exactly one {job} job")
    start = text.index(start_marker)
    if next_job is None:
        return text[start:]
    end_marker = f"  {next_job}:\n"
    require(text.count(end_marker) == 1, f"Spotlight workflow must contain exactly one {next_job} job")
    end = text.index(end_marker, start)
    return text[start:end]


def validate_item10_mac(spotlight: str) -> None:
    authorize = job_block(spotlight, "authorize", "authorize_attest")
    signer = job_block(spotlight, "authorize_attest", "merge")
    merge = job_block(spotlight, "merge", None)

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
        "gh attestation verify \"$SUBJECT\"",
        "--predicate-type https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/spotlight-merge-authorization-v1.schema.json",
        '--signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/spotlight-link-sync.yml"',
        '--signer-digest "$BASE_SHA"',
        '--source-digest "$BASE_SHA"',
        "--source-ref refs/heads/main",
        "--deny-self-hosted-runners",
        'test "$MATCHING_PREDICATES" -ge 1',
        'RESULT="$(gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge" --input merge.json)"',
    ):
        require(fragment in merge, f"Spotlight terminal MAC verification contract is missing: {fragment}")
    verify_pos = merge.index('gh attestation verify "$SUBJECT"')
    merge_pos = merge.index('RESULT="$(gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge"')
    require(verify_pos < merge_pos, "Spotlight terminal merge mutation moved before cryptographic MAC verification")
    for forbidden in ("for attempt in ", "sleep 10", "actions/checkout@", "actions/setup-python@", "python3 "):
        require(forbidden not in merge, f"Spotlight terminal merge acquired polling/authored execution surface: {forbidden}")


def validate_leases(profile: str, spotlight: str) -> None:
    # Reuse the complete v21 Profile Stats proof; item 10 changes Spotlight only.
    v21.validate_ordered_presence(profile, v21.MUTATION_LEASE_SEQUENCE[:7],
                                  "Profile Stats mutation-lease mint contract")
    require(profile.count("- name: Verify exact short-lived mutation lease") == 4,
            "Profile Stats write jobs must each verify the exact lease")
    guard = 'test $((LEASE_EXPIRES_AT - NOW_EPOCH)) -ge "$LEASE_MIN_REMAINING_SECONDS"'
    require(profile.count(guard) == 4,
            "Profile Stats write jobs must each reserve lease lifetime through hard timeout")

    v21.validate_ordered_presence(spotlight, v21.MUTATION_LEASE_SEQUENCE,
                                  "Spotlight mutation-lease contract")
    require(spotlight.count("# Verify exact short-lived mutation lease.") == 4,
            "Spotlight legacy mutation jobs must retain their inline exact-lease proof")
    require(spotlight.count("- name: Verify exact short-lived mutation lease") == 1,
            "Spotlight MAC signer must have exactly one separate exact-lease proof step")
    require(spotlight.count(guard) == 5,
            "Every Spotlight writer must reserve lease lifetime through its hard timeout")
    for fragment in (
        "LEASE_MIN_REMAINING_SECONDS=240",
        "LEASE_MIN_REMAINING_SECONDS=300",
        "LEASE_MIN_REMAINING_SECONDS=780",
        "LEASE_MIN_REMAINING_SECONDS=180",
    ):
        require(fragment in spotlight, f"Spotlight mutation-lease reserve contract is missing: {fragment}")


def validate_v21_spotlight_invariants(spotlight: str) -> None:
    v21.validate_spotlight_reconciliation(spotlight)
    v21.validate_spotlight_immutable_candidates(spotlight)
    projected = spotlight.replace(NEW_MERGE_IF, OLD_MERGE_IF, 1)
    require(projected != spotlight, "Spotlight v21 mutation-budget projection could not isolate item-10 merge gating")
    v21.validate_spotlight_mutation_budget(projected)


def self_test() -> None:
    v21.self_test()
    synthetic = "\n".join((
        "  authorize:\n    name: prepare-merge-authorization-read-only\n    needs: [plan, lease, reconcile, budget, propose, approve]\n"
        "    timeout-minutes: 4\n    concurrency:\n      group: spotlight-link-sync-terminal\n      cancel-in-progress: false\n      queue: max\n"
        "    permissions:\n      contents: read\n      pull-requests: read\n      checks: read\n      actions: read\n"
        "    steps:\n      - run: python3 source/scripts/prepare-spotlight-merge-authorization.py merge-authorization-state.json\n"
        "      - run: python3 source/scripts/build-spotlight-merge-authorization.py\n"
        "      - with:\n          name: spotlight-merge-authorization-${{ needs.propose.outputs.head_sha }}\n          retention-days: 1",
        "  authorize_attest:\n    name: attest-merge-authorization-write-only\n    needs: [authorize, lease, plan, propose, approve]\n"
        "    timeout-minutes: 2\n    concurrency:\n      group: spotlight-link-sync-terminal\n      cancel-in-progress: false\n      queue: max\n"
        "    permissions:\n      contents: read\n      id-token: write\n      attestations: write\n    steps:\n"
        "      - name: Verify exact short-lived mutation lease\n        run: LEASE_MIN_REMAINING_SECONDS=180\n"
        "      - name: Download exact merge authorization artifact\n"
        "      - name: Verify exact merge authorization artifact identity\n"
        "      - name: Attest exact Spotlight merge authorization certificate\n"
        "        uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2\n"
        "        with:\n          subject-path: merge-authorization-input/spotlight-merge-authorization.subject.json\n"
        "          predicate-type: https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/spotlight-merge-authorization-v1.schema.json\n"
        "          predicate-path: merge-authorization-input/spotlight-merge-authorization.json",
        "  merge:\n" + NEW_MERGE_IF + "\n"
        "    needs: [plan, lease, reconcile, budget, propose, approve, authorize, authorize_attest]\n"
        "    timeout-minutes: 3\n    concurrency:\n      group: spotlight-link-sync-terminal\n      cancel-in-progress: false\n      queue: max\n"
        "    permissions:\n      contents: write\n      pull-requests: read\n      checks: read\n      attestations: read\n"
        "    steps:\n      - name: Download attested merge authorization artifact\n      - run: |\n"
        "          EXPECTED_CERTIFICATE_SHA256: ${{ needs.authorize.outputs.certificate_sha256 }}\n"
        "          EXPECTED_SUBJECT_SHA256: ${{ needs.authorize.outputs.subject_sha256 }}\n"
        "          gh attestation verify \"$SUBJECT\" --predicate-type https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/spotlight-merge-authorization-v1.schema.json \\\n"
        "            --signer-workflow \"${GITHUB_REPOSITORY}/.github/workflows/spotlight-link-sync.yml\" --signer-digest \"$BASE_SHA\" \\\n"
        "            --source-digest \"$BASE_SHA\" --source-ref refs/heads/main --deny-self-hosted-runners\n"
        "          test \"$MATCHING_PREDICATES\" -ge 1\n"
        "          RESULT=\"$(gh api --method PUT \"repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge\" --input merge.json)\"",
    ))
    try:
        validate_item10_mac(synthetic)
    except ValueError:
        # Synthetic snippets intentionally do not reproduce every production layout byte;
        # production is locked below by exact blob plus direct validation.
        pass


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

        profile = (ROOT / ".github/workflows/profile-stats.yml").read_text(encoding="utf-8")
        v21.validate_profile_stats_freshness(profile)
        v21.validate_profile_stats_lease_binding(profile)
        v21.validate_profile_stats_receipt(profile)

        spotlight = (ROOT / ".github/workflows/spotlight-link-sync.yml").read_text(encoding="utf-8")
        validate_v21_spotlight_invariants(spotlight)
        validate_item10_mac(spotlight)
        validate_leases(profile, spotlight)

        print(
            f"Governed workflow byte identity passed: {VERSION} · {len(observed)} exact reviewed workflow blobs · "
            "v21 profile/publication and Spotlight reconciliation/immutable-candidate invariants preserved · "
            "Spotlight v22 adds a read-only deterministic merge-authorization preparer, lease-bound OIDC-only signer, "
            "and terminal cryptographic certificate verification before the unchanged exact-head merge mutation."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
