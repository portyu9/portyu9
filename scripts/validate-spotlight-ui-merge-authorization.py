#!/usr/bin/env python3
"""Extend the frozen item-9 Spotlight authorization proof with item-10 MAC semantics."""
from __future__ import annotations

from pathlib import Path
import sys

import spotlight_merge_authorization as mac_builder
import spotlight_merge_authorization_item9_core as item9

ROOT = Path(__file__).resolve().parents[1]
SYNC = ROOT / ".github/workflows/spotlight-link-sync.yml"
STATS = ROOT / ".github/workflows/profile-stats.yml"
POLICY = ROOT / ".github/SPOTLIGHT_UI_MERGE_AUTHORIZATION.md"
BUILDER = ROOT / "scripts/build-spotlight-merge-authorization.py"
BUILDER_CORE = ROOT / "scripts/spotlight_merge_authorization.py"
PREPARER = ROOT / "scripts/prepare-spotlight-merge-authorization.py"
SCHEMA = ROOT / ".github/attestation/spotlight-merge-authorization-v1.schema.json"
PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "spotlight-merge-authorization-v1.schema.json"
)
BUILDER_WRAPPER = (
    "#!/usr/bin/env python3\n"
    '"""CLI wrapper for deterministic Spotlight merge authorization certificate construction."""\n'
    "from __future__ import annotations\n\n"
    "from spotlight_merge_authorization import main\n\n\n"
    'if __name__ == "__main__":\n'
    "    raise SystemExit(main())\n"
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


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def job_block(text: str, job: str, next_job: str | None) -> str:
    marker = f"  {job}:\n"
    require(text.count(marker) == 1, f"Spotlight workflow must contain exactly one {job} job")
    start = text.index(marker)
    if next_job is None:
        return text[start:]
    end_marker = f"  {next_job}:\n"
    require(text.count(end_marker) == 1, f"Spotlight workflow must contain exactly one {next_job} job")
    return text[start:text.index(end_marker, start)]


def project_item9(sync: str) -> str:
    """Remove only item-10 jobs/merge proof so the exact item-9 validator can rerun."""
    authorize_start = sync.index("  authorize:\n")
    merge_start = sync.index("  merge:\n", authorize_start)
    legacy = sync[:authorize_start] + sync[merge_start:]
    require(legacy.count(NEW_MERGE_IF) == 1, "item-10 merge-if projection is ambiguous")
    legacy = legacy.replace(NEW_MERGE_IF, OLD_MERGE_IF, 1)
    require(legacy.count(NEW_MERGE_NEEDS) == 1, "item-10 merge-needs projection is ambiguous")
    legacy = legacy.replace(NEW_MERGE_NEEDS, OLD_MERGE_NEEDS, 1)
    legacy = legacy.replace("      attestations: read\n", "", 1)
    require(legacy.count(DOWNLOAD_STEP) == 1, "item-10 merge artifact-download projection is ambiguous")
    legacy = legacy.replace(DOWNLOAD_STEP, "", 1)
    legacy = legacy.replace(
        "          EXPECTED_CERTIFICATE_SHA256: ${{ needs.authorize.outputs.certificate_sha256 }}\n"
        "          EXPECTED_SUBJECT_SHA256: ${{ needs.authorize.outputs.subject_sha256 }}\n",
        "",
        1,
    )
    mac_start = '          CERTIFICATE="merge-authorization-input/spotlight-merge-authorization.json"\n'
    require(legacy.count(mac_start) == 1, "item-10 terminal MAC proof projection is ambiguous")
    start = legacy.index(mac_start)
    final_reproof = '          test "$(gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha)" = "$BASE_SHA"\n'
    end = legacy.index(final_reproof, start)
    legacy = legacy[:start] + legacy[end:]
    return legacy


def validate_preparer_script(text: str) -> None:
    require("def gh_json(endpoint: str)" in text and '["gh", "api", endpoint]' in text,
            "Spotlight MAC preparer must retain one GET-only GitHub API helper")
    for forbidden in ("--method", "requests.", "urllib", "curl ", "wget "):
        require(forbidden not in text, f"Spotlight MAC preparer acquired alternate/mutating network surface: {forbidden}")
    for fragment in (
        'git/ref/heads/main',
        'git/ref/heads/generated',
        'pulls/{pr_number}/files?per_page=100',
        'compare/{base}...{head}',
        'actions/runs?head_sha={head}&event=pull_request&per_page=100',
        'total == len(runs) == 3',
        'check-runs?filter=latest&per_page=100',
        'checks_total == len(checks)',
        'len(actions_checks) == 5',
    ):
        require(fragment in text, f"Spotlight MAC preparer lost independent live-state proof: {fragment}")


def validate_builder_script(wrapper: str, core: str) -> None:
    require(wrapper == BUILDER_WRAPPER,
            "Spotlight MAC builder wrapper acquired logic outside the reviewed importable core")
    require(Path(mac_builder.__file__).resolve(strict=True) == BUILDER_CORE.resolve(strict=True),
            "Spotlight MAC validator imported an unexpected builder core")
    for fragment in (
        'KIND = "spotlight-merge-authorization"',
        'SUBJECT_KIND = "spotlight-merge-authorization-subject"',
        'PREDICATE_TYPE = (',
        'candidate identity differs from exact Spotlight candidate',
        'merge authorization workflow-run identities changed',
        'merge authorization required check-run identities changed',
        'certificateSha256',
        'def self_test() -> None:',
    ):
        require(fragment in core, f"Spotlight MAC builder core contract is missing: {fragment}")
    mac_builder.self_test()


def validate_mac(sync: str) -> None:
    authorize = job_block(sync, "authorize", "authorize_attest")
    signer = job_block(sync, "authorize_attest", "merge")
    merge = job_block(sync, "merge", None)

    require("name: prepare-merge-authorization-read-only" in authorize,
            "Spotlight MAC preparer job identity changed")
    require("needs: [plan, lease, reconcile, budget, propose, approve]" in authorize,
            "Spotlight MAC preparer dependencies changed")
    require(
        "permissions:\n      contents: read\n      pull-requests: read\n      checks: read\n      actions: read" in authorize,
        "Spotlight MAC preparer must remain read-only",
    )
    require("python3 source/scripts/prepare-spotlight-merge-authorization.py" in authorize and
            "python3 source/scripts/build-spotlight-merge-authorization.py" in authorize,
            "Spotlight MAC preparer must execute only the reviewed first-party proof/build path")

    require("name: attest-merge-authorization-write-only" in signer,
            "Spotlight MAC signer identity changed")
    require("needs: [authorize, lease, plan, propose, approve]" in signer,
            "Spotlight MAC signer dependencies changed")
    require(
        "permissions:\n      contents: read\n      id-token: write\n      attestations: write" in signer,
        "Spotlight MAC signer authority changed",
    )
    require(signer.count("uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2") == 1,
            "Spotlight MAC signer must contain exactly one reviewed attestation action")
    for fragment in (
        "subject-path: merge-authorization-input/spotlight-merge-authorization.subject.json",
        f"predicate-type: {PREDICATE_TYPE}",
        "predicate-path: merge-authorization-input/spotlight-merge-authorization.json",
        "LEASE_MIN_REMAINING_SECONDS=180",
    ):
        require(fragment in signer, f"Spotlight MAC signer contract is missing: {fragment}")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "python3 ", "gh api ", "--method "):
        require(forbidden not in signer, f"Spotlight MAC signer acquired unreviewed execution surface: {forbidden}")

    require(NEW_MERGE_IF in merge and NEW_MERGE_NEEDS in merge,
            "Spotlight terminal merge can bypass MAC preparation/signing")
    require("attestations: read" in merge,
            "Spotlight terminal merge lacks explicit read-only attestation verification authority")
    for fragment in (
        "- name: Download attested merge authorization artifact",
        "EXPECTED_CERTIFICATE_SHA256: ${{ needs.authorize.outputs.certificate_sha256 }}",
        "EXPECTED_SUBJECT_SHA256: ${{ needs.authorize.outputs.subject_sha256 }}",
        'gh attestation verify "$SUBJECT"',
        f"--predicate-type {PREDICATE_TYPE}",
        '--signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/spotlight-link-sync.yml"',
        '--signer-digest "$BASE_SHA"',
        '--source-digest "$BASE_SHA"',
        "--source-ref refs/heads/main",
        "--deny-self-hosted-runners",
        'test "$MATCHING_PREDICATES" -ge 1',
    ):
        require(fragment in merge, f"Spotlight terminal MAC consumption contract is missing: {fragment}")
    verify = merge.index('gh attestation verify "$SUBJECT"')
    mutation = merge.index('gh api --method PUT "repos/${GITHUB_REPOSITORY}/pulls/${PR_NUMBER}/merge"')
    require(verify < mutation, "Spotlight terminal merge mutation moved before cryptographic MAC verification")


def expect_failure(sync: str, stats: str, policy: str, expected: str) -> None:
    try:
        item9.validate(project_item9(sync), stats, policy)
        validate_mac(sync)
    except ValueError as exc:
        require(expected in str(exc), f"item-10 Spotlight authorization self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"item-10 Spotlight authorization self-test accepted forbidden drift: {expected}")


def self_test(sync: str, stats: str, policy: str) -> None:
    item9.self_test(project_item9(sync), stats, policy)
    expect_failure(sync.replace("      attestations: read\n", "", 1), stats, policy, "lacks explicit read-only")
    expect_failure(sync.replace('gh attestation verify "$SUBJECT"', 'echo "$SUBJECT"', 1),
                   stats, policy, "terminal MAC consumption contract is missing")
    expect_failure(sync.replace("      attestations: write\n", "      actions: write\n", 1),
                   stats, policy, "signer authority changed")


def main() -> int:
    try:
        for path in (SYNC, STATS, POLICY, BUILDER, BUILDER_CORE, PREPARER, SCHEMA):
            require(path.is_file() and not path.is_symlink(),
                    f"Spotlight merge authorization input is missing or aliased: {path.relative_to(ROOT)}")
        sync = SYNC.read_text(encoding="utf-8")
        stats = STATS.read_text(encoding="utf-8")
        policy = POLICY.read_text(encoding="utf-8")
        preparer = PREPARER.read_text(encoding="utf-8")
        builder = BUILDER.read_text(encoding="utf-8")
        builder_core = BUILDER_CORE.read_text(encoding="utf-8")

        legacy = project_item9(sync)
        item9.validate(legacy, stats, policy)
        item9.self_test(legacy, stats, policy)
        validate_preparer_script(preparer)
        validate_builder_script(builder, builder_core)
        validate_mac(sync)
        self_test(sync, stats, policy)
        print(
            "Spotlight UI merge authorization validation passed: the complete frozen item-9 authorization proof still holds after exact item-10 projection; "
            "the new read-only MAC preparer independently re-proves live state, the isolated OIDC signer attests only the deterministic certificate subject, "
            "and terminal merge cryptographically verifies that certificate after fresh PR/ref/check revalidation and before expected-head mutation."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
