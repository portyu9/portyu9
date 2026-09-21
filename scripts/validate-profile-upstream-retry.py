#!/usr/bin/env python3
"""Fail closed on Profile Quality's witness-first bounded pinned-upstream retry boundary."""
from __future__ import annotations

from pathlib import Path
import re
import sys

from profile_generator_compatibility_witness import self_test as compatibility_witness_self_test

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/profile-quality.yml"
UPSTREAM_SHA = "49b5f7091182a45f3ef93923505b660c6da5f835"
UPSTREAM_USES = f"shinpr/github-profile-stats@{UPSTREAM_SHA} # v0.2.0"
DOWNLOAD_USES = "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1"
PREDICATE_TYPE = "https://github.com/portyu9/portyu9/attestations/profile-generator-compatibility/v1"
FALLBACK_IF = "steps.profile_generator_witness_verify.outcome != 'success'"
RETRY_IF = FALLBACK_IF + " && steps.stats_primary.outcome == 'failure'"


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def job_block(text: str, key: str, next_key: str | None) -> str:
    start = re.search(rf"(?m)^  {re.escape(key)}:\s*$", text)
    require(start is not None, f"workflow job is missing: {key}")
    if next_key is None:
        return text[start.start():]
    relative = text[start.end():]
    end = re.search(rf"(?m)^  {re.escape(next_key)}:\s*$", relative)
    require(end is not None, f"workflow job boundary is missing after {key}: {next_key}")
    return text[start.start(): start.end() + end.start()]


def step_block(job: str, name: str, next_name: str | None) -> str:
    marker = f"      - name: {name}\n"
    require(job.count(marker) == 1, f"integration step identity changed or is ambiguous: {name}")
    start = job.index(marker)
    if next_name is None:
        return job[start:]
    next_marker = f"      - name: {next_name}\n"
    require(job.count(next_marker) == 1, f"integration step boundary is missing: {next_name}")
    end = job.index(next_marker, start + len(marker))
    return job[start:end]


def require_action(block: str, *, primary: bool) -> None:
    label = "primary" if primary else "retry"
    expected_id = "stats_primary" if primary else "stats_retry"
    expected_if = FALLBACK_IF if primary else RETRY_IF
    require(f"        id: {expected_id}\n" in block,
            f"Pinned upstream {label} step id changed")
    require(f"        if: {expected_if}\n" in block,
            f"Pinned upstream {label} fallback condition changed")
    require(f"        uses: {UPSTREAM_USES}\n" in block,
            f"Pinned upstream {label} Action identity changed")
    require(block.count("username: portyu9") == 1 and
            block.count('token: ${{ github.token }}') == 1 and
            block.count("profile: signal-field") == 1,
            f"Pinned upstream {label} input surface changed")
    if primary:
        require("        continue-on-error: true\n" in block,
                "Primary pinned upstream attempt must expose failure to the one reviewed retry path")
    else:
        require("continue-on-error:" not in block,
                "Retry pinned upstream Action must fail the integration job if it fails")


def validate(text: str) -> None:
    integration = job_block(text, "integration", None)
    require("name: integration-pinned-upstream" in integration,
            "Pinned upstream integration job identity changed")
    permissions = (
        "permissions:\n"
        "      actions: read\n"
        "      attestations: read\n"
        "      contents: read"
    )
    require(integration.count(permissions) == 1,
            "Pinned upstream witness consumer read authority changed")
    for forbidden in (
        "actions: write", "attestations: write", "checks: write", "contents: write",
        "id-token: write", "pull-requests: write", "packages: write", "security-events: write",
    ):
        require(forbidden not in integration,
                f"Pinned upstream witness consumer acquired forbidden write authority: {forbidden}")
    require(integration.count(f"uses: {UPSTREAM_USES}") == 2,
            "Integration must retain exactly two possible live attempts of one immutable upstream Action identity")

    names = (
        "Discover exact fresh signed Profile Generator Compatibility Witness",
        "Download exact fresh signed Profile Generator Compatibility Witness",
        "Verify and consume exact fresh signed Profile Generator Compatibility Witness",
        "Generate actual pinned upstream Signal Field",
        "Back off before one exact pinned upstream retry",
        "Retry exact pinned upstream Signal Field once",
        "Select successful exact pinned upstream output",
        "Exercise canonical profile evidence generation pipeline",
    )
    discovery = step_block(integration, names[0], names[1])
    download = step_block(integration, names[1], names[2])
    verify = step_block(integration, names[2], names[3])
    primary = step_block(integration, names[3], names[4])
    backoff = step_block(integration, names[4], names[5])
    retry = step_block(integration, names[5], names[6])
    selector = step_block(integration, names[6], names[7])

    for fragment in (
        "        id: profile_generator_witness_discovery",
        "        continue-on-error: true",
        "GH_TOKEN: ${{ github.token }}",
        'gh api "repos/${GITHUB_REPOSITORY}/actions/workflows/profile-generator-compatibility-witness.yml/runs?branch=main&status=success&per_page=100"',
        'gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/attempts/${RUN_ATTEMPT}"',
        'gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${RUN_ID}/artifacts?per_page=100"',
        "python3 scripts/profile_generator_compatibility_witness.py select-run",
        "python3 scripts/profile_generator_compatibility_witness.py select-artifact",
    ):
        require(fragment in discovery,
                f"Profile generator compatibility witness discovery contract changed: {fragment}")
    require(discovery.count("gh api ") == 3,
            "Profile generator compatibility witness discovery API surface changed")

    require("        id: profile_generator_witness_download\n" in download,
            "Profile generator compatibility witness download step id changed")
    require("        if: steps.profile_generator_witness_discovery.outcome == 'success'\n" in download,
            "Profile generator compatibility witness download condition changed")
    require("        continue-on-error: true\n" in download,
            "Profile generator compatibility witness download must fail into live fallback")
    for fragment in (
        f"uses: {DOWNLOAD_USES}",
        "name: profile-generator-compatibility-witness-v1",
        "path: profile-generator-compatibility-witness-consumer",
        "github-token: ${{ github.token }}",
        "run-id: ${{ steps.profile_generator_witness_discovery.outputs.run_id }}",
        "digest-mismatch: error",
    ):
        require(fragment in download,
                f"Profile generator compatibility witness artifact transport changed: {fragment}")

    require("        id: profile_generator_witness_verify\n" in verify,
            "Profile generator compatibility witness verify step id changed")
    require(
        "        if: steps.profile_generator_witness_discovery.outcome == 'success' && "
        "steps.profile_generator_witness_download.outcome == 'success'\n" in verify,
        "Profile generator compatibility witness verify condition changed",
    )
    require("        continue-on-error: true\n" in verify,
            "Profile generator compatibility witness verification must fail into live fallback")
    for fragment in (
        'gh attestation verify "$SUBJECT"',
        '--repo "$GITHUB_REPOSITORY"',
        f"--predicate-type {PREDICATE_TYPE}",
        '--signer-workflow "${GITHUB_REPOSITORY}/.github/workflows/profile-generator-compatibility-witness.yml"',
        '--signer-digest "$SOURCE_SHA"',
        '--source-digest "$SOURCE_SHA"',
        "--source-ref refs/heads/main",
        "--deny-self-hosted-runners",
        "--format json",
        "python3 scripts/profile_generator_compatibility_witness.py consume-evidence",
        '--signal-field-dir "$RAW_DIR"',
        'echo "ready-dir=$RAW_DIR" >> "$GITHUB_OUTPUT"',
    ):
        require(fragment in verify,
                f"Profile generator compatibility witness cryptographic/local validation changed: {fragment}")
    require(verify.count("gh attestation verify ") == 1,
            "Profile generator compatibility witness must perform exactly one attestation verification")
    require(verify.count("consume-evidence") == 1,
            "Profile generator compatibility witness must consume exactly one evidence bundle")
    require("signal_field_pipeline.py" not in verify,
            "Profile generator compatibility witness consumer must not duplicate canonical Signal Field sequencing")

    require_action(primary, primary=True)
    require(f"        if: {RETRY_IF}\n" in backoff,
            "Pinned upstream retry backoff fallback condition changed")
    require(backoff.count("        run: sleep 60\n") == 1,
            "Pinned upstream retry must use exactly one 60-second backoff")
    require("gh api" not in backoff and "curl " not in backoff and "wget " not in backoff,
            "Pinned upstream retry backoff must remain passive and must not poll")
    require_action(retry, primary=False)

    require("        id: stats\n" in selector,
            "Pinned upstream selector must retain the canonical downstream step id")
    for fragment in (
        'WITNESS_OUTCOME: ${{ steps.profile_generator_witness_verify.outcome }}',
        'WITNESS_READY_DIR: ${{ steps.profile_generator_witness_verify.outputs.ready-dir }}',
        'PRIMARY_OUTCOME: ${{ steps.stats_primary.outcome }}',
        'PRIMARY_READY_DIR: ${{ steps.stats_primary.outputs.ready-dir }}',
        'RETRY_OUTCOME: ${{ steps.stats_retry.outcome }}',
        'RETRY_READY_DIR: ${{ steps.stats_retry.outputs.ready-dir }}',
        'if [ "$WITNESS_OUTCOME" = "success" ]; then',
        'elif [ "$PRIMARY_OUTCOME" = "success" ]; then',
        'test "$PRIMARY_OUTCOME" = "failure"',
        'test "$RETRY_OUTCOME" = "success"',
        'echo "ready-dir=$READY_DIR" >> "$GITHUB_OUTPUT"',
    ):
        require(fragment in selector, f"Pinned upstream successful-output selector changed: {fragment}")
    require(selector.count("ready-dir=$READY_DIR") == 1,
            "Pinned upstream selector must emit exactly one canonical ready-dir output")

    require("search/issues" not in integration,
            "Pinned upstream witness/fallback path must not introduce Search polling")
    for forbidden in ("--method POST", "--method PUT", "--method PATCH", "--method DELETE"):
        require(forbidden not in integration,
                f"Pinned upstream witness/fallback path acquired mutation API surface: {forbidden}")

    tail = integration[integration.index(f"      - name: {names[7]}\n"):]
    require("steps.stats_primary" not in tail and "steps.stats_retry" not in tail
            and "steps.profile_generator_witness_verify" not in tail,
            "Downstream integration must consume only the canonical successful-output selector")
    require("steps.stats.outputs.ready-dir" in tail,
            "Downstream integration lost the canonical selected ready-dir boundary")


def expect_failure(text: str, expected: str) -> None:
    try:
        validate(text)
    except ValueError as exc:
        require(expected in str(exc), f"self-test failed for wrong reason: {exc}")
    else:
        fail(f"self-test accepted forbidden pinned-upstream witness/retry drift: {expected}")


def self_test(text: str) -> None:
    expect_failure(
        text.replace(UPSTREAM_SHA, "0" * 40, 1),
        "exactly two possible live attempts",
    )
    integration_permissions = (
        "  integration:\n"
        "    name: integration-pinned-upstream\n"
        "    runs-on: ubuntu-24.04\n"
        "    timeout-minutes: 12\n"
        "    permissions:\n"
        "      actions: read\n"
        "      attestations: read\n"
        "      contents: read\n"
    )
    require(text.count(integration_permissions) == 1,
            "self-test could not isolate integration witness permissions")
    expect_failure(
        text.replace(
            integration_permissions,
            integration_permissions.replace("      actions: read\n", "      actions: write\n"),
            1,
        ),
        "read authority changed",
    )
    expect_failure(
        text.replace(PREDICATE_TYPE, "https://example.invalid/v1", 1),
        "cryptographic/local validation changed",
    )
    expect_failure(
        text.replace("        run: sleep 60\n", "        run: sleep 1\n", 1),
        "60-second backoff",
    )
    expect_failure(
        text.replace(f"        if: {FALLBACK_IF}\n", "        if: always()\n", 1),
        "primary fallback condition changed",
    )
    expect_failure(
        text.replace("        id: stats_retry\n", "        id: stats_retry\n        continue-on-error: true\n", 1),
        "must fail the integration job",
    )
    injected_pipeline = text.replace(
        '          echo "ready-dir=$RAW_DIR" >> "$GITHUB_OUTPUT"\n',
        '          python3 scripts/signal_field_pipeline.py "$RAW_DIR"\n'
        '          echo "ready-dir=$RAW_DIR" >> "$GITHUB_OUTPUT"\n',
        1,
    )
    expect_failure(injected_pipeline, "must not duplicate canonical Signal Field sequencing")
    expect_failure(
        text.replace('READY_DIR: ${{ steps.stats.outputs.ready-dir }}',
                     'READY_DIR: ${{ steps.stats_primary.outputs.ready-dir }}', 1),
        "canonical successful-output selector",
    )
    injected_poll = text.replace(
        "      - name: Generate actual pinned upstream Signal Field\n",
        "      - name: Poll Search first\n        run: gh api search/issues\n\n"
        "      - name: Generate actual pinned upstream Signal Field\n",
        1,
    )
    expect_failure(injected_poll, "must not introduce Search polling")


def main() -> int:
    try:
        require(WORKFLOW.is_file(), "Profile Quality workflow is missing")
        text = WORKFLOW.read_text(encoding="utf-8")
        validate(text)
        self_test(text)
        compatibility_witness_self_test()
        print(
            "Pinned upstream witness/retry validation passed: one cryptographically verified current-epoch "
            "raw Signal Field witness may satisfy the canonical ready-dir boundary; otherwise the immutable "
            "upstream Action retains exactly one primary attempt, one passive 60-second backoff, and one "
            "terminal retry, with no Search polling, write authority, or downstream bypass."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
