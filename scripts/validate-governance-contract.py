#!/usr/bin/env python3
"""Validate repository governance encoded in version-controlled workflows."""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
QUALITY = ROOT / ".github/workflows/profile-quality.yml"
STATS = ROOT / ".github/workflows/profile-stats.yml"
GOVERNANCE = ROOT / ".github/GOVERNANCE.md"
CADENCE = ROOT / ".github/REFRESH_CADENCE.md"
PIPELINE = ROOT / "scripts/signal_field_pipeline.py"
PIPELINE_MANIFEST = ROOT / "scripts/signal-field-pipeline-v1.json"
GENERATION_MANIFEST = ROOT / "scripts/profile-evidence-generation-v1.json"
GENERATION_RUNNER = ROOT / "scripts/generate-profile-evidence.py"
VALIDATION_MANIFEST = ROOT / "scripts/profile-evidence-validation-boundary-v1.json"
VALIDATION_LOADER = ROOT / "scripts/profile_evidence_validation.py"
VALIDATION_RUNNER = ROOT / "scripts/validate-profile-evidence-boundary.py"

CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "5fda3b95a4ea91299a34e894583c3862153e4b97"
UPLOAD_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
DOWNLOAD_SHA = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
UPSTREAM_SHA = "49b5f7091182a45f3ef93923505b660c6da5f835"
ATTEST_SHA = "1e69f48acb82d1966a394da916b4c1698aa569d6"
DIRECT_PIPELINE_STAGE_MARKERS = (
    "customize-signal-field.py \"$READY_DIR\"",
    "polish-signal-field-v2.py \"$READY_DIR\"",
    "enhance-signal-field-v2.py \"$READY_DIR\"",
    "identify-signal-field-evidence.py \"$READY_DIR\"",
    "set-signal-field-refresh-cadence.py \"$READY_DIR\"",
    "validate-generated-signal-field.py \"$READY_DIR\"",
)
DIRECT_GENERATION_SCRIPTS = (
    "signal_field_pipeline.py",
    "generate-portfolio-evidence-ledger.py",
    "validate-portfolio-evidence-ledger.py",
    "generate-engineering-spotlight.py",
    "validate-engineering-spotlight.py",
)


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def job_block(workflow: str, key: str, next_key: str | None) -> str:
    start = re.search(rf"(?m)^  {re.escape(key)}:\s*$", workflow)
    require(start is not None, f"workflow job is missing: {key}")
    if next_key is None:
        return workflow[start.start():]
    relative = workflow[start.end():]
    end = re.search(rf"(?m)^  {re.escape(next_key)}:\s*$", relative)
    require(end is not None, f"workflow job boundary is missing: {next_key}")
    return workflow[start.start(): start.end() + end.start()]


def require_generation_entrypoint(
    block: str, *, command: str, signal: str, ledger: str, spotlight: str, label: str,
) -> None:
    require(block.count("generate-profile-evidence.py") == 1,
            f"{label} must invoke the canonical profile evidence generation pipeline exactly once")
    require(command in block, f"{label} must invoke the reviewed generation entrypoint")
    for fragment in (
        f"--signal-field-dir {signal}",
        f"--portfolio-ledger-dir {ledger}",
        f"--spotlight-dir {spotlight}",
    ):
        require(fragment in block, f"{label} canonical generation pipeline is missing: {fragment}")
    for script in DIRECT_GENERATION_SCRIPTS:
        require(script not in block, f"{label} must not duplicate authored generation sequencing: {script}")
    for marker in DIRECT_PIPELINE_STAGE_MARKERS:
        require(marker not in block, f"{label} must not duplicate Signal Field stage ordering: {marker}")


def require_validation_boundary(block: str, *, signal: str, spotlight: str, ledger: str, label: str) -> None:
    require(block.count("validate-profile-evidence-boundary.py") == 1,
            f"{label} must invoke the canonical profile evidence validation boundary exactly once")
    for fragment in (
        f"--signal-field-dir {signal}",
        f"--spotlight-dir {spotlight}",
        f"--portfolio-ledger-dir {ledger}",
    ):
        require(fragment in block, f"{label} canonical validation boundary is missing: {fragment}")


def validate_publish_write_surface(publish: str) -> None:
    require(publish.count("      - name: ") == 4,
            "Write-only publication must contain exactly four reviewed steps")
    require(publish.count(f"uses: actions/download-artifact@{DOWNLOAD_SHA}") == 1,
            "Write-only publication must execute only the reviewed candidate download Action")
    require(publish.count("        uses: ") == 1,
            "Write-only publication must contain exactly one external Action step")
    for forbidden in (
        "actions/checkout@", "actions/setup-python@", "python3 ", "git commit", "git add",
        "gh ", "curl ", "wget ", "persist-credentials:", "id-token:", "attestations:",
    ):
        require(forbidden not in publish,
                f"Write-only publication contains forbidden code/authority surface: {forbidden}")
    require(publish.count("digest-mismatch: error") == 1,
            "Sealed publication candidate download must fail closed on digest mismatch")
    for fragment in (
        "git bundle list-heads publication-candidate/generated-publication.bundle",
        "git -C artifacts bundle verify ../publication-candidate/generated-publication.bundle",
        "git -C artifacts rev-parse HEAD",
        "git -C artifacts rev-parse HEAD^",
        "git -C artifacts rev-list --parents -n 1 HEAD",
        "git -C artifacts ls-tree -r --name-only HEAD",
        "git -C artifacts ls-tree -r HEAD",
        "git -C artifacts remote add origin https://github.com/portyu9/portyu9",
        "git -C artifacts remote get-url origin",
        "generated-publication.bundle",
        "expected-publication-paths.txt",
        "observed-publication-paths.txt",
    ):
        require(fragment in publish, f"Write-only publication verification is missing: {fragment}")
    for path in (
        "profile-stats/profile/signal-field-wide-light.svg",
        "profile-stats/profile/signal-field-wide-dark.svg",
        "profile-stats/profile/signal-field-compact-light.svg",
        "profile-stats/profile/signal-field-compact-dark.svg",
        "engineering-spotlight/spotlight-1-light.svg",
        "engineering-spotlight/spotlight-1-dark.svg",
        "engineering-spotlight/spotlight-2-light.svg",
        "engineering-spotlight/spotlight-2-dark.svg",
        "engineering-spotlight/spotlight-3-light.svg",
        "engineering-spotlight/spotlight-3-dark.svg",
        "portfolio-evidence/portfolio-evidence-ledger.json",
    ):
        require(publish.count(path) == 1, f"Write-only publication exact path closure changed: {path}")
    expressions = re.findall(r"\$\{\{\s*([^}]+?)\s*\}\}", publish)
    require(
        expressions == [
            "needs.stage.outputs.base_sha",
            "needs.stage.outputs.candidate_sha",
            "needs.stage.outputs.source_sha",
            "github.token",
            "needs.stage.outputs.source_sha",
        ],
        f"Write-only publication expression surface changed: {expressions!r}",
    )
    marker = "      - name: Publish sealed artifact commit\n"
    require(publish.count(marker) == 1, "Publication must contain one exact terminal push step")
    terminal = publish[publish.index(marker):]
    require(terminal.count("      - name: ") == 1,
            "No authored step may follow explicit publication token introduction")
    for fragment in (
        "          SOURCE_SHA: ${{ needs.stage.outputs.source_sha }}",
        '          [[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]',
        '          REMOTE_MAIN="$(git -C artifacts ls-remote --exit-code origin refs/heads/main)"',
        '          [[ "$REMOTE_MAIN" =~ ^([0-9a-f]{40})[[:space:]]refs/heads/main$ ]]',
        '          test "${BASH_REMATCH[1]}" = "$SOURCE_SHA"',
    ):
        require(terminal.count(fragment) == 1,
                f"Publication terminal source-freshness contract changed: {fragment}")
    freshness_guard = '          test "${BASH_REMATCH[1]}" = "$SOURCE_SHA"'
    auth_intro = '          AUTH_HEADER="$(printf \'x-access-token:%s\' "$GITHUB_TOKEN" | base64 -w0)"'
    push = 'git -C artifacts -c "http.https://github.com/.extraheader=AUTHORIZATION: basic ${AUTH_HEADER}" push origin HEAD:generated'
    require(terminal.index(freshness_guard) < terminal.index(auth_intro) < terminal.index(push),
            "Publication must prove current main source before token derivation and exact generated push")
    require(push in terminal, "Publication exact terminal generated push changed")


def validate_quality(text: str) -> None:
    require("name: Profile quality" in text, "Profile quality workflow name changed")
    require('PYTHON_VERSION: "3.13.15"' in text, "Profile quality Python version is not explicit")
    require(text.count("runs-on: ubuntu-24.04") == 2, "Both Profile Quality jobs must pin ubuntu-24.04")
    require(text.count(f"actions/checkout@{CHECKOUT_SHA}") == 2, "Both Profile Quality jobs must use reviewed checkout")
    require(text.count(f"actions/setup-python@{SETUP_PYTHON_SHA}") == 2, "Both Profile Quality jobs must use reviewed setup-python")
    require("cancel-in-progress: true" in text, "Profile Quality must cancel stale runs")
    require('- ".github/REFRESH_CADENCE.md"' in text, "Profile Quality push paths must cover refresh governance")

    validate = job_block(text, "validate", "integration")
    integration = job_block(text, "integration", None)
    require("name: validate-contracts" in validate, "Required contract-check job name changed")
    require("name: integration-pinned-upstream" in integration, "Required integration-check job name changed")
    require("permissions:\n      contents: read" in validate and "permissions:\n      contents: read" in integration,
            "Profile Quality jobs must remain read-only")
    require(f"shinpr/github-profile-stats@{UPSTREAM_SHA}" in integration,
            "PR integration must execute reviewed pinned upstream generator")
    require("python3 scripts/signal_field_pipeline.py --self-test" in validate,
            "Profile Quality must self-test the governed Signal Field pipeline")
    require("python3 scripts/generate-profile-evidence.py --self-test" in validate,
            "Profile Quality must self-test canonical evidence generation")
    require("python3 scripts/profile_evidence_validation.py" in validate,
            "Profile Quality must validate the canonical profile evidence boundary contract")
    require_generation_entrypoint(
        integration,
        command="python3 scripts/generate-profile-evidence.py",
        signal='"$READY_DIR"', ledger="integration-portfolio-evidence",
        spotlight="integration-engineering-spotlight", label="PR integration",
    )
    require_validation_boundary(
        integration,
        signal='"$SIGNAL_FIELD_DIR"', spotlight="integration-engineering-spotlight",
        ledger="integration-portfolio-evidence", label="PR integration",
    )
    for command in (
        "python3 scripts/validate-profile-cache-contract.py",
        "python3 scripts/validate-action-release-provenance.py",
        "python3 scripts/validate-dependency-review-contract.py",
        "python3 scripts/validate-workflow-authority-contract.py",
        "python3 scripts/validate-workflow-shell-safety.py",
        "python3 scripts/validate-governance-contract.py",
        "python3 scripts/validate-profile-attestation-contract.py",
    ):
        require(command in validate, f"Profile Quality contract step disappeared: {command}")
    require("python3 scripts/write-profile-contract-summary.py --self-test" in validate,
            "Profile Quality must self-test the read-only contract summary renderer")
    require("python3 scripts/write-profile-contract-summary.py" in integration,
            "Profile Quality integration must publish the read-only contract summary")


def validate_stats(text: str) -> None:
    require("name: Update profile stats" in text, "Profile stats workflow name changed")
    require('cron: "17 * * * *"' in text, "Hourly best-effort refresh contract changed")
    require('cron: "17,47 * * * *"' not in text and 'cron: "2-57/5 * * * *"' not in text,
            "Stale higher-frequency cron remains in production workflow")
    require("cancel-in-progress: true" in text, "Stats workflow must cancel stale runs")
    require('PYTHON_VERSION: "3.13.15"' in text, "Stats Python version is not explicit")
    require(text.count("runs-on: ubuntu-24.04") == 6, "All six stats jobs must pin ubuntu-24.04")

    generate = job_block(text, "generate", "attest")
    prepare = job_block(text, "attest", "attest_publish")
    attest_write = job_block(text, "attest_publish", "stage")
    stage = job_block(text, "stage", "publish")
    publish = job_block(text, "publish", "dispatch")
    dispatch = job_block(text, "dispatch", None)

    require("name: generate-read-only" in generate, "Read-only generation job name changed")
    require("name: prepare-attestation-read-only" in prepare, "Attestation preparation job name changed")
    require("name: attest-write-only" in attest_write, "Terminal attestation job name changed")
    require("name: stage-publication-read-only" in stage, "Publication staging job name changed")
    require("name: publish-write-only" in publish, "Write-only publication job name changed")
    require("name: dispatch-spotlight-link-sync" in dispatch, "Dispatcher job name changed")

    require("permissions:\n      contents: read" in generate,
            "Third-party generation job must remain contents: read")
    for forbidden in ("contents: write", "id-token: write", "attestations: write"):
        require(forbidden not in generate, f"Generation received forbidden authority: {forbidden}")
    require_generation_entrypoint(
        generate,
        command="python3 source/scripts/generate-profile-evidence.py",
        signal='"$READY_DIR"', ledger="portfolio-ledger-ready", spotlight="spotlight-ready",
        label="Production generation",
    )

    require("needs: generate" in prepare and "permissions:\n      contents: read" in prepare,
            "Attestation preparation must depend on generation and remain read-only")
    for forbidden in ("id-token: write", "attestations: write", "contents: write", f"actions/attest@{ATTEST_SHA}"):
        require(forbidden not in prepare,
                f"Attestation preparation acquired terminal authority/surface: {forbidden}")
    require_validation_boundary(
        prepare,
        signal="profile-stats/profile", spotlight="engineering-spotlight",
        ledger="portfolio-evidence", label="Attestation preparation boundary",
    )
    require("python3 source/scripts/build-profile-evidence-attestation.py profile-stats/profile portfolio-evidence attestation-predicate.json" in prepare,
            "Read-only preparation must build the reviewed attestation predicate")
    require(prepare.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 3,
            "Attestation preparation must download all three evidence sets")
    require(prepare.count("digest-mismatch: error") == 3,
            "Attestation preparation downloads must fail closed")
    require(prepare.count(f"actions/upload-artifact@{UPLOAD_SHA}") == 1,
            "Attestation preparation must upload exactly one predicate artifact")

    require("needs: attest" in attest_write,
            "Terminal attestation must consume only read-only preparation")
    require("contents: read" in attest_write and "id-token: write" in attest_write and "attestations: write" in attest_write,
            "Terminal attestation authority changed")
    for forbidden in ("contents: write", "actions/checkout@", "actions/setup-python@", "        run:", "python3 ", "git ", "gh "):
        require(forbidden not in attest_write,
                f"Terminal attestation acquired forbidden authored code/mutation surface: {forbidden}")
    require(attest_write.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 4,
            "Terminal attestation must download three evidence sets plus the reviewed predicate")
    require(attest_write.count("digest-mismatch: error") == 4,
            "Terminal attestation downloads must all fail closed")
    require(attest_write.count(f"actions/attest@{ATTEST_SHA}") == 1,
            "Terminal attestation must execute exactly one pinned actions/attest")
    require(attest_write.count("      - name: ") == 5,
            "Terminal attestation must contain exactly four downloads plus one attest action")
    guard = "if: github.event_name != 'schedule' || needs.attest.outputs.changed == 'true'"
    require(attest_write.startswith(f"  attest_publish:\n    {guard}\n"),
            "Terminal attestation must use the exact scheduled-delta guard at the job boundary")
    require(attest_write.count(guard) == 6,
            "Terminal attestation job and all five terminal steps must share the exact scheduled-delta guard")

    require("needs: [generate, attest, attest_publish]" in stage,
            "Publication staging must depend on generation, preparation, and terminal attestation")
    require("permissions:\n      contents: read" in stage, "Publication staging must remain read-only")
    for forbidden in ("contents: write", "id-token: write", "attestations: write", "GITHUB_TOKEN:", "git push"):
        require(forbidden not in stage, f"Publication staging acquired forbidden authority/mutation surface: {forbidden}")
    require_validation_boundary(
        stage,
        signal="publish-input", spotlight="spotlight-publish-input",
        ledger="portfolio-ledger-publish-input", label="Publication staging boundary",
    )
    for fragment in (
        "python3 source/scripts/validate-signal-field-v214.py artifacts/profile-stats/profile",
        "find artifacts -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +",
        'git -C artifacts commit -m "chore: publish validated profile evidence [skip ci]"',
        "git -C artifacts bundle create ../generated-publication.bundle generated",
        "git -C artifacts bundle verify ../generated-publication.bundle",
        "fetch-depth: 0",
        'source_sha="$(git -C source rev-parse HEAD)"',
        'test "$source_sha" = "$GITHUB_SHA"',
        'echo "source_sha=$source_sha" >> "$GITHUB_OUTPUT"',
        'source_sha: ${{ steps.seal.outputs.source_sha }}',
    ):
        require(fragment in stage, f"Publication staging sealing contract is missing: {fragment}")
    require(stage.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 3,
            "Publication staging must download three evidence sets")
    require(stage.count("digest-mismatch: error") == 3,
            "Publication staging downloads must fail closed")
    require(stage.count(f"actions/upload-artifact@{UPLOAD_SHA}") == 1,
            "Publication staging must upload exactly one sealed candidate bundle")
    require(stage.count("persist-credentials: false") == 2,
            "Both publication staging checkouts must remain credential-free")

    require("permissions:\n      contents: write" in publish and "needs: stage" in publish,
            "Write-only publication authority/dependency changed")
    publication_guard = "if: needs.stage.outputs.changed == 'true'"
    require(publish.startswith(f"  publish:\n    {publication_guard}\n"),
            "Write-only publication must use the exact staged-candidate guard at the job boundary")
    require(publish.count(publication_guard) == 4,
            "Write-only publication job and all three changed-candidate steps must share the exact staged-candidate guard")
    validate_publish_write_surface(publish)

    require("needs: publish" in dispatch and "permissions:\n      actions: write" in dispatch,
            "Spotlight dispatch dependency/authority changed")
    for forbidden in ("contents:", "pull-requests:", "checks:", "id-token:", "attestations:", "security-events:"):
        require(forbidden not in dispatch, f"Spotlight dispatcher received forbidden authority: {forbidden}")
    require("actions/checkout@" not in dispatch and "actions/setup-python@" not in dispatch,
            "Spotlight dispatcher must not checkout or execute authored Python")
    require("actions/workflows/spotlight-link-sync.yml/dispatches" in dispatch and "-f ref=main" in dispatch,
            "Spotlight dispatcher target changed")

    require(f"shinpr/github-profile-stats@{UPSTREAM_SHA}" in generate, "Pinned upstream generator SHA changed")
    require(generate.count(f"actions/upload-artifact@{UPLOAD_SHA}") == 3,
            "Generation must upload exactly three evidence sets")
    require(text.count(f"actions/checkout@{CHECKOUT_SHA}") == 5,
            "Stats workflow must retain five reviewed checkout calls")
    require(text.count(f"actions/setup-python@{SETUP_PYTHON_SHA}") == 3,
            "Stats setup-python action inventory changed")
    require(generate.count("persist-credentials: false") == 1,
            "Generation checkout must not persist credentials")
    require(prepare.count("persist-credentials: false") == 2,
            "Attestation preparation checkouts must not persist credentials")


def validate_governance_doc(text: str) -> None:
    for phrase in (
        "Profile quality / validate-contracts",
        "Profile quality / integration-pinned-upstream",
        "Dependency review / dependency-review",
        "Protect Main",
        "Action release provenance",
        "Workflow authority firewall",
        "Workflow shell safety",
        "shell source",
        "closed allowlist",
        "generated",
        "deletion",
        "non-fast-forward",
        "GitHub Actions",
        "Signal Field Evidence ID",
        "signal-field-evidence-v1",
        "full SHA-256",
        "attest-validated-evidence",
        "prepare-attestation-read-only",
        "attest-write-only",
        "stage-publication-read-only",
        "profile-evidence-validation-boundary-v1",
        "sealed Git bundle",
        "id-token: write",
        "attestations: write",
        "post-publication",
        "actions: write only",
        "not certify every software behavior",
    ):
        require(phrase in text, f"Governance documentation is missing: {phrase}")


def validate_cadence_doc(text: str) -> None:
    for phrase in (
        "profile-refresh-v2", "17 * * * *", "2-57/5 * * * *",
        "best-effort hourly generation refresh", "4h32m", "3h40m", "3h28m", "2h47m",
        'data-generation-schedule="1-hour"',
        'data-generation-cadence-contract="profile-refresh-v2"',
        'data-current-day-highlight="phosphorescent-red-v1"',
        "REFRESH · 1 HR",
        "Generation refresh cadence and evidence freshness are different claims",
        "push-triggered", "workflow_dispatch",
    ):
        require(phrase in text, f"Refresh-cadence documentation is missing: {phrase}")


def main() -> int:
    try:
        for path in (
            QUALITY, STATS, GOVERNANCE, CADENCE, PIPELINE, PIPELINE_MANIFEST,
            GENERATION_MANIFEST, GENERATION_RUNNER, VALIDATION_MANIFEST,
            VALIDATION_LOADER, VALIDATION_RUNNER,
        ):
            require(path.is_file(), f"governance input is missing: {path.relative_to(ROOT)}")
        validate_quality(QUALITY.read_text(encoding="utf-8"))
        validate_stats(STATS.read_text(encoding="utf-8"))
        validate_governance_doc(GOVERNANCE.read_text(encoding="utf-8"))
        validate_cadence_doc(CADENCE.read_text(encoding="utf-8"))
        print(
            "Repository governance validation passed: PR checks remain stable/read-only; dependency/action provenance is mandatory; "
            "generation and attestation preparation execute authored code with read-only authority; terminal OIDC/attestation authority executes only digest-checked transport plus pinned actions/attest; "
            "publication staging seals the generated candidate and trusted source epoch under read-only authority; terminal contents-write publication re-proves current main source before token derivation and one exact generated push; "
            "and post-publication Spotlight dispatch remains isolated to actions: write."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
