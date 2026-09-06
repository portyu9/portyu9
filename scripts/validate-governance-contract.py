#!/usr/bin/env python3
"""Validate repository governance encoded in version-controlled workflows.

GitHub repository rulesets are settings-level controls and are not writable from every
integration. This validator therefore protects the executable half of the governance
contract: named PR checks, explicit runtime, pinned dependencies, release provenance,
closed workflow authority, shell-safe expression boundaries, least-privilege profile
evidence generation/identity/attestation/publication, measured refresh cadence,
generated-surface cache binding, fresh-run concurrency, artifact-only publish behavior,
and the single governed Signal Field pipeline entrypoint.
"""
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


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def job_block(workflow: str, key: str, next_key: str | None) -> str:
    start_pattern = re.compile(rf"(?m)^  {re.escape(key)}:\s*$")
    start = start_pattern.search(workflow)
    if not start:
        fail(f"workflow job is missing: {key}")
    if next_key is None:
        return workflow[start.start():]
    end_pattern = re.compile(rf"(?m)^  {re.escape(next_key)}:\s*$")
    end = end_pattern.search(workflow, start.end())
    if not end:
        fail(f"workflow job boundary is missing: {next_key}")
    return workflow[start.start():end.start()]


def require_pipeline_entrypoint(block: str, command: str, label: str) -> None:
    require(command in block, f"{label} must invoke the governed Signal Field pipeline")
    require(block.count(command) == 1, f"{label} must invoke the Signal Field pipeline exactly once")
    for marker in DIRECT_PIPELINE_STAGE_MARKERS:
        require(marker not in block, f"{label} must not duplicate pipeline stage ordering in workflow YAML: {marker}")


def validate_quality(text: str) -> None:
    require("name: Profile quality" in text, "Profile quality workflow name changed")
    require('PYTHON_VERSION: "3.13"' in text, "Profile quality Python version is not explicit")
    require(text.count("runs-on: ubuntu-24.04") == 2, "Both Profile Quality jobs must pin ubuntu-24.04")
    require(text.count(f"actions/checkout@{CHECKOUT_SHA}") == 2, "Both Profile Quality jobs must use the reviewed checkout SHA")
    require(text.count(f"actions/setup-python@{SETUP_PYTHON_SHA}") == 2, "Both Profile Quality jobs must use the reviewed setup-python SHA")
    require("cancel-in-progress: true" in text, "Profile Quality must cancel stale runs")
    require('- ".github/REFRESH_CADENCE.md"' in text, "Profile Quality push paths must cover refresh-cadence governance")

    validate = job_block(text, "validate", "integration")
    integration = job_block(text, "integration", None)
    require("name: validate-contracts" in validate, "Required contract-check job name changed")
    require("name: integration-pinned-upstream" in integration, "Required integration-check job name changed")
    require("permissions:\n      contents: read" in validate, "Contract-check job must remain read-only")
    require("permissions:\n      contents: read" in integration, "Integration job must remain read-only")
    require("contents: write" not in integration, "Profile Quality integration must not receive repository write authority")
    require(f"shinpr/github-profile-stats@{UPSTREAM_SHA}" in integration, "PR integration must execute reviewed pinned upstream generator")
    require("python3 scripts/signal_field_pipeline.py --self-test" in validate, "Profile Quality must self-test the governed Signal Field pipeline")
    require_pipeline_entrypoint(integration, 'python3 scripts/signal_field_pipeline.py "$READY_DIR"', "PR integration")
    require(integration.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 1, "PR integration must exercise the reviewed download-artifact SHA exactly once")
    require(integration.count("digest-mismatch: error") == 1, "PR artifact round-trip must fail on digest mismatch")
    require("python3 scripts/validate-generated-signal-field.py roundtrip-signal-field" in integration, "PR integration must revalidate downloaded Signal Field bytes")
    require("python3 scripts/validate-profile-cache-contract.py" in validate, "Profile Quality must validate generated-surface cache identities")
    require(
        "name: Bind generated cache identities to live candidate contracts" in integration,
        "Profile Quality integration must bind mutable cache identities to the live candidate contracts",
    )
    require("--signal-field-dir \"$SIGNAL_FIELD_DIR\"" in integration, "Cache binding must consume the live Signal Field candidate")
    require("--spotlight-dir integration-engineering-spotlight" in integration, "Cache binding must consume the live Spotlight candidate")
    require("--ledger-dir integration-portfolio-evidence" in integration, "Cache binding must consume the live Portfolio Ledger candidate")
    require("python3 scripts/validate-action-release-provenance.py" in validate, "Profile Quality must execute action release provenance verification")
    require("python3 scripts/validate-dependency-review-contract.py" in validate, "Profile Quality must execute Dependency Review governance validator")
    require("python3 scripts/validate-workflow-authority-contract.py" in validate, "Profile Quality must execute workflow authority firewall")
    require("python3 scripts/validate-workflow-shell-safety.py" in validate, "Profile Quality must execute workflow shell-safety validator")
    require("python3 scripts/validate-governance-contract.py" in validate, "Profile Quality must execute this governance validator")
    require("python3 scripts/validate-profile-attestation-contract.py" in validate, "Profile Quality must execute engineering-attestation validator")
    require(
        "python3 scripts/write-profile-contract-summary.py --self-test" in validate,
        "Profile Quality must self-test the read-only contract summary renderer",
    )
    require(
        "python3 scripts/write-profile-contract-summary.py" in integration,
        "Profile Quality integration must publish the read-only contract summary",
    )
    require("SIGNAL_FIELD_DIR:" in integration, "Contract summary must bind the live Signal Field candidate")
    require("SPOTLIGHT_DIR: integration-engineering-spotlight" in integration, "Contract summary must bind live Spotlight evidence")
    require("PORTFOLIO_LEDGER_DIR: integration-portfolio-evidence" in integration, "Contract summary must bind the live Portfolio Ledger")


def validate_stats(text: str) -> None:
    require("name: Update profile stats" in text, "Profile stats workflow name changed")
    require('cron: "17 * * * *"' in text, "Hourly best-effort refresh contract changed")
    require('cron: "17,47 * * * *"' not in text, "Stale twice-hourly cron remains in production workflow")
    require('cron: "2-57/5 * * * *"' not in text, "Stale five-minute cron remains in production workflow")
    require('- "scripts/set-signal-field-refresh-cadence.py"' in text, "Stats push paths must cover refresh-cadence finalizer changes")
    require('- "scripts/signal_field_pipeline.py"' in text, "Stats push paths must cover the Signal Field orchestrator")
    require('- "scripts/signal-field-pipeline-v1.json"' in text, "Stats push paths must cover the Signal Field stage manifest")
    require("cancel-in-progress: true" in text, "Stats workflow must cancel stale runs")
    require('PYTHON_VERSION: "3.13"' in text, "Stats Python version is not explicit")
    require(text.count("runs-on: ubuntu-24.04") == 3, "All three stats jobs must pin ubuntu-24.04")

    generate = job_block(text, "generate", "attest")
    attest = job_block(text, "attest", "publish")
    publish = job_block(text, "publish", None)

    require("name: generate-read-only" in generate, "Read-only generation job name changed")
    require("name: attest-validated-evidence" in attest, "Attestation job name changed")
    require("name: publish-write-only" in publish, "Write-only publication job name changed")

    require("permissions:\n      contents: read" in generate, "Third-party generation job must remain contents: read")
    require("contents: write" not in generate, "Third-party generation job received repository write authority")
    require("id-token: write" not in generate, "Third-party generation job received signing identity authority")
    require("attestations: write" not in generate, "Third-party generation job received attestation authority")
    require_pipeline_entrypoint(generate, 'python3 source/scripts/signal_field_pipeline.py "$READY_DIR"', "Production generation")

    require("needs: generate" in attest, "Attestation job must depend on validated generation")
    require("contents: read" in attest, "Attestation job must retain contents: read")
    require("id-token: write" in attest, "Attestation job must receive OIDC authority")
    require("attestations: write" in attest, "Attestation job must receive attestation authority")
    require("contents: write" not in attest, "Attestation job must not receive repository-content write authority")
    require(f"actions/attest@{ATTEST_SHA}" in attest, "Pinned actions/attest SHA changed")
    require("python3 source/scripts/validate-signal-field-v214.py profile-stats/profile" in attest, "Attestation boundary must validate Signal Field Evidence ID")
    require("python3 source/scripts/build-profile-evidence-attestation.py profile-stats/profile portfolio-evidence attestation-predicate.json" in attest, "Attestation predicate must bind Signal Field and Portfolio Ledger identities")

    require("permissions:\n      contents: write" in publish, "Only publication job may receive contents: write")
    require("needs: [generate, attest]" in publish, "Publication must depend on both generation and attestation")
    require("id-token: write" not in publish, "Publication job must not receive signing identity authority")
    require("attestations: write" not in publish, "Publication job must not receive attestation authority")
    require("python3 source/scripts/validate-signal-field-v214.py publish-input" in publish, "Publish boundary must validate Signal Field Evidence ID")
    require("python3 source/scripts/validate-signal-field-v214.py artifacts/profile-stats/profile" in publish, "Staged generated branch must validate Signal Field Evidence ID")

    require(f"shinpr/github-profile-stats@{UPSTREAM_SHA}" in generate, "Pinned upstream generator SHA changed")
    require(generate.count(f"actions/upload-artifact@{UPLOAD_SHA}") == 3, "Generation must upload exactly three immutable evidence sets")
    require(attest.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 3, "Attestation must download all three immutable evidence sets")
    require(publish.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 3, "Publication must download all three immutable evidence sets")
    require(attest.count("digest-mismatch: error") == 3, "Attestation downloads must fail closed on all artifact digest mismatches")
    require(publish.count("digest-mismatch: error") == 3, "Publication downloads must fail closed on all artifact digest mismatches")
    require(text.count(f"actions/checkout@{CHECKOUT_SHA}") == 5, "Stats workflow must retain five reviewed checkout calls")
    require(text.count(f"actions/setup-python@{SETUP_PYTHON_SHA}") == 3, "Stats setup-python action SHA changed")
    require(generate.count("persist-credentials: false") == 1, "Generation checkout must not persist credentials")
    require(attest.count("persist-credentials: false") == 2, "Attestation source/generated checkouts must not persist credentials")
    require(publish.count("persist-credentials: false") == 1, "Publish trusted-source checkout must not persist credentials")
    require("python3 source/scripts/validate-generated-signal-field.py profile-stats/profile" in attest, "Attestation boundary must revalidate Signal Field artifacts")
    require("python3 source/scripts/validate-engineering-spotlight.py engineering-spotlight --require-live" in attest, "Attestation boundary must revalidate Engineering Spotlight")
    require("python3 source/scripts/validate-portfolio-evidence-ledger.py portfolio-evidence --require-live" in attest, "Attestation boundary must revalidate Portfolio Evidence Ledger")
    require("python3 source/scripts/validate-generated-signal-field.py publish-input" in publish, "Publish boundary must revalidate downloaded artifacts")
    require("python3 source/scripts/validate-portfolio-evidence-ledger.py portfolio-ledger-publish-input --require-live" in publish, "Publish boundary must revalidate Portfolio Evidence Ledger")
    require("find artifacts -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +" in publish, "Generated branch must be staged as artifact-only")
    require("git -C artifacts push origin HEAD:generated" in publish, "Publisher must target only generated branch")


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
        "id-token: write",
        "attestations: write",
        "not certify every software behavior",
    ):
        require(phrase in text, f"Governance documentation is missing: {phrase}")


def validate_cadence_doc(text: str) -> None:
    for phrase in (
        "profile-refresh-v2",
        "17 * * * *",
        "2-57/5 * * * *",
        "best-effort hourly generation refresh",
        "4h32m",
        "3h40m",
        "3h28m",
        "2h47m",
        'data-generation-schedule="1-hour"',
        'data-generation-cadence-contract="profile-refresh-v2"',
        'data-current-day-highlight="phosphorescent-red-v1"',
        "REFRESH · 1 HR",
        "Generation refresh cadence and evidence freshness are different claims",
        "push-triggered",
        "workflow_dispatch",
    ):
        require(phrase in text, f"Refresh-cadence documentation is missing: {phrase}")


def main() -> int:
    try:
        for path in (QUALITY, STATS, GOVERNANCE, CADENCE, PIPELINE, PIPELINE_MANIFEST):
            require(path.is_file(), f"governance input is missing: {path.relative_to(ROOT)}")
        validate_quality(QUALITY.read_text(encoding="utf-8"))
        validate_stats(STATS.read_text(encoding="utf-8"))
        validate_governance_doc(GOVERNANCE.read_text(encoding="utf-8"))
        validate_cadence_doc(CADENCE.read_text(encoding="utf-8"))
        print(
            "Repository governance validation passed: PR checks are stable/read-only, action release provenance is mandatory, "
            "Dependency Review governance is mandatory, workflow authority is closed, workflow shell source is expression-safe, "
            "pinned-upstream integration and the single versioned Signal Field pipeline are mandatory, mutable profile cache identities "
            "bind to the same live candidate contracts, measured profile generation uses the governed best-effort hourly refresh, "
            "three artifact downloads are integrity-checked, Signal Field and Portfolio Ledger identities are validated before signing, "
            "third-party generation has neither write nor signing authority, attestation is isolated, and publication revalidates the same identities."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
