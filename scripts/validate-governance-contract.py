#!/usr/bin/env python3
"""Validate repository governance encoded in version-controlled workflows.

GitHub repository rulesets are settings-level controls and are not writable from every
integration. This validator therefore protects the executable half of the governance
contract: named PR checks, explicit runtime, pinned dependencies, least-privilege
profile evidence generation/attestation/publication, fresh-run concurrency, and
artifact-only publish behavior. The companion .github/GOVERNANCE.md records the
settings-level controls that must mirror these checks in GitHub.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
QUALITY = ROOT / ".github/workflows/profile-quality.yml"
STATS = ROOT / ".github/workflows/profile-stats.yml"
GOVERNANCE = ROOT / ".github/GOVERNANCE.md"

CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "ece7cb06caefa5fff74198d8649806c4678c61a1"
UPLOAD_SHA = "ea165f8d65b6e75b540449e92b4886f43607fa02"
DOWNLOAD_SHA = "634f93cb2916e3fdff6788551b99b062d0335ce0"
UPSTREAM_SHA = "49b5f7091182a45f3ef93923505b660c6da5f835"
ATTEST_SHA = "1e69f48acb82d1966a394da916b4c1698aa569d6"


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


def validate_quality(text: str) -> None:
    require("name: Profile quality" in text, "Profile quality workflow name changed")
    require('PYTHON_VERSION: "3.13"' in text, "Profile quality Python version is not explicit")
    require(text.count("runs-on: ubuntu-24.04") == 2, "Both Profile Quality jobs must pin ubuntu-24.04")
    require(text.count(f"actions/checkout@{CHECKOUT_SHA}") == 2, "Both Profile Quality jobs must use the reviewed checkout SHA")
    require(text.count(f"actions/setup-python@{SETUP_PYTHON_SHA}") == 2, "Both Profile Quality jobs must use the reviewed setup-python SHA")
    require("cancel-in-progress: true" in text, "Profile Quality must cancel stale runs")

    validate = job_block(text, "validate", "integration")
    integration = job_block(text, "integration", None)
    require("name: validate-contracts" in validate, "Required contract-check job name changed")
    require("name: integration-pinned-upstream" in integration, "Required integration-check job name changed")
    require("permissions:\n      contents: read" in validate, "Contract-check job must remain read-only")
    require("permissions:\n      contents: read" in integration, "Integration job must remain read-only")
    require(
        f"shinpr/github-profile-stats@{UPSTREAM_SHA}" in integration,
        "PR integration must execute the reviewed pinned upstream generator",
    )
    require(
        "python3 scripts/validate-generated-signal-field.py \"$READY_DIR\"" in integration,
        "PR integration must validate the complete publishable artifact",
    )
    require(
        "python3 scripts/validate-governance-contract.py" in validate,
        "Profile Quality must execute this governance validator",
    )
    require(
        "python3 scripts/validate-profile-attestation-contract.py" in validate,
        "Profile Quality must execute the engineering-attestation validator",
    )


def validate_stats(text: str) -> None:
    require("name: Update profile stats" in text, "Profile stats workflow name changed")
    require('cron: "2-57/5 * * * *"' in text, "Five-minute schedule offset contract changed")
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

    require("needs: generate" in attest, "Attestation job must depend on validated generation")
    require("contents: read" in attest, "Attestation job must retain contents: read")
    require("id-token: write" in attest, "Attestation job must receive OIDC authority")
    require("attestations: write" in attest, "Attestation job must receive attestation authority")
    require("contents: write" not in attest, "Attestation job must not receive repository-content write authority")
    require(f"actions/attest@{ATTEST_SHA}" in attest, "Pinned actions/attest SHA changed")

    require("permissions:\n      contents: write" in publish, "Only publication job may receive contents: write")
    require("needs: [generate, attest]" in publish, "Publication must depend on both generation and attestation")
    require("id-token: write" not in publish, "Publication job must not receive signing identity authority")
    require("attestations: write" not in publish, "Publication job must not receive attestation authority")

    require(f"shinpr/github-profile-stats@{UPSTREAM_SHA}" in generate, "Pinned upstream generator SHA changed")
    require(generate.count(f"actions/upload-artifact@{UPLOAD_SHA}") == 2, "Generation must upload exactly two immutable evidence sets")
    require(attest.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 2, "Attestation must download both immutable evidence sets")
    require(publish.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 2, "Publication must download both immutable evidence sets")
    require(
        text.count(f"actions/checkout@{CHECKOUT_SHA}") == 5,
        "Stats workflow must retain five reviewed checkout calls across generation, attestation, and publication",
    )
    require(text.count(f"actions/setup-python@{SETUP_PYTHON_SHA}") == 3, "Stats setup-python action SHA changed")
    require(generate.count("persist-credentials: false") == 1, "Generation checkout must not persist credentials")
    require(attest.count("persist-credentials: false") == 2, "Attestation source/generated checkouts must not persist credentials")
    require(
        publish.count("persist-credentials: false") == 1,
        "Publish trusted-source checkout must not persist credentials; generated-branch checkout alone retains push credentials",
    )
    require(
        "python3 source/scripts/validate-generated-signal-field.py profile-stats/profile" in attest,
        "Attestation boundary must revalidate Signal Field artifacts",
    )
    require(
        "python3 source/scripts/validate-engineering-spotlight.py engineering-spotlight --require-live" in attest,
        "Attestation boundary must revalidate Engineering Spotlight artifacts",
    )
    require(
        "python3 source/scripts/validate-generated-signal-field.py publish-input" in publish,
        "Publish boundary must revalidate downloaded artifacts",
    )
    require(
        "find artifacts -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +" in publish,
        "Generated branch must be staged as artifact-only",
    )
    require("git -C artifacts push origin HEAD:generated" in publish, "Publisher must target only the generated branch")


def validate_governance_doc(text: str) -> None:
    for phrase in (
        "Profile quality / validate-contracts",
        "Profile quality / integration-pinned-upstream",
        "Protect Main",
        "generated",
        "deletion",
        "non-fast-forward",
        "GitHub Actions",
        "attest-validated-evidence",
        "id-token: write",
        "attestations: write",
        "not certify every software behavior",
    ):
        require(phrase in text, f"Governance documentation is missing: {phrase}")


def main() -> int:
    try:
        for path in (QUALITY, STATS, GOVERNANCE):
            require(path.is_file(), f"governance input is missing: {path.relative_to(ROOT)}")
        validate_quality(QUALITY.read_text(encoding="utf-8"))
        validate_stats(STATS.read_text(encoding="utf-8"))
        validate_governance_doc(GOVERNANCE.read_text(encoding="utf-8"))
        print(
            "Repository governance validation passed: PR checks are stable/read-only, pinned-upstream "
            "integration is mandatory, third-party generation has neither write nor signing authority, "
            "attestation is isolated, publication depends on attestation and revalidation, and settings-level "
            "protection intent is documented."
        )
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
