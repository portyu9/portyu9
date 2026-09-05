#!/usr/bin/env python3
"""Validate the generated profile-evidence attestation contract."""
from __future__ import annotations

import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
STATS = ROOT / ".github/workflows/profile-stats.yml"
SCHEMA = ROOT / ".github/attestation/profile-evidence-v1.schema.json"
DOC = ROOT / ".github/ATTESTATION.md"
BUILDER = ROOT / "scripts/build-profile-evidence-attestation.py"

ATTEST_SHA = "1e69f48acb82d1966a394da916b4c1698aa569d6"  # actions/attest v4.2.2
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "5fda3b95a4ea91299a34e894583c3862153e4b97"
DOWNLOAD_SHA = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
UPLOAD_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "profile-evidence-v1.schema.json"
)
SUBJECT_PATHS = (
    "profile-stats/profile/signal-field-*.svg",
    "engineering-spotlight/*.svg",
    "portfolio-evidence/portfolio-evidence-ledger.json",
)


def fail(message: str) -> None:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def job_block(workflow: str, key: str, next_key: str | None) -> str:
    start = re.search(rf"(?m)^  {re.escape(key)}:\s*$", workflow)
    if not start:
        fail(f"workflow job is missing: {key}")
    if next_key is None:
        return workflow[start.start():]
    end = re.search(rf"(?m)^  {re.escape(next_key)}:\s*$", workflow[start.end():])
    if not end:
        fail(f"workflow job boundary is missing: {next_key}")
    return workflow[start.start(): start.end() + end.start()]


def validate_schema() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    require(schema.get("$id") == PREDICATE_TYPE, "attestation predicate schema id changed")
    require(schema.get("additionalProperties") is False, "predicate schema must fail closed")
    required = schema.get("required", [])
    require("signalFieldEvidence" in required, "predicate must require Signal Field Evidence ID")
    require("portfolioEvidenceLedger" in required, "predicate must require Portfolio Evidence Ledger identity")
    properties = schema.get("properties")
    require(isinstance(properties, dict), "predicate schema properties are missing")
    require(properties.get("schemaVersion", {}).get("const") == 1, "schema version changed")
    require(
        properties.get("kind", {}).get("const") == "profile-evidence-attestation",
        "predicate kind changed",
    )
    evidence = properties.get("signalFieldEvidence", {})
    evidence_props = evidence.get("properties", {}) if isinstance(evidence, dict) else {}
    require(evidence.get("additionalProperties") is False, "Signal Field evidence block must fail closed")
    require(evidence_props.get("schema", {}).get("const") == "signal-field-evidence-v1", "Evidence ID schema changed")
    require(evidence_props.get("id", {}).get("pattern") == "^SF1-[0-9A-F]{16}$", "Evidence ID format changed")
    require(evidence_props.get("digest", {}).get("pattern") == "^sha256:[0-9a-f]{64}$", "Evidence digest format changed")

    portfolio = properties.get("portfolioEvidenceLedger", {})
    portfolio_props = portfolio.get("properties", {}) if isinstance(portfolio, dict) else {}
    require(portfolio.get("additionalProperties") is False, "Portfolio Evidence Ledger block must fail closed")
    require(portfolio_props.get("version", {}).get("const") == "portfolio-evidence-ledger-v1", "Portfolio Ledger version changed")
    require(portfolio_props.get("id", {}).get("pattern") == "^PL1-[0-9A-F]{16}$", "Portfolio Ledger ID format changed")
    require(portfolio_props.get("digest", {}).get("pattern") == "^sha256:[0-9a-f]{64}$", "Portfolio Ledger digest format changed")
    require(portfolio_props.get("systemCount", {}).get("const") == 13, "Portfolio Ledger system count changed")

    validation = properties.get("validation", {})
    require("portfolioEvidenceLedger" in validation.get("required", []), "Portfolio Ledger validator must be required")
    ledger_validation = validation.get("properties", {}).get("portfolioEvidenceLedger", {})
    require(ledger_validation.get("minItems") == 1, "Portfolio Ledger validator set must not be empty")

    claim = properties.get("claim", {}).get("const")
    require(
        isinstance(claim, str) and "not universal certification" in claim,
        "predicate must preserve the non-certification claim boundary",
    )
    subject = properties.get("subjectSet", {}).get("properties", {}).get("publishedPaths", {})
    require(subject.get("minItems") == 11 and subject.get("maxItems") == 11, "subject set must remain exactly eleven subjects")


def validate_builder() -> None:
    text = BUILDER.read_text(encoding="utf-8")
    for phrase in (
        'REPOSITORY = "portyu9/portyu9"',
        'KIND = "profile-evidence-attestation"',
        'BOUNDARY = "attest-validated-evidence"',
        'EVIDENCE_SCHEMA = "signal-field-evidence-v1"',
        'PORTFOLIO_LEDGER_VERSION = "portfolio-evidence-ledger-v1"',
        "scripts/validate-signal-field-v213.py",
        "scripts/validate-signal-field-v214.py",
        "scripts/validate-generated-signal-field.py",
        "scripts/validate-engineering-spotlight.py --require-live",
        "scripts/validate-portfolio-evidence-ledger.py --require-live",
        '"signalFieldEvidence": read_signal_field_evidence(signal_field_dir)',
        '"portfolioEvidenceLedger": read_portfolio_ledger_evidence(portfolio_ledger_dir)',
        '"generation": "contents:read"',
        '"attestation": "contents:read,id-token:write,attestations:write"',
        '"publication": "contents:write"',
        "not universal certification",
    ):
        require(phrase in text, f"attestation predicate builder contract is missing: {phrase}")
    require(text.count("signal-field-") >= 4, "builder must enumerate the four Signal Field subjects")
    require(text.count("spotlight-") >= 6, "builder must enumerate the six Spotlight subjects")
    require(text.count("portfolio-evidence/portfolio-evidence-ledger.json") == 1, "builder must enumerate the Portfolio Evidence Ledger subject exactly once")


def validate_workflow() -> None:
    text = STATS.read_text(encoding="utf-8")
    generate = job_block(text, "generate", "attest")
    attest = job_block(text, "attest", "publish")
    publish = job_block(text, "publish", None)

    require("name: generate-read-only" in generate, "generation job name changed")
    require("name: attest-validated-evidence" in attest, "attestation job name changed")
    require("name: publish-write-only" in publish, "publication job name changed")
    require("contents: write" not in generate, "generation job must not receive repository write authority")
    require("attestations: write" not in generate, "generation job must not receive attestation authority")
    require("id-token: write" not in generate, "generation job must not receive OIDC signing authority")

    require("needs: generate" in attest, "attestation must depend on generation")
    require("contents: read" in attest, "attestation job must receive contents: read")
    require("id-token: write" in attest, "attestation job must receive OIDC signing authority")
    require("attestations: write" in attest, "attestation job must receive attestation write authority")
    require("contents: write" not in attest, "attestation job must not receive repository-content write authority")

    require("needs: [generate, attest]" in publish, "publication must depend on both generation and attestation")
    require("attestations: write" not in publish, "publication job must not create attestations")
    require("id-token: write" not in publish, "publication job must not receive OIDC signing authority")
    require("permissions:\n      contents: write" in publish, "publication job must retain only contents write authority")

    require(generate.count(f"actions/upload-artifact@{UPLOAD_SHA}") == 3, "generation must upload exactly three immutable evidence sets")
    require("name: portfolio-evidence-ledger" in generate, "generation must upload the Portfolio Evidence Ledger artifact")
    require("python3 source/scripts/generate-portfolio-evidence-ledger.py portfolio-ledger-ready" in generate, "generation must build the Portfolio Evidence Ledger")
    require("python3 source/scripts/validate-portfolio-evidence-ledger.py portfolio-ledger-ready --require-live" in generate, "generation must validate the live Portfolio Evidence Ledger")

    require(attest.count(f"actions/checkout@{CHECKOUT_SHA}") == 2, "attestation must use reviewed checkout SHA for source and current generated evidence")
    require(attest.count(f"actions/setup-python@{SETUP_PYTHON_SHA}") == 1, "attestation setup-python SHA changed")
    require(attest.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 3, "attestation must download three immutable evidence sets")
    require(attest.count("digest-mismatch: error") == 3, "attestation artifact downloads must fail closed on digest mismatch")
    require(publish.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 3, "publication must download three immutable evidence sets")
    require(publish.count("digest-mismatch: error") == 3, "publication artifact downloads must fail closed on digest mismatch")
    require(attest.count("persist-credentials: false") == 2, "attestation checkouts must not persist credentials")
    require("ref: generated" in attest and "path: published" in attest, "attestation must compare against current generated evidence")
    require("github.event_name != 'schedule' || steps.delta.outputs.changed == 'true'" in attest, "scheduled attestation deduplication guard changed")
    require("diff -qr portfolio-evidence published/portfolio-evidence" in attest, "scheduled delta check must include the Portfolio Evidence Ledger")

    for command in (
        "python3 source/scripts/validate-signal-field-v213.py profile-stats/profile",
        "python3 source/scripts/validate-signal-field-v214.py profile-stats/profile",
        "python3 source/scripts/validate-generated-signal-field.py profile-stats/profile",
        "python3 source/scripts/validate-engineering-spotlight.py engineering-spotlight --require-live",
        "python3 source/scripts/validate-portfolio-evidence-ledger.py portfolio-evidence --require-live",
        "python3 source/scripts/build-profile-evidence-attestation.py profile-stats/profile portfolio-evidence attestation-predicate.json",
    ):
        require(command in attest, f"attestation boundary command is missing: {command}")

    for command in (
        "python3 source/scripts/validate-portfolio-evidence-ledger.py portfolio-ledger-publish-input --require-live",
        "cp portfolio-ledger-publish-input/portfolio-evidence-ledger.json artifacts/portfolio-evidence/",
        "python3 source/scripts/validate-portfolio-evidence-ledger.py artifacts/portfolio-evidence --require-live",
    ):
        require(command in publish, f"publication ledger boundary command is missing: {command}")

    require(
        f"uses: actions/attest@{ATTEST_SHA} # v4.2.2" in attest,
        "actions/attest must remain pinned to the reviewed v4.2.2 commit",
    )
    for path in SUBJECT_PATHS:
        require(path in attest, f"attestation subject path is missing: {path}")
    require(f"predicate-type: {PREDICATE_TYPE}" in attest, "custom predicate type changed")
    require("predicate-path: attestation-predicate.json" in attest, "custom predicate path changed")

    for source_path in (
        '"scripts/engineering_spotlight_v2.py"',
        '"scripts/engineering_spotlight_v21.py"',
        '"scripts/validate_engineering_spotlight_v2.py"',
        '"scripts/validate_engineering_spotlight_v21.py"',
        '"scripts/generate-portfolio-evidence-ledger.py"',
        '"scripts/validate-portfolio-evidence-ledger.py"',
    ):
        require(source_path in text, f"profile-stats push paths must cover production evidence source: {source_path}")


def validate_doc() -> None:
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "generate-read-only",
        "attest-validated-evidence",
        "publish-write-only",
        "Sigstore",
        "third-party Signal Field generator",
        "Signal Field Evidence ID",
        "signal-field-evidence-v1",
        "Portfolio Evidence Ledger",
        "PL1-",
        "portfolio-evidence/portfolio-evidence-ledger.json",
        "13 reviewed systems",
        "not universal certification",
        "gh attestation verify",
        PREDICATE_TYPE,
    ):
        require(phrase in text, f"attestation documentation is missing: {phrase}")


def main() -> int:
    try:
        for path in (STATS, SCHEMA, DOC, BUILDER):
            require(path.is_file(), f"attestation contract input is missing: {path.relative_to(ROOT)}")
        validate_schema()
        validate_builder()
        validate_workflow()
        validate_doc()
        print(
            "Engineering attestation validation passed: generation has no signing/write authority, three immutable evidence sets fail closed on digest mismatch, "
            "Signal Field and Portfolio Ledger identities are bound into the signed predicate, publication depends on attestation/revalidation, "
            "and the claim remains provenance/contract conformance rather than certification."
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
