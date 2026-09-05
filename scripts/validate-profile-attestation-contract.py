#!/usr/bin/env python3
"""Validate immutable profile-evidence attestation schema/version contracts."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
STATS = ROOT / ".github/workflows/profile-stats.yml"
LEGACY_SCHEMA = ROOT / ".github/attestation/profile-evidence-v1.schema.json"
CURRENT_SCHEMA = ROOT / ".github/attestation/profile-evidence-v2.schema.json"
DOC = ROOT / ".github/ATTESTATION.md"
BUILDER = ROOT / "scripts/build-profile-evidence-attestation.py"

LEGACY_V1_GIT_BLOB_SHA = "075fc17c817fe689702bc96c9875a0eb0a934375"
ATTEST_SHA = "1e69f48acb82d1966a394da916b4c1698aa569d6"  # actions/attest v4.2.2
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "5fda3b95a4ea91299a34e894583c3862153e4b97"
DOWNLOAD_SHA = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
UPLOAD_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
LEGACY_PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "profile-evidence-v1.schema.json"
)
PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "profile-evidence-v2.schema.json"
)
PUBLISHED_PATHS = [
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
]
SIGNAL_VALIDATORS = [
    "scripts/validate-signal-field-v213.py",
    "scripts/validate-signal-field-v214.py",
    "scripts/validate-generated-signal-field.py",
]
SPOTLIGHT_VALIDATORS = ["scripts/validate-engineering-spotlight.py --require-live"]
LEDGER_VALIDATORS = ["scripts/validate-portfolio-evidence-ledger.py --require-live"]
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


def git_blob_sha(path: Path) -> str:
    payload = path.read_bytes()
    header = f"blob {len(payload)}\0".encode("ascii")
    return hashlib.sha1(header + payload).hexdigest()


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


def validate_legacy_v1_frozen() -> None:
    require(LEGACY_SCHEMA.is_file(), "legacy v1 predicate schema is missing")
    require(
        git_blob_sha(LEGACY_SCHEMA) == LEGACY_V1_GIT_BLOB_SHA,
        "legacy profile-evidence-v1 schema bytes changed; published schema versions are immutable",
    )
    schema = json.loads(LEGACY_SCHEMA.read_text(encoding="utf-8"))
    require(schema.get("$id") == LEGACY_PREDICATE_TYPE, "legacy v1 predicate schema id changed")
    require(schema.get("properties", {}).get("schemaVersion", {}).get("const") == 1, "legacy v1 schema version changed")


def validate_current_schema() -> None:
    schema = json.loads(CURRENT_SCHEMA.read_text(encoding="utf-8"))
    require(schema.get("$id") == PREDICATE_TYPE, "attestation predicate v2 schema id changed")
    require(schema.get("additionalProperties") is False, "predicate v2 schema must fail closed")
    required = schema.get("required", [])
    for key in ("predicateSchema", "subjectSet", "signalFieldEvidence", "portfolioEvidenceLedger", "validation", "authority"):
        require(key in required, f"predicate v2 must require {key}")
    properties = schema.get("properties")
    require(isinstance(properties, dict), "predicate v2 schema properties are missing")
    require(properties.get("schemaVersion", {}).get("const") == 2, "current schema version must be 2")
    require(properties.get("kind", {}).get("const") == "profile-evidence-attestation", "predicate kind changed")

    schema_identity = properties.get("predicateSchema", {})
    schema_identity_props = schema_identity.get("properties", {}) if isinstance(schema_identity, dict) else {}
    require(schema_identity.get("additionalProperties") is False, "predicateSchema block must fail closed")
    require(schema_identity_props.get("id", {}).get("const") == PREDICATE_TYPE, "predicateSchema id must bind v2")
    require(
        schema_identity_props.get("digest", {}).get("pattern") == "^sha256:[0-9a-f]{64}$",
        "predicateSchema digest format changed",
    )

    subject = properties.get("subjectSet", {}).get("properties", {}).get("publishedPaths", {})
    require(subject.get("const") == PUBLISHED_PATHS, "v2 published subject paths must be an exact constant array")

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

    validation = properties.get("validation", {}).get("properties", {})
    require(validation.get("signalField", {}).get("const") == SIGNAL_VALIDATORS, "Signal Field validator set must be exact")
    require(validation.get("engineeringSpotlight", {}).get("const") == SPOTLIGHT_VALIDATORS, "Spotlight validator set must be exact")
    require(validation.get("portfolioEvidenceLedger", {}).get("const") == LEDGER_VALIDATORS, "Ledger validator set must be exact")
    require(validation.get("boundary", {}).get("const") == "attest-validated-evidence", "validation boundary changed")

    authority = properties.get("authority", {}).get("properties", {})
    require(authority.get("generation", {}).get("const") == "contents:read", "generation authority changed")
    require(
        authority.get("attestation", {}).get("const") == "contents:read,id-token:write,attestations:write",
        "attestation authority changed",
    )
    require(authority.get("publication", {}).get("const") == "contents:write", "publication authority changed")
    require(isinstance(authority.get("separation", {}).get("const"), str), "authority separation must be an exact constant")

    claim = properties.get("claim", {}).get("const")
    require(isinstance(claim, str) and "not universal certification" in claim, "predicate must preserve the non-certification claim boundary")


def validate_builder() -> None:
    text = BUILDER.read_text(encoding="utf-8")
    for phrase in (
        'SCHEMA_VERSION = 2',
        "profile-evidence-v2.schema.json",
        'PREDICATE_SCHEMA = ROOT / ".github/attestation/profile-evidence-v2.schema.json"',
        '"predicateSchema": predicate_schema_identity()',
        "hashlib.sha256(PREDICATE_SCHEMA.read_bytes()).hexdigest()",
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
        require(phrase in text, f"attestation predicate v2 builder contract is missing: {phrase}")
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
    require(attest.count(f"actions/checkout@{CHECKOUT_SHA}") == 2, "attestation must use reviewed checkout SHA for source and current generated evidence")
    require(attest.count(f"actions/setup-python@{SETUP_PYTHON_SHA}") == 1, "attestation setup-python SHA changed")
    require(attest.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 3, "attestation must download three immutable evidence sets")
    require(attest.count("digest-mismatch: error") == 3, "attestation artifact downloads must fail closed on digest mismatch")
    require(publish.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 3, "publication must download three immutable evidence sets")
    require(publish.count("digest-mismatch: error") == 3, "publication artifact downloads must fail closed on digest mismatch")

    for command in (
        "python3 source/scripts/validate-signal-field-v213.py profile-stats/profile",
        "python3 source/scripts/validate-signal-field-v214.py profile-stats/profile",
        "python3 source/scripts/validate-generated-signal-field.py profile-stats/profile",
        "python3 source/scripts/validate-engineering-spotlight.py engineering-spotlight --require-live",
        "python3 source/scripts/validate-portfolio-evidence-ledger.py portfolio-evidence --require-live",
        "python3 source/scripts/build-profile-evidence-attestation.py profile-stats/profile portfolio-evidence attestation-predicate.json",
    ):
        require(command in attest, f"attestation boundary command is missing: {command}")

    require(f"uses: actions/attest@{ATTEST_SHA} # v4.2.2" in attest, "actions/attest pin changed")
    for path in SUBJECT_PATHS:
        require(path in attest, f"attestation subject path is missing: {path}")
    require(f"predicate-type: {PREDICATE_TYPE}" in attest, "production must issue current v2 predicate type")
    require(LEGACY_PREDICATE_TYPE not in attest, "production workflow must not issue mutable legacy v1 predicates")
    require("predicate-path: attestation-predicate.json" in attest, "custom predicate path changed")

    require("cp spotlight-publish-input/spotlight-*.svg artifacts/engineering-spotlight/" in publish, "publication must stage only six attested Spotlight SVGs")
    require('test ! -e artifacts/engineering-spotlight/spotlight-manifest.json' in publish, "internal Spotlight manifest must not reach generated")
    require("find artifacts/profile-stats/profile artifacts/engineering-spotlight artifacts/portfolio-evidence -type f | wc -l" in publish, "publication must enforce exact eleven-file public subject set")


def validate_doc() -> None:
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "profile-evidence-v2.schema.json",
        "profile-evidence-v1.schema.json",
        "frozen",
        "predicateSchema.digest",
        "generate-read-only",
        "attest-validated-evidence",
        "publish-write-only",
        "Signal Field Evidence ID",
        "Portfolio Evidence Ledger",
        "13 reviewed systems",
        "spotlight-manifest.json",
        "exactly the same eleven subjects",
        "not universal certification",
        "gh attestation verify",
    ):
        require(phrase in text, f"attestation documentation is missing: {phrase}")


def main() -> int:
    try:
        for path in (STATS, LEGACY_SCHEMA, CURRENT_SCHEMA, DOC, BUILDER):
            require(path.is_file(), f"attestation contract input is missing: {path.relative_to(ROOT)}")
        validate_legacy_v1_frozen()
        validate_current_schema()
        validate_builder()
        validate_workflow()
        validate_doc()
        print(
            "Engineering attestation validation passed: legacy v1 bytes are frozen, current v2 binds its schema digest and exact subject/validator sets, "
            "generation has no signing/write authority, publication matches the eleven attested subjects, and the claim remains provenance/contract conformance rather than certification."
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
