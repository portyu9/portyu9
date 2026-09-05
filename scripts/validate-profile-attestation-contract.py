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
V1_SCHEMA = ROOT / ".github/attestation/profile-evidence-v1.schema.json"
V2_SCHEMA = ROOT / ".github/attestation/profile-evidence-v2.schema.json"
CURRENT_SCHEMA = ROOT / ".github/attestation/profile-evidence-v3.schema.json"
DOC = ROOT / ".github/ATTESTATION.md"
BUILDER = ROOT / "scripts/build-profile-evidence-attestation.py"

V1_GIT_BLOB_SHA = "075fc17c817fe689702bc96c9875a0eb0a934375"
V2_GIT_BLOB_SHA = "66a1486e565b89759812ff00dd33edc44a64cfa6"
ATTEST_SHA = "1e69f48acb82d1966a394da916b4c1698aa569d6"  # actions/attest v4.2.2
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "5fda3b95a4ea91299a34e894583c3862153e4b97"
DOWNLOAD_SHA = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
UPLOAD_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
V1_PREDICATE_TYPE = "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v1.schema.json"
V2_PREDICATE_TYPE = "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v2.schema.json"
PREDICATE_TYPE = "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v3.schema.json"
EVIDENCE_SEMANTICS = "execution-result-subject-binding-freshness-v1"
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
    return hashlib.sha1(f"blob {len(payload)}\0".encode("ascii") + payload).hexdigest()


def job_block(workflow: str, key: str, next_key: str | None) -> str:
    start = re.search(rf"(?m)^  {re.escape(key)}:\s*$", workflow)
    if not start:
        fail(f"workflow job is missing: {key}")
    if next_key is None:
        return workflow[start.start():]
    relative = workflow[start.end():]
    end = re.search(rf"(?m)^  {re.escape(next_key)}:\s*$", relative)
    if not end:
        fail(f"workflow job boundary is missing: {next_key}")
    return workflow[start.start(): start.end() + end.start()]


def validate_frozen_schema(path: Path, blob_sha: str, predicate_type: str, version: int) -> None:
    require(path.is_file(), f"frozen predicate v{version} schema is missing")
    require(
        git_blob_sha(path) == blob_sha,
        f"published profile-evidence-v{version} schema bytes changed; published schema versions are immutable",
    )
    schema = json.loads(path.read_text(encoding="utf-8"))
    require(schema.get("$id") == predicate_type, f"frozen predicate v{version} schema id changed")
    require(schema.get("properties", {}).get("schemaVersion", {}).get("const") == version, f"frozen predicate v{version} schema version changed")


def validate_current_schema() -> None:
    schema = json.loads(CURRENT_SCHEMA.read_text(encoding="utf-8"))
    require(schema.get("$id") == PREDICATE_TYPE, "attestation predicate v3 schema id changed")
    require(schema.get("additionalProperties") is False, "predicate v3 schema must fail closed")
    required = schema.get("required", [])
    for key in ("predicateSchema", "subjectSet", "signalFieldEvidence", "portfolioEvidenceLedger", "validation", "authority"):
        require(key in required, f"predicate v3 must require {key}")
    properties = schema.get("properties")
    require(isinstance(properties, dict), "predicate v3 schema properties are missing")
    require(properties.get("schemaVersion", {}).get("const") == 3, "current schema version must be 3")
    require(properties.get("kind", {}).get("const") == "profile-evidence-attestation", "predicate kind changed")

    schema_identity = properties.get("predicateSchema", {})
    schema_identity_props = schema_identity.get("properties", {}) if isinstance(schema_identity, dict) else {}
    require(schema_identity.get("additionalProperties") is False, "predicateSchema block must fail closed")
    require(schema_identity_props.get("id", {}).get("const") == PREDICATE_TYPE, "predicateSchema id must bind v3")
    require(schema_identity_props.get("digest", {}).get("pattern") == "^sha256:[0-9a-f]{64}$", "predicateSchema digest format changed")

    subject = properties.get("subjectSet", {}).get("properties", {}).get("publishedPaths", {})
    require(subject.get("const") == PUBLISHED_PATHS, "v3 published subject paths must be the exact eleven-file array")

    signal = properties.get("signalFieldEvidence", {})
    signal_props = signal.get("properties", {}) if isinstance(signal, dict) else {}
    require(signal.get("additionalProperties") is False, "Signal Field evidence block must fail closed")
    require(signal_props.get("schema", {}).get("const") == "signal-field-evidence-v1", "Signal Field Evidence ID schema changed")
    require(signal_props.get("id", {}).get("pattern") == "^SF1-[0-9A-F]{16}$", "Signal Field Evidence ID format changed")

    portfolio = properties.get("portfolioEvidenceLedger", {})
    portfolio_props = portfolio.get("properties", {}) if isinstance(portfolio, dict) else {}
    require(portfolio.get("additionalProperties") is False, "Portfolio Evidence Ledger block must fail closed")
    require(portfolio_props.get("version", {}).get("const") == "portfolio-evidence-ledger-v2", "Portfolio Ledger v2 version binding changed")
    require(portfolio_props.get("semantics", {}).get("const") == EVIDENCE_SEMANTICS, "Portfolio evidence semantics binding changed")
    require(portfolio_props.get("id", {}).get("pattern") == "^PL2-[0-9A-F]{16}$", "Portfolio Ledger v2 ID format changed")
    require(portfolio_props.get("digest", {}).get("pattern") == "^sha256:[0-9a-f]{64}$", "Portfolio Ledger digest format changed")
    require(portfolio_props.get("systemCount", {}).get("const") == 13, "Portfolio Ledger system count changed")

    validation = properties.get("validation", {}).get("properties", {})
    require(validation.get("signalField", {}).get("const") == SIGNAL_VALIDATORS, "Signal Field validator set must be exact")
    require(validation.get("engineeringSpotlight", {}).get("const") == SPOTLIGHT_VALIDATORS, "Spotlight validator set must be exact")
    require(validation.get("portfolioEvidenceLedger", {}).get("const") == LEDGER_VALIDATORS, "Ledger validator set must be exact")
    require(validation.get("boundary", {}).get("const") == "attest-validated-evidence", "validation boundary changed")

    authority = properties.get("authority", {}).get("properties", {})
    require(authority.get("generation", {}).get("const") == "contents:read", "generation authority changed")
    require(authority.get("attestation", {}).get("const") == "contents:read,id-token:write,attestations:write", "attestation authority changed")
    require(authority.get("publication", {}).get("const") == "contents:write", "publication authority changed")
    claim = properties.get("claim", {}).get("const")
    require(isinstance(claim, str) and "not universal certification" in claim, "predicate must preserve the non-certification claim boundary")


def validate_builder() -> None:
    text = BUILDER.read_text(encoding="utf-8")
    for phrase in (
        "SCHEMA_VERSION = 3",
        "profile-evidence-v3.schema.json",
        'PORTFOLIO_LEDGER_VERSION = "portfolio-evidence-ledger-v2"',
        f'PORTFOLIO_EVIDENCE_SEMANTICS = "{EVIDENCE_SEMANTICS}"',
        'PORTFOLIO_EVIDENCE_ID = re.compile(r"^PL2-[0-9A-F]{16}$")',
        '"predicateSchema": predicate_schema_identity()',
        "hashlib.sha256(PREDICATE_SCHEMA.read_bytes()).hexdigest()",
        '"signalFieldEvidence": read_signal_field_evidence(signal_field_dir)',
        '"portfolioEvidenceLedger": read_portfolio_ledger_evidence(portfolio_ledger_dir)',
        '"generation": "contents:read"',
        '"attestation": "contents:read,id-token:write,attestations:write"',
        '"publication": "contents:write"',
        "not universal certification",
    ):
        require(phrase in text, f"attestation predicate v3 builder contract is missing: {phrase}")
    require(text.count("portfolio-evidence/portfolio-evidence-ledger.json") == 1, "builder must enumerate the Portfolio Ledger subject exactly once")


def validate_workflow() -> None:
    text = STATS.read_text(encoding="utf-8")
    generate = job_block(text, "generate", "attest")
    attest = job_block(text, "attest", "publish")
    publish = job_block(text, "publish", None)
    require("name: generate-read-only" in generate, "generation job name changed")
    require("contents: write" not in generate and "id-token: write" not in generate and "attestations: write" not in generate, "generation authority expanded")
    require("name: attest-validated-evidence" in attest, "attestation job name changed")
    require("contents: read" in attest and "id-token: write" in attest and "attestations: write" in attest, "attestation authority changed")
    require("contents: write" not in attest, "attestation job must not receive repository-content write authority")
    require("name: publish-write-only" in publish and "needs: [generate, attest]" in publish, "publication dependency changed")
    require("permissions:\n      contents: write" in publish and "id-token: write" not in publish and "attestations: write" not in publish, "publication authority changed")

    require(generate.count(f"actions/upload-artifact@{UPLOAD_SHA}") == 3, "generation must upload exactly three immutable evidence sets")
    require(attest.count(f"actions/checkout@{CHECKOUT_SHA}") == 2, "attestation checkout inventory changed")
    require(attest.count(f"actions/setup-python@{SETUP_PYTHON_SHA}") == 1, "attestation setup-python SHA changed")
    require(attest.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 3, "attestation must download three immutable evidence sets")
    require(attest.count("digest-mismatch: error") == 3, "attestation downloads must fail closed on digest mismatch")
    require(publish.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 3, "publication must download three immutable evidence sets")
    require(publish.count("digest-mismatch: error") == 3, "publication downloads must fail closed on digest mismatch")

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
    require(f"predicate-type: {PREDICATE_TYPE}" in attest, "production must issue current v3 predicate type")
    require(V1_PREDICATE_TYPE not in attest and V2_PREDICATE_TYPE not in attest, "production workflow must not issue frozen historical predicate versions")
    require("predicate-path: attestation-predicate.json" in attest, "custom predicate path changed")
    require("cp spotlight-publish-input/spotlight-*.svg artifacts/engineering-spotlight/" in publish, "publication must stage only six attested Spotlight SVGs")
    require('test ! -e artifacts/engineering-spotlight/spotlight-manifest.json' in publish, "internal Spotlight manifest must not reach generated")
    require("find artifacts/profile-stats/profile artifacts/engineering-spotlight artifacts/portfolio-evidence -type f | wc -l" in publish, "publication must enforce exact eleven-file subject set")


def validate_doc() -> None:
    text = DOC.read_text(encoding="utf-8")
    for phrase in (
        "profile-evidence-v3.schema.json",
        "profile-evidence-v2.schema.json",
        "profile-evidence-v1.schema.json",
        "frozen",
        "predicateSchema.digest",
        "Portfolio Evidence Ledger v2",
        "PL2-",
        EVIDENCE_SEMANTICS,
        "execution result",
        "subject binding",
        "freshness",
        "exactly the same eleven subjects",
        "not universal certification",
        "gh attestation verify",
    ):
        require(phrase in text, f"attestation documentation is missing: {phrase}")


def main() -> int:
    try:
        for path in (STATS, V1_SCHEMA, V2_SCHEMA, CURRENT_SCHEMA, DOC, BUILDER):
            require(path.is_file(), f"attestation contract input is missing: {path.relative_to(ROOT)}")
        validate_frozen_schema(V1_SCHEMA, V1_GIT_BLOB_SHA, V1_PREDICATE_TYPE, 1)
        validate_frozen_schema(V2_SCHEMA, V2_GIT_BLOB_SHA, V2_PREDICATE_TYPE, 2)
        validate_current_schema()
        validate_builder()
        validate_workflow()
        validate_doc()
        print(
            "Engineering attestation validation passed: predicate v1/v2 bytes are frozen, current v3 binds its schema digest and "
            "Ledger v2 result/binding/freshness semantics, generation has no signing/write authority, publication matches the eleven attested subjects, "
            "and the claim remains provenance/contract conformance rather than certification."
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
