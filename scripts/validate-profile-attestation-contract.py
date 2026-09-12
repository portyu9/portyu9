#!/usr/bin/env python3
"""Validate immutable profile-evidence and post-publication attestation contracts."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import re
import sys

import profile_evidence_subjects as subjects
import profile_evidence_validation as validation_contract

ROOT = Path(__file__).resolve().parents[1]
STATS = ROOT / ".github/workflows/profile-stats.yml"
V1_SCHEMA = ROOT / ".github/attestation/profile-evidence-v1.schema.json"
V2_SCHEMA = ROOT / ".github/attestation/profile-evidence-v2.schema.json"
CURRENT_SCHEMA = ROOT / ".github/attestation/profile-evidence-v3.schema.json"
RECEIPT_SCHEMA = ROOT / ".github/attestation/generated-publication-receipt-v1.schema.json"
DOC = ROOT / ".github/ATTESTATION.md"
BUILDER = ROOT / "scripts/build-profile-evidence-attestation.py"
RECEIPT_BUILDER = ROOT / "scripts/build-generated-publication-receipt.py"
SUBJECT_VALIDATOR = ROOT / "scripts/validate-profile-evidence-subjects.py"
STAGER = ROOT / "scripts/stage-profile-evidence.py"
VALIDATION_MANIFEST = ROOT / "scripts/profile-evidence-validation-boundary-v1.json"
VALIDATION_RUNNER = ROOT / "scripts/validate-profile-evidence-boundary.py"

V1_GIT_BLOB_SHA = "075fc17c817fe689702bc96c9875a0eb0a934375"
V2_GIT_BLOB_SHA = "66a1486e565b89759812ff00dd33edc44a64cfa6"
V3_GIT_BLOB_SHA = "9f9ef42b4861fd3130568197f0592353c0acad9c"
ATTEST_SHA = "1e69f48acb82d1966a394da916b4c1698aa569d6"  # actions/attest v4.2.2
CHECKOUT_SHA = "3d3c42e5aac5ba805825da76410c181273ba90b1"
SETUP_PYTHON_SHA = "5fda3b95a4ea91299a34e894583c3862153e4b97"
DOWNLOAD_SHA = "3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
UPLOAD_SHA = "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
V1_PREDICATE_TYPE = "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v1.schema.json"
V2_PREDICATE_TYPE = "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v2.schema.json"
PREDICATE_TYPE = "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/profile-evidence-v3.schema.json"
RECEIPT_PREDICATE_TYPE = "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/generated-publication-receipt-v1.schema.json"
EVIDENCE_SEMANTICS = "execution-result-subject-binding-freshness-v1"
VALIDATOR_CONTRACT = validation_contract.predicate_validators()
SIGNAL_VALIDATORS = list(VALIDATOR_CONTRACT["signalField"])
SPOTLIGHT_VALIDATORS = list(VALIDATOR_CONTRACT["engineeringSpotlight"])
LEDGER_VALIDATORS = list(VALIDATOR_CONTRACT["portfolioEvidenceLedger"])
VALIDATION_BOUNDARY = validation_contract.boundary_name()


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


def require_boundary_runner(block: str, *, signal: str, spotlight: str, ledger: str, label: str) -> None:
    require(block.count("validate-profile-evidence-boundary.py") == 1,
            f"{label} must invoke canonical validation boundary exactly once")
    for fragment in (
        f"--signal-field-dir {signal}",
        f"--spotlight-dir {spotlight}",
        f"--portfolio-ledger-dir {ledger}",
    ):
        require(fragment in block, f"{label} canonical validation boundary is missing: {fragment}")


def validate_frozen_schema(path: Path, blob_sha: str, predicate_type: str, version: int) -> None:
    require(path.is_file(), f"frozen predicate v{version} schema is missing")
    require(git_blob_sha(path) == blob_sha,
            f"published profile-evidence-v{version} schema bytes changed; published schema versions are immutable")
    schema = json.loads(path.read_text(encoding="utf-8"))
    require(schema.get("$id") == predicate_type, f"frozen predicate v{version} schema id changed")
    require(schema.get("properties", {}).get("schemaVersion", {}).get("const") == version,
            f"frozen predicate v{version} schema version changed")


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

    published = properties.get("subjectSet", {}).get("properties", {}).get("publishedPaths", {}).get("const")
    require(published == list(subjects.published_paths()), "v3 published subjects must equal canonical subject contract")

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
    require(validation.get("signalField", {}).get("const") == SIGNAL_VALIDATORS,
            "v3 Signal Field validator set differs from canonical validation boundary")
    require(validation.get("engineeringSpotlight", {}).get("const") == SPOTLIGHT_VALIDATORS,
            "v3 Spotlight validator set differs from canonical validation boundary")
    require(validation.get("portfolioEvidenceLedger", {}).get("const") == LEDGER_VALIDATORS,
            "v3 Ledger validator set differs from canonical validation boundary")
    require(validation.get("boundary", {}).get("const") == VALIDATION_BOUNDARY,
            "v3 validation boundary differs from canonical validation boundary")

    authority = properties.get("authority", {}).get("properties", {})
    require(authority.get("generation", {}).get("const") == "contents:read", "generation authority changed")
    require(authority.get("attestation", {}).get("const") == "contents:read,id-token:write,attestations:write",
            "attestation authority changed")
    require(authority.get("publication", {}).get("const") == "contents:write", "publication authority changed")
    claim = properties.get("claim", {}).get("const")
    require(isinstance(claim, str) and "not universal certification" in claim,
            "predicate must preserve non-certification claim boundary")


def validate_receipt_schema_payload(schema: dict[str, object]) -> None:
    require(schema.get("$id") == RECEIPT_PREDICATE_TYPE,
            "publication receipt predicate schema id changed")
    require(schema.get("additionalProperties") is False,
            "publication receipt predicate schema must fail closed")
    required = schema.get("required")
    require(isinstance(required, list), "publication receipt required set is malformed")
    for key in ("predicateSchema", "source", "transaction", "publication", "evidence", "claim"):
        require(key in required, f"publication receipt predicate must require {key}")
    properties = schema.get("properties")
    require(isinstance(properties, dict), "publication receipt predicate properties are missing")
    require(properties.get("schemaVersion", {}).get("const") == 1,
            "publication receipt schemaVersion changed")
    require(properties.get("kind", {}).get("const") == "generated-publication-receipt",
            "publication receipt kind changed")
    require(properties.get("repository", {}).get("const") == "portyu9/portyu9",
            "publication receipt repository identity changed")
    require(properties.get("workflowRef", {}).get("const") ==
            "portyu9/portyu9/.github/workflows/profile-stats.yml@refs/heads/main",
            "publication receipt workflow identity changed")

    schema_identity = properties.get("predicateSchema", {})
    schema_props = schema_identity.get("properties", {}) if isinstance(schema_identity, dict) else {}
    require(schema_identity.get("additionalProperties") is False,
            "publication receipt predicateSchema block must fail closed")
    require(schema_props.get("id", {}).get("const") == RECEIPT_PREDICATE_TYPE,
            "publication receipt predicateSchema id changed")
    require(schema_props.get("digest", {}).get("pattern") == "^sha256:[0-9a-f]{64}$",
            "publication receipt predicateSchema digest format changed")

    source = properties.get("source", {})
    source_props = source.get("properties", {}) if isinstance(source, dict) else {}
    epoch = source_props.get("epoch", {}) if isinstance(source_props, dict) else {}
    epoch_props = epoch.get("properties", {}) if isinstance(epoch, dict) else {}
    require(source.get("additionalProperties") is False and epoch.get("additionalProperties") is False,
            "publication receipt source/epoch blocks must fail closed")
    require(epoch_props.get("version", {}).get("const") == "profile-stats-source-epoch-v1",
            "publication receipt source epoch version changed")
    require(epoch_props.get("algorithm", {}).get("const") == "sha256-sorted-path-nul-git-blob-oid-lf-v1",
            "publication receipt source epoch algorithm changed")
    require(epoch_props.get("closureSha256", {}).get("pattern") == "^[0-9a-f]{64}$",
            "publication receipt source epoch digest format changed")

    transaction = properties.get("transaction", {})
    transaction_props = transaction.get("properties", {}) if isinstance(transaction, dict) else {}
    require(transaction.get("additionalProperties") is False,
            "publication receipt transaction block must fail closed")
    for key in ("leaseId", "candidateId"):
        require(transaction_props.get(key, {}).get("pattern") == "^[0-9a-f]{64}$",
                f"publication receipt {key} format changed")

    publication = properties.get("publication", {})
    publication_props = publication.get("properties", {}) if isinstance(publication, dict) else {}
    require(publication.get("additionalProperties") is False,
            "publication receipt publication block must fail closed")
    require(publication_props.get("branch", {}).get("const") == "generated",
            "publication receipt branch changed")
    for key in ("commitSha", "parentSha"):
        require(publication_props.get(key, {}).get("pattern") == "^[0-9a-f]{40}$",
                f"publication receipt {key} format changed")
    require(publication_props.get("gitObjectSha256", {}).get("pattern") == "^[0-9a-f]{64}$",
            "publication receipt canonical Git-object digest format changed")

    evidence = properties.get("evidence", {})
    evidence_props = evidence.get("properties", {}) if isinstance(evidence, dict) else {}
    require(evidence.get("additionalProperties") is False,
            "publication receipt evidence block must fail closed")
    require(evidence_props.get("subjectSet", {}).get("const") == subjects.NAME,
            "publication receipt subject-set identity changed")
    subject_schema = evidence_props.get("subjects", {})
    require(subject_schema.get("minItems") == 11 and subject_schema.get("maxItems") == 11,
            "publication receipt must bind exactly eleven evidence subjects")
    prefix_items = subject_schema.get("prefixItems")
    require(isinstance(prefix_items, list) and len(prefix_items) == 11 and subject_schema.get("items") is False,
            "publication receipt subject schema closure changed")
    definitions = schema.get("$defs")
    require(isinstance(definitions, dict), "publication receipt schema definitions are missing")
    observed_paths: list[str] = []
    for item in prefix_items:
        require(isinstance(item, dict) and isinstance(item.get("$ref"), str),
                "publication receipt subject schema reference is malformed")
        ref = item["$ref"]
        name = ref.removeprefix("#/$defs/")
        definition = definitions.get(name)
        require(isinstance(definition, dict), f"publication receipt subject definition is missing: {name}")
        all_of = definition.get("allOf")
        require(isinstance(all_of, list) and len(all_of) == 2,
                f"publication receipt subject definition changed: {name}")
        path_const = all_of[1].get("properties", {}).get("path", {}).get("const")
        require(isinstance(path_const, str), f"publication receipt subject path is missing: {name}")
        observed_paths.append(path_const)
    require(observed_paths == list(subjects.published_paths()),
            "publication receipt subjects must equal canonical published subject order")

    claim = properties.get("claim", {}).get("const")
    require(isinstance(claim, str) and "actual published generated Git commit and parent" in claim
            and "leased transaction" in claim,
            "publication receipt claim boundary changed")


def validate_receipt_schema() -> None:
    schema = json.loads(RECEIPT_SCHEMA.read_text(encoding="utf-8"))
    require(isinstance(schema, dict), "publication receipt schema root must be an object")
    validate_receipt_schema_payload(schema)
    mutated = copy.deepcopy(schema)
    mutated["properties"]["publication"]["properties"]["branch"]["const"] = "main"
    try:
        validate_receipt_schema_payload(mutated)
    except ValueError as exc:
        require("branch changed" in str(exc),
                f"publication receipt schema negative test failed for wrong reason: {exc}")
    else:
        fail("publication receipt schema negative test accepted branch drift")


def validate_builder() -> None:
    text = BUILDER.read_text(encoding="utf-8")
    for phrase in (
        "SCHEMA_VERSION = 3",
        "profile-evidence-v3.schema.json",
        'PORTFOLIO_LEDGER_VERSION = "portfolio-evidence-ledger-v2"',
        f'PORTFOLIO_EVIDENCE_SEMANTICS = "{EVIDENCE_SEMANTICS}"',
        'PORTFOLIO_EVIDENCE_ID = re.compile(r"^PL2-[0-9A-F]{16}$")',
        "import profile_evidence_subjects as subjects",
        "import profile_evidence_validation as validation_contract",
        "PUBLISHED_PATHS = subjects.published_paths()",
        'SIGNAL_FIELD_FILENAMES = subjects.source_basenames("signal_field")',
        "VALIDATOR_CONTRACT = validation_contract.predicate_validators()",
        "BOUNDARY = validation_contract.boundary_name()",
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
    for validator in (*SIGNAL_VALIDATORS, *SPOTLIGHT_VALIDATORS, *LEDGER_VALIDATORS):
        require(f'"{validator}"' not in text,
                f"attestation builder still hardcodes canonical validator identity: {validator}")
    for published_path in subjects.published_paths():
        require(f'"{published_path}"' not in text,
                f"attestation builder must not hardcode canonical subject path: {published_path}")


def validate_receipt_builder() -> None:
    text = RECEIPT_BUILDER.read_text(encoding="utf-8")
    for phrase in (
        "SCHEMA_VERSION = 1",
        'KIND = "generated-publication-receipt"',
        "generated-publication-receipt-v1.schema.json",
        'SOURCE_EPOCH_VERSION = "profile-stats-source-epoch-v1"',
        'SOURCE_EPOCH_ALGORITHM = "sha256-sorted-path-nul-git-blob-oid-lf-v1"',
        "import profile_evidence_subjects as subjects",
        'subjectSet.get("publishedPaths") == list(subjects.published_paths())',
        'expected_candidate = hashlib.sha256(',
        'f"{source_sha}\\n{parent_sha}\\n{profile_digest}\\n".encode("ascii")',
        '"leaseId": lease_id, "candidateId": candidate_id',
        '"commitSha": published_sha',
        '"parentSha": parent_sha',
        '"gitObjectSha256": git_object_sha256',
        '"profileEvidencePredicateSha256": profile_digest',
        '"subjects": evidence_subjects(published_root)',
        "publication receipt candidate identity is not the exact leased Profile Stats candidate",
        "publication receipt subject set must contain exactly eleven files",
    ):
        require(phrase in text, f"publication receipt builder contract is missing: {phrase}")
    require("subprocess" not in text and "os.system" not in text,
            "publication receipt builder must not acquire process execution authority")


def validate_workflow() -> None:
    text = STATS.read_text(encoding="utf-8")
    generate = job_block(text, "generate", "attest")
    prepare = job_block(text, "attest", "lease")
    lease = job_block(text, "lease", "attest_publish")
    attest_write = job_block(text, "attest_publish", "stage")
    stage = job_block(text, "stage", "publish")
    publish = job_block(text, "publish", "receipt")
    receipt = job_block(text, "receipt", "receipt_attest")
    receipt_attest = job_block(text, "receipt_attest", "dispatch")
    dispatch = job_block(text, "dispatch", None)

    require("name: generate-read-only" in generate, "generation job name changed")
    require("contents: write" not in generate and "id-token: write" not in generate and "attestations: write" not in generate,
            "generation authority expanded")

    require("name: prepare-attestation-read-only" in prepare and "needs: generate" in prepare,
            "attestation preparation identity/dependency changed")
    require("permissions:\n      contents: read" in prepare,
            "attestation preparation must retain contents: read only")
    for forbidden in ("contents: write", "id-token: write", "attestations: write", f"actions/attest@{ATTEST_SHA}"):
        require(forbidden not in prepare,
                f"attestation preparation acquired terminal signing/write surface: {forbidden}")

    require("name: mint-mutation-lease-read-only" in lease and "needs: attest" in lease,
            "mutation lease mint identity/dependency changed")
    require("permissions:\n      actions: read" in lease,
            "mutation lease mint must remain Actions-read-only")
    for forbidden in ("contents: write", "id-token: write", "attestations: write", f"actions/attest@{ATTEST_SHA}"):
        require(forbidden not in lease,
                f"mutation lease mint acquired attestation/content-write authority: {forbidden}")

    require("name: attest-write-only" in attest_write and "needs: [attest, lease]" in attest_write,
            "terminal attestation identity/dependency changed")
    require("contents: read" in attest_write and "id-token: write" in attest_write and "attestations: write" in attest_write,
            "terminal attestation authority changed")
    require("contents: write" not in attest_write,
            "terminal attestation must not receive repository-content write authority")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "python3 ", "git ", "gh ", "GITHUB_TOKEN:", "GH_TOKEN:"):
        require(forbidden not in attest_write,
                f"terminal attestation must not execute repository-authored code or alternate mutation clients: {forbidden}")
    require(attest_write.count("        run: |") == 2,
            "terminal attestation may execute only the two reviewed first-party proof shells")
    for fragment in (
        "- name: Verify exact short-lived mutation lease",
        "LEASE_MIN_REMAINING_SECONDS=300",
        'test $((LEASE_EXPIRES_AT - NOW_EPOCH)) -ge "$LEASE_MIN_REMAINING_SECONDS"',
        "- name: Verify leased attestation predicate identity",
        'EXPECTED_PREDICATE_SHA256: ${{ needs.attest.outputs.predicate_sha256 }}',
        'test "$(sha256sum attestation-input/attestation-predicate.json | cut -d\' \' -f1)" = "$EXPECTED_PREDICATE_SHA256"',
    ):
        require(fragment in attest_write,
                f"terminal attestation lost reviewed lease/predicate proof: {fragment}")

    require("name: stage-publication-read-only" in stage and
            "needs: [generate, attest, lease, attest_publish]" in stage,
            "publication staging dependency changed")
    require("permissions:\n      contents: read" in stage, "publication staging authority changed")
    require("contents: write" not in stage and "id-token: write" not in stage and "attestations: write" not in stage,
            "publication staging authority expanded")
    require("name: publish-write-only" in publish and "needs: [stage, lease, attest]" in publish,
            "publication dependency changed")
    require("permissions:\n      contents: write" in publish and "id-token: write" not in publish and "attestations: write" not in publish,
            "publication authority changed")
    publish_guard = "if: needs.stage.outputs.changed == 'true'"
    require(publish.startswith(f"  publish:\n    {publish_guard}\n"),
            "terminal publication must use the exact staged-candidate guard at the job boundary")
    require(publish.count(publish_guard) == 4,
            "terminal publication job and all three changed-candidate steps must share the exact staged-candidate guard")
    require("actions/checkout@" not in publish and "actions/setup-python@" not in publish and "python3 " not in publish,
            "terminal publication must not execute checkout/setup/authored Python")

    require("name: prepare-publication-receipt-read-only" in receipt and
            "needs: [publish, stage, lease, attest]" in receipt,
            "publication receipt preparation identity/dependency changed")
    require("permissions:\n      contents: read" in receipt,
            "publication receipt preparation must retain contents: read only")
    for forbidden in ("contents: write", "id-token: write", "attestations: write", "actions: write", f"actions/attest@{ATTEST_SHA}", "GH_TOKEN:", "GITHUB_TOKEN:"):
        require(forbidden not in receipt,
                f"publication receipt preparation acquired terminal mutation/signing authority: {forbidden}")
    require(receipt.count(f"actions/checkout@{CHECKOUT_SHA}") == 2,
            "publication receipt preparation must perform exactly two credential-free checkouts")
    require(receipt.count(f"actions/setup-python@{SETUP_PYTHON_SHA}") == 1,
            "publication receipt preparation setup-python SHA changed")
    require(receipt.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 1 and
            receipt.count("digest-mismatch: error") == 1,
            "publication receipt preparation must download exactly one digest-checked reviewed predicate")
    require(receipt.count(f"actions/upload-artifact@{UPLOAD_SHA}") == 1,
            "publication receipt preparation must upload exactly one receipt predicate")
    for fragment in (
        'ref: ${{ needs.publish.outputs.published_sha }}',
        "fetch-depth: 2",
        'PUBLISHED_SHA: ${{ needs.publish.outputs.published_sha }}',
        'PUBLISHED_PARENT_SHA: ${{ needs.publish.outputs.parent_sha }}',
        'SOURCE_SHA: ${{ needs.publish.outputs.source_sha }}',
        'LEASE_ID: ${{ needs.lease.outputs.lease_id }}',
        'CANDIDATE_ID: ${{ needs.attest.outputs.candidate_id }}',
        'test "$(git -C published rev-parse HEAD)" = "$PUBLISHED_SHA"',
        'test "$(git -C published rev-parse HEAD^)" = "$PUBLISHED_PARENT_SHA"',
        'test "$(git -C published rev-list --parents -n 1 HEAD | awk \'{print NF}\')" -eq 2',
        'test "$(git -C published log -1 --format=%s)" = "chore: publish validated profile evidence [skip ci]"',
        'test "$(git -C published log -1 --format=\'%an <%ae>\')" = "github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>"',
        'test "$(git -C published log -1 --format=\'%cn <%ce>\')" = "github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>"',
        'REMOTE_GENERATED="$(git -C published ls-remote --exit-code origin refs/heads/generated)"',
        'test "${BASH_REMATCH[1]}" = "$PUBLISHED_SHA"',
        'git -C published cat-file commit "$PUBLISHED_SHA" > published-commit.payload',
        "{ printf 'commit %s\\0' \"$PAYLOAD_SIZE\"; cat published-commit.payload; } > published-commit.object",
        'test "$(sha1sum published-commit.object | cut -d\' \' -f1)" = "$PUBLISHED_SHA"',
        'GIT_OBJECT_SHA256="$(sha256sum published-commit.object | cut -d\' \' -f1)"',
        "python3 source/scripts/build-generated-publication-receipt.py",
        "name: generated-publication-receipt-predicate",
        "path: generated-publication-receipt.json",
    ):
        require(fragment in receipt, f"publication receipt preparation lost proof: {fragment}")

    require("name: attest-publication-receipt-write-only" in receipt_attest and
            "needs: [receipt, lease, attest]" in receipt_attest,
            "publication receipt signer identity/dependency changed")
    require("contents: read" in receipt_attest and "id-token: write" in receipt_attest
            and "attestations: write" in receipt_attest and "contents: write" not in receipt_attest
            and "actions: write" not in receipt_attest,
            "publication receipt signer authority changed")
    for forbidden in ("actions/checkout@", "actions/setup-python@", "python3 ", "git ", "gh ", "GITHUB_TOKEN:", "GH_TOKEN:"):
        require(forbidden not in receipt_attest,
                f"publication receipt signer must not execute repository-authored code or alternate mutation clients: {forbidden}")
    require(receipt_attest.count("        run: |") == 2,
            "publication receipt signer may execute only lease and predicate-digest proof shells")
    require(receipt_attest.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 1 and
            receipt_attest.count("digest-mismatch: error") == 1,
            "publication receipt signer must download exactly one digest-checked predicate")
    require(receipt_attest.count(f"actions/attest@{ATTEST_SHA}") == 1,
            "publication receipt signer must execute the reviewed actions/attest SHA exactly once")
    require(receipt_attest.count("      - name: ") == 4,
            "publication receipt signer must contain lease proof, predicate download/proof, and one attest step")
    for fragment in (
        "- name: Verify exact short-lived mutation lease",
        "LEASE_MIN_REMAINING_SECONDS=300",
        'test $((LEASE_EXPIRES_AT - NOW_EPOCH)) -ge "$LEASE_MIN_REMAINING_SECONDS"',
        "- name: Verify exact receipt predicate identity",
        'EXPECTED_PREDICATE_SHA256: ${{ needs.receipt.outputs.predicate_sha256 }}',
        'test "$(sha256sum receipt-attestation-input/generated-publication-receipt.json | cut -d\' \' -f1)" = "$EXPECTED_PREDICATE_SHA256"',
        f"uses: actions/attest@{ATTEST_SHA} # v4.2.2",
        'subject-name: portyu9/portyu9:generated@${{ needs.receipt.outputs.published_sha }}',
        'subject-digest: sha256:${{ needs.receipt.outputs.git_object_sha256 }}',
        f"predicate-type: {RECEIPT_PREDICATE_TYPE}",
        "predicate-path: receipt-attestation-input/generated-publication-receipt.json",
    ):
        require(fragment in receipt_attest, f"publication receipt signer lost proof: {fragment}")

    require("name: dispatch-spotlight-link-sync" in dispatch and
            "needs: [receipt_attest, lease, attest]" in dispatch,
            "post-publication dispatcher must remain downstream of signed receipt")
    require("permissions:\n      actions: write" in dispatch,
            "post-publication dispatcher authority changed")
    for forbidden in ("contents: write", "id-token: write", "attestations: write", "pull-requests: write", "actions/checkout@", "actions/setup-python@", "python3 "):
        require(forbidden not in dispatch,
                f"post-publication dispatcher acquired unrelated authority/execution surface: {forbidden}")

    require(generate.count(f"actions/upload-artifact@{UPLOAD_SHA}") == 3,
            "generation must upload exactly three immutable evidence sets")
    require(prepare.count(f"actions/checkout@{CHECKOUT_SHA}") == 2,
            "attestation preparation checkout inventory changed")
    require(prepare.count(f"actions/setup-python@{SETUP_PYTHON_SHA}") == 1,
            "attestation preparation setup-python SHA changed")
    require(prepare.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 3,
            "attestation preparation must download three immutable evidence sets")
    require(prepare.count("digest-mismatch: error") == 3,
            "attestation preparation downloads must fail closed on digest mismatch")
    require(prepare.count(f"actions/upload-artifact@{UPLOAD_SHA}") == 1,
            "attestation preparation must upload exactly one reviewed predicate artifact")

    require(attest_write.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 4,
            "terminal attestation must download three evidence sets plus one reviewed predicate")
    require(attest_write.count("digest-mismatch: error") == 4,
            "terminal attestation downloads must fail closed on digest mismatch")
    require(attest_write.count(f"actions/attest@{ATTEST_SHA}") == 1,
            "terminal attestation must execute the reviewed actions/attest SHA exactly once")
    require(attest_write.count("      - name: ") == 7,
            "terminal attestation must contain two reviewed proof shells, four downloads, and one attest step")

    require(stage.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 3,
            "publication staging must download three immutable evidence sets")
    require(stage.count("digest-mismatch: error") == 3,
            "publication staging downloads must fail closed on digest mismatch")
    require(stage.count(f"actions/upload-artifact@{UPLOAD_SHA}") == 1,
            "publication staging must upload one sealed candidate bundle")
    require(publish.count(f"actions/download-artifact@{DOWNLOAD_SHA}") == 1,
            "terminal publication must download only the sealed candidate bundle")
    require(publish.count("digest-mismatch: error") == 1,
            "terminal publication candidate download must fail closed on digest mismatch")

    require_boundary_runner(
        prepare,
        signal="profile-stats/profile",
        spotlight="engineering-spotlight",
        ledger="portfolio-evidence",
        label="attestation preparation",
    )
    require_boundary_runner(
        stage,
        signal="publish-input",
        spotlight="spotlight-publish-input",
        ledger="portfolio-ledger-publish-input",
        label="publication staging",
    )
    for forbidden in (
        "python3 source/scripts/validate-signal-field-v213.py profile-stats/profile",
        "python3 source/scripts/validate-signal-field-v214.py profile-stats/profile",
        "python3 source/scripts/validate-generated-signal-field.py profile-stats/profile",
        "python3 source/scripts/validate-engineering-spotlight.py engineering-spotlight",
        "python3 source/scripts/validate-portfolio-evidence-ledger.py portfolio-evidence",
    ):
        require(forbidden not in prepare,
                f"attestation preparation duplicates canonical validation stage: {forbidden}")
    for forbidden in (
        "python3 source/scripts/validate-signal-field-v213.py publish-input",
        "python3 source/scripts/validate-signal-field-v214.py publish-input",
        "python3 source/scripts/validate-generated-signal-field.py publish-input",
        "python3 source/scripts/validate-engineering-spotlight.py spotlight-publish-input",
        "python3 source/scripts/validate-portfolio-evidence-ledger.py portfolio-ledger-publish-input",
    ):
        require(forbidden not in stage,
                f"publication staging duplicates canonical validation stage: {forbidden}")

    require("python3 source/scripts/build-profile-evidence-attestation.py profile-stats/profile portfolio-evidence attestation-predicate.json" in prepare,
            "attestation predicate build command is missing from read-only preparation")
    require("name: profile-evidence-attestation-predicate" in prepare and
            "path: attestation-predicate.json" in prepare,
            "reviewed predicate artifact identity changed")
    require(f"uses: actions/attest@{ATTEST_SHA} # v4.2.2" in attest_write,
            "actions/attest pin changed")
    for pattern in subjects.attestation_patterns():
        require(pattern in attest_write, f"attestation subject pattern is missing: {pattern}")
    require("engineering-spotlight/*.svg" not in attest_write,
            "attestation must not use broad Spotlight glob")
    require(f"predicate-type: {PREDICATE_TYPE}" in attest_write,
            "production must issue current v3 predicate type")
    require(V1_PREDICATE_TYPE not in attest_write and V2_PREDICATE_TYPE not in attest_write,
            "production workflow must not issue frozen historical predicate versions")
    require("predicate-path: attestation-input/attestation-predicate.json" in attest_write,
            "terminal attestation predicate path changed")

    guard = "if: github.event_name != 'schedule' || needs.attest.outputs.changed == 'true'"
    require(attest_write.startswith(f"  attest_publish:\n    {guard}\n"),
            "terminal attestation job must use the exact scheduled-delta guard at the job boundary")
    require(attest_write.count(guard) == 6,
            "terminal attestation job, four downloads, and attest step must share the exact scheduled-delta guard")
    require("python3 source/scripts/stage-profile-evidence.py candidate-profile-evidence" in prepare,
            "scheduled delta comparison must stage canonical subject set")
    require("python3 source/scripts/validate-profile-evidence-subjects.py --published-root published" in prepare,
            "scheduled delta comparison must validate current generated inventory")
    require("python3 source/scripts/stage-profile-evidence.py artifacts" in stage,
            "publication staging must use canonical subject contract")
    require("python3 source/scripts/validate-profile-evidence-subjects.py --published-root artifacts" in stage,
            "publication staging must validate exact generated inventory")
    require("git -C artifacts bundle create ../generated-publication.bundle generated" in stage,
            "publication staging must seal the generated candidate bundle")
    require("name: generated-publication-candidate" in stage and "path: generated-publication.bundle" in stage,
            "sealed publication artifact identity changed")


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
        "profile-evidence-subjects-v1",
        "profile-evidence-validation-boundary-v1",
        "validate-profile-evidence-boundary.py",
        "prepare-attestation-read-only",
        "attest-write-only",
        "no repository-authored shell",
        "not universal certification",
        "gh attestation verify",
    ):
        require(phrase in text, f"attestation documentation is missing: {phrase}")


def main() -> int:
    try:
        subjects.load_manifest()
        validation_contract.load_manifest()
        for path in (
            STATS, V1_SCHEMA, V2_SCHEMA, CURRENT_SCHEMA, RECEIPT_SCHEMA, DOC, BUILDER,
            RECEIPT_BUILDER, SUBJECT_VALIDATOR, STAGER, VALIDATION_MANIFEST, VALIDATION_RUNNER,
        ):
            require(path.is_file(), f"attestation contract input is missing: {path.relative_to(ROOT)}")
        validate_frozen_schema(V1_SCHEMA, V1_GIT_BLOB_SHA, V1_PREDICATE_TYPE, 1)
        validate_frozen_schema(V2_SCHEMA, V2_GIT_BLOB_SHA, V2_PREDICATE_TYPE, 2)
        validate_frozen_schema(CURRENT_SCHEMA, V3_GIT_BLOB_SHA, PREDICATE_TYPE, 3)
        validate_current_schema()
        validate_receipt_schema()
        validate_builder()
        validate_receipt_builder()
        validate_workflow()
        validate_doc()
        print(
            "Engineering attestation validation passed: predicate v1/v2/v3 bytes are frozen; read-only preparation owns validation/predicate construction; "
            "terminal evidence attestation and post-publication receipt signing each retain isolated OIDC/attestation authority with reviewed proof shells and pinned actions/attest; "
            "terminal contents-write publication remains separate; the actual published generated Git commit object is SHA-256 receipted before Spotlight dispatch; "
            "the eleven-subject contract remains closed and the evidence claim remains provenance/contract conformance rather than certification."
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
