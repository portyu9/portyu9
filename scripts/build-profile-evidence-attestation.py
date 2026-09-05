#!/usr/bin/env python3
"""Build the custom predicate used for generated profile-evidence attestations.

Subject digests are supplied by actions/attest. Predicate v3 records source revision,
workflow identity, immutable predicate-schema identity, the exact eleven published
subjects, Signal Field identity, Portfolio Evidence Ledger v2 identity/semantics, the
validation boundary, authority separation, and a bounded provenance claim.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

import profile_evidence_subjects as subjects

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "portyu9/portyu9"
KIND = "profile-evidence-attestation"
SCHEMA_VERSION = 3
PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "profile-evidence-v3.schema.json"
)
PREDICATE_SCHEMA = ROOT / ".github/attestation/profile-evidence-v3.schema.json"
BOUNDARY = "attest-validated-evidence"
EVIDENCE_SCHEMA = "signal-field-evidence-v1"
PORTFOLIO_LEDGER_VERSION = "portfolio-evidence-ledger-v2"
PORTFOLIO_EVIDENCE_SEMANTICS = "execution-result-subject-binding-freshness-v1"
AUTHORITY_SEPARATION = (
    "Generation, attestation, and publication run as distinct jobs; third-party "
    "generation code has neither repository-write nor attestation authority."
)
CLAIM = (
    "Subjects passed repository-defined validation at sourceRevision before publication; "
    "this attests artifact provenance and contract conformance, not universal certification."
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGITS = re.compile(r"^[0-9]+$")
EVIDENCE_ID = re.compile(r"^SF1-[0-9A-F]{16}$")
EVIDENCE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
PORTFOLIO_EVIDENCE_ID = re.compile(r"^PL2-[0-9A-F]{16}$")
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')

PUBLISHED_PATHS = subjects.published_paths()
SIGNAL_FIELD_FILENAMES = subjects.source_basenames("signal_field")
SIGNAL_FIELD_VALIDATORS = (
    "scripts/validate-signal-field-v213.py",
    "scripts/validate-signal-field-v214.py",
    "scripts/validate-generated-signal-field.py",
)
SPOTLIGHT_VALIDATORS = ("scripts/validate-engineering-spotlight.py --require-live",)
PORTFOLIO_LEDGER_VALIDATORS = ("scripts/validate-portfolio-evidence-ledger.py --require-live",)


def required_env(name: str, env: dict[str, str]) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ValueError(f"required environment variable is missing: {name}")
    return value


def predicate_schema_identity() -> dict[str, str]:
    if not PREDICATE_SCHEMA.is_file():
        raise ValueError(f"predicate schema is missing: {PREDICATE_SCHEMA.relative_to(ROOT)}")
    digest = hashlib.sha256(PREDICATE_SCHEMA.read_bytes()).hexdigest()
    return {"id": PREDICATE_TYPE, "digest": f"sha256:{digest}"}


def root_attrs(text: str) -> dict[str, str]:
    match = SVG_OPEN.search(text)
    if not match:
        raise ValueError("Signal Field SVG root is missing")
    return dict(ATTR.findall(match.group(0)))


def read_signal_field_evidence(directory: Path) -> dict[str, str]:
    identities: list[tuple[str, str, str]] = []
    for filename in SIGNAL_FIELD_FILENAMES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"attestation Signal Field subject is missing: {filename}")
        attrs = root_attrs(path.read_text(encoding="utf-8"))
        schema = attrs.get("data-evidence-id-schema", "")
        evidence_id = attrs.get("data-evidence-id", "")
        digest = attrs.get("data-evidence-digest", "")
        if attrs.get("data-evidence-identity") != "signal-field-v2.14":
            raise ValueError(f"{filename}: v2.14 Evidence ID provenance missing")
        if schema != EVIDENCE_SCHEMA:
            raise ValueError(f"{filename}: Signal Field Evidence ID schema changed")
        if not EVIDENCE_ID.fullmatch(evidence_id):
            raise ValueError(f"{filename}: Signal Field Evidence ID is malformed")
        if not EVIDENCE_DIGEST.fullmatch(digest):
            raise ValueError(f"{filename}: Signal Field evidence digest is malformed")
        identities.append((schema, evidence_id, digest))
    if len(set(identities)) != 1:
        raise ValueError("attested Signal Field variants do not share one Evidence ID")
    schema, evidence_id, digest = identities[0]
    return {"schema": schema, "id": evidence_id, "digest": digest}


def read_portfolio_ledger_evidence(directory: Path) -> dict[str, object]:
    path = directory / "portfolio-evidence-ledger.json"
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError("attestation Portfolio Evidence Ledger subject is missing")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("version") != PORTFOLIO_LEDGER_VERSION:
        raise ValueError("Portfolio Evidence Ledger version changed")
    if payload.get("kind") != "portfolio-evidence-ledger":
        raise ValueError("Portfolio Evidence Ledger kind changed")
    if payload.get("evidence_semantics") != PORTFOLIO_EVIDENCE_SEMANTICS:
        raise ValueError("Portfolio Evidence Ledger semantics changed")
    if "signal_summary" in payload:
        raise ValueError("Portfolio Evidence Ledger v2 contains legacy conflated signal summary")
    evidence_id = payload.get("evidence_id")
    digest = payload.get("evidence_digest")
    system_count = payload.get("system_count")
    if not isinstance(evidence_id, str) or not PORTFOLIO_EVIDENCE_ID.fullmatch(evidence_id):
        raise ValueError("Portfolio Evidence Ledger ID is malformed")
    if not isinstance(digest, str) or not EVIDENCE_DIGEST.fullmatch(digest):
        raise ValueError("Portfolio evidence digest is malformed")
    if system_count != 13:
        raise ValueError("Portfolio Evidence Ledger system count changed")
    return {
        "version": PORTFOLIO_LEDGER_VERSION,
        "semantics": PORTFOLIO_EVIDENCE_SEMANTICS,
        "id": evidence_id,
        "digest": digest,
        "systemCount": system_count,
    }


def build_predicate(env: dict[str, str], signal_field_dir: Path, portfolio_ledger_dir: Path) -> dict[str, object]:
    repository = required_env("GITHUB_REPOSITORY", env)
    revision = required_env("GITHUB_SHA", env)
    workflow_ref = required_env("GITHUB_WORKFLOW_REF", env)
    run_id = required_env("GITHUB_RUN_ID", env)
    attempt = required_env("GITHUB_RUN_ATTEMPT", env)
    server = required_env("GITHUB_SERVER_URL", env).rstrip("/")

    if repository != REPOSITORY:
        raise ValueError(f"unexpected attestation repository: {repository!r}")
    if not SHA40.fullmatch(revision):
        raise ValueError("GITHUB_SHA must be one lowercase 40-character git SHA")
    if not DIGITS.fullmatch(run_id) or not DIGITS.fullmatch(attempt):
        raise ValueError("workflow run id and attempt must be positive decimal strings")
    if server != "https://github.com":
        raise ValueError(f"unexpected GitHub server URL: {server!r}")
    if ".github/workflows/profile-stats.yml@" not in workflow_ref:
        raise ValueError("attestation must originate from profile-stats.yml")

    return {
        "schemaVersion": SCHEMA_VERSION,
        "kind": KIND,
        "repository": REPOSITORY,
        "sourceRevision": revision,
        "workflowRef": workflow_ref,
        "run": {"id": run_id, "attempt": attempt, "url": f"{server}/{REPOSITORY}/actions/runs/{run_id}"},
        "predicateSchema": predicate_schema_identity(),
        "subjectSet": {"name": subjects.NAME, "publishedPaths": list(PUBLISHED_PATHS)},
        "signalFieldEvidence": read_signal_field_evidence(signal_field_dir),
        "portfolioEvidenceLedger": read_portfolio_ledger_evidence(portfolio_ledger_dir),
        "validation": {
            "signalField": list(SIGNAL_FIELD_VALIDATORS),
            "engineeringSpotlight": list(SPOTLIGHT_VALIDATORS),
            "portfolioEvidenceLedger": list(PORTFOLIO_LEDGER_VALIDATORS),
            "boundary": BOUNDARY,
        },
        "authority": {
            "generation": "contents:read",
            "attestation": "contents:read,id-token:write,attestations:write",
            "publication": "contents:write",
            "separation": AUTHORITY_SEPARATION,
        },
        "claim": CLAIM,
    }


def validate_predicate(predicate: dict[str, object]) -> None:
    if predicate.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError("schemaVersion changed")
    if predicate.get("kind") != KIND or predicate.get("repository") != REPOSITORY:
        raise ValueError("predicate identity changed")
    revision = predicate.get("sourceRevision")
    if not isinstance(revision, str) or not SHA40.fullmatch(revision):
        raise ValueError("sourceRevision is malformed")
    if predicate.get("predicateSchema") != predicate_schema_identity():
        raise ValueError("predicate schema identity changed")

    subject_set = predicate.get("subjectSet")
    if not isinstance(subject_set, dict) or subject_set.get("name") != subjects.NAME:
        raise ValueError("subjectSet changed")
    if subject_set.get("publishedPaths") != list(PUBLISHED_PATHS) or len(set(PUBLISHED_PATHS)) != 11:
        raise ValueError("published subject paths changed")

    signal = predicate.get("signalFieldEvidence")
    if not isinstance(signal, dict) or signal.get("schema") != EVIDENCE_SCHEMA:
        raise ValueError("Signal Field evidence block changed")
    if not isinstance(signal.get("id"), str) or not EVIDENCE_ID.fullmatch(str(signal["id"])):
        raise ValueError("Signal Field Evidence ID is malformed")
    if not isinstance(signal.get("digest"), str) or not EVIDENCE_DIGEST.fullmatch(str(signal["digest"])):
        raise ValueError("Signal Field evidence digest is malformed")

    portfolio = predicate.get("portfolioEvidenceLedger")
    if not isinstance(portfolio, dict):
        raise ValueError("portfolioEvidenceLedger is missing")
    expected_portfolio = {
        "version": PORTFOLIO_LEDGER_VERSION,
        "semantics": PORTFOLIO_EVIDENCE_SEMANTICS,
        "id": portfolio.get("id"),
        "digest": portfolio.get("digest"),
        "systemCount": 13,
    }
    if portfolio != expected_portfolio:
        raise ValueError("Portfolio Evidence Ledger predicate block changed")
    if not isinstance(portfolio.get("id"), str) or not PORTFOLIO_EVIDENCE_ID.fullmatch(str(portfolio["id"])):
        raise ValueError("Portfolio Evidence Ledger ID is malformed")
    if not isinstance(portfolio.get("digest"), str) or not EVIDENCE_DIGEST.fullmatch(str(portfolio["digest"])):
        raise ValueError("Portfolio Evidence Ledger digest is malformed")

    validation = predicate.get("validation")
    expected_validation = {
        "signalField": list(SIGNAL_FIELD_VALIDATORS),
        "engineeringSpotlight": list(SPOTLIGHT_VALIDATORS),
        "portfolioEvidenceLedger": list(PORTFOLIO_LEDGER_VALIDATORS),
        "boundary": BOUNDARY,
    }
    if validation != expected_validation:
        raise ValueError("validation contract changed")
    expected_authority = {
        "generation": "contents:read",
        "attestation": "contents:read,id-token:write,attestations:write",
        "publication": "contents:write",
        "separation": AUTHORITY_SEPARATION,
    }
    if predicate.get("authority") != expected_authority:
        raise ValueError("authority contract changed")
    if predicate.get("claim") != CLAIM:
        raise ValueError("claim boundary changed")


def fixture_env() -> dict[str, str]:
    return {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_SHA": "a" * 40,
        "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/.github/workflows/profile-stats.yml@refs/heads/main",
        "GITHUB_RUN_ID": "123456789",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SERVER_URL": "https://github.com",
    }


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        signal_dir = root / "signal"
        ledger_dir = root / "ledger"
        signal_dir.mkdir()
        ledger_dir.mkdir()
        for filename in SIGNAL_FIELD_FILENAMES:
            (signal_dir / filename).write_text(
                '<svg data-evidence-identity="signal-field-v2.14" '
                'data-evidence-id-schema="signal-field-evidence-v1" '
                'data-evidence-id="SF1-0123456789ABCDEF" '
                f'data-evidence-digest="sha256:{"a" * 64}"></svg>',
                encoding="utf-8",
            )
        (ledger_dir / "portfolio-evidence-ledger.json").write_text(
            json.dumps(
                {
                    "version": PORTFOLIO_LEDGER_VERSION,
                    "kind": "portfolio-evidence-ledger",
                    "evidence_semantics": PORTFOLIO_EVIDENCE_SEMANTICS,
                    "result_summary": {"PASSING": 25},
                    "binding_summary": {"CURRENT_SUBJECT": 25},
                    "freshness_summary": {"SAME_DAY": 25},
                    "evidence_id": "PL2-0123456789ABCDEF",
                    "evidence_digest": f"sha256:{'b' * 64}",
                    "system_count": 13,
                }
            ),
            encoding="utf-8",
        )
        predicate = build_predicate(fixture_env(), signal_dir, ledger_dir)
        validate_predicate(predicate)
        reparsed = json.loads(json.dumps(predicate, sort_keys=True, separators=(",", ":")))
        validate_predicate(reparsed)
        if reparsed["portfolioEvidenceLedger"]["semantics"] != PORTFOLIO_EVIDENCE_SEMANTICS:
            raise AssertionError("Portfolio evidence semantics were not recorded")
        if reparsed["predicateSchema"] != predicate_schema_identity():
            raise AssertionError("predicate schema digest was not recorded")
    print(
        "Profile evidence attestation predicate v3 self-test passed: immutable schema + Signal Field + "
        "three Spotlights + Portfolio Evidence Ledger v2 with result/binding/freshness semantics"
    )


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 4:
            raise ValueError(
                "usage: build-profile-evidence-attestation.py <signal-field-directory> <portfolio-ledger-directory> <output.json> | --self-test"
            )
        signal_field_dir = Path(sys.argv[1])
        portfolio_ledger_dir = Path(sys.argv[2])
        predicate = build_predicate(dict(os.environ), signal_field_dir, portfolio_ledger_dir)
        validate_predicate(predicate)
        output = Path(sys.argv[3])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(predicate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            "Profile evidence predicate v3 built: "
            f"{predicate['portfolioEvidenceLedger']['id']} · {predicate['portfolioEvidenceLedger']['semantics']}"
        )
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
