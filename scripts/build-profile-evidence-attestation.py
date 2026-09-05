#!/usr/bin/env python3
"""Build the custom predicate used for generated profile-evidence attestations.

Subject digests are supplied by actions/attest. This predicate records source revision,
workflow identity, immutable predicate-schema identity, published paths,
validation/authority boundaries, the deterministic Signal Field Evidence ID, and the
Portfolio Evidence Ledger identity.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "portyu9/portyu9"
KIND = "profile-evidence-attestation"
SCHEMA_VERSION = 2
PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "profile-evidence-v2.schema.json"
)
PREDICATE_SCHEMA = ROOT / ".github/attestation/profile-evidence-v2.schema.json"
BOUNDARY = "attest-validated-evidence"
EVIDENCE_SCHEMA = "signal-field-evidence-v1"
PORTFOLIO_LEDGER_VERSION = "portfolio-evidence-ledger-v1"
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
PORTFOLIO_EVIDENCE_ID = re.compile(r"^PL1-[0-9A-F]{16}$")
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')

PUBLISHED_PATHS = (
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
)
SIGNAL_FIELD_FILENAMES = tuple(Path(path).name for path in PUBLISHED_PATHS[:4])
SIGNAL_FIELD_VALIDATORS = (
    "scripts/validate-signal-field-v213.py",
    "scripts/validate-signal-field-v214.py",
    "scripts/validate-generated-signal-field.py",
)
SPOTLIGHT_VALIDATORS = (
    "scripts/validate-engineering-spotlight.py --require-live",
)
PORTFOLIO_LEDGER_VALIDATORS = (
    "scripts/validate-portfolio-evidence-ledger.py --require-live",
)


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
        "run": {
            "id": run_id,
            "attempt": attempt,
            "url": f"{server}/{REPOSITORY}/actions/runs/{run_id}",
        },
        "predicateSchema": predicate_schema_identity(),
        "subjectSet": {
            "name": "generated-profile-evidence",
            "publishedPaths": list(PUBLISHED_PATHS),
        },
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
    if predicate.get("kind") != KIND:
        raise ValueError("attestation kind changed")
    if predicate.get("repository") != REPOSITORY:
        raise ValueError("repository changed")
    revision = predicate.get("sourceRevision")
    if not isinstance(revision, str) or not SHA40.fullmatch(revision):
        raise ValueError("sourceRevision is malformed")

    predicate_schema = predicate.get("predicateSchema")
    if not isinstance(predicate_schema, dict):
        raise ValueError("predicateSchema is missing")
    expected_schema = predicate_schema_identity()
    if predicate_schema != expected_schema:
        raise ValueError("predicate schema identity changed")

    subject_set = predicate.get("subjectSet")
    if not isinstance(subject_set, dict):
        raise ValueError("subjectSet is missing")
    if subject_set.get("name") != "generated-profile-evidence":
        raise ValueError("subject-set name changed")
    paths = subject_set.get("publishedPaths")
    if paths != list(PUBLISHED_PATHS):
        raise ValueError("published subject paths changed")
    if len(set(PUBLISHED_PATHS)) != 11:
        raise ValueError("published subject paths must be eleven unique subjects")

    evidence = predicate.get("signalFieldEvidence")
    if not isinstance(evidence, dict):
        raise ValueError("signalFieldEvidence is missing")
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        raise ValueError("Signal Field Evidence ID schema changed")
    if not isinstance(evidence.get("id"), str) or not EVIDENCE_ID.fullmatch(str(evidence["id"])):
        raise ValueError("Signal Field Evidence ID is malformed")
    if not isinstance(evidence.get("digest"), str) or not EVIDENCE_DIGEST.fullmatch(str(evidence["digest"])):
        raise ValueError("Signal Field evidence digest is malformed")

    portfolio = predicate.get("portfolioEvidenceLedger")
    if not isinstance(portfolio, dict):
        raise ValueError("portfolioEvidenceLedger is missing")
    if portfolio.get("version") != PORTFOLIO_LEDGER_VERSION:
        raise ValueError("Portfolio Evidence Ledger version changed")
    if not isinstance(portfolio.get("id"), str) or not PORTFOLIO_EVIDENCE_ID.fullmatch(str(portfolio["id"])):
        raise ValueError("Portfolio Evidence Ledger ID is malformed")
    if not isinstance(portfolio.get("digest"), str) or not EVIDENCE_DIGEST.fullmatch(str(portfolio["digest"])):
        raise ValueError("Portfolio Evidence Ledger digest is malformed")
    if portfolio.get("systemCount") != 13:
        raise ValueError("Portfolio Evidence Ledger system count changed")

    validation = predicate.get("validation")
    if not isinstance(validation, dict) or validation.get("boundary") != BOUNDARY:
        raise ValueError("validation boundary changed")
    if validation.get("signalField") != list(SIGNAL_FIELD_VALIDATORS):
        raise ValueError("Signal Field validator set changed")
    if validation.get("engineeringSpotlight") != list(SPOTLIGHT_VALIDATORS):
        raise ValueError("Engineering Spotlight validator set changed")
    if validation.get("portfolioEvidenceLedger") != list(PORTFOLIO_LEDGER_VALIDATORS):
        raise ValueError("Portfolio Evidence Ledger validator set changed")

    authority = predicate.get("authority")
    if not isinstance(authority, dict):
        raise ValueError("authority block is missing")
    expected_authority = {
        "generation": "contents:read",
        "attestation": "contents:read,id-token:write,attestations:write",
        "publication": "contents:write",
        "separation": AUTHORITY_SEPARATION,
    }
    if authority != expected_authority:
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
                    "evidence_id": "PL1-0123456789ABCDEF",
                    "evidence_digest": f"sha256:{'b' * 64}",
                    "system_count": 13,
                }
            ),
            encoding="utf-8",
        )
        predicate = build_predicate(fixture_env(), signal_dir, ledger_dir)
        validate_predicate(predicate)
        encoded = json.dumps(predicate, sort_keys=True, separators=(",", ":"))
        reparsed = json.loads(encoded)
        validate_predicate(reparsed)
        if reparsed["run"]["url"] != "https://github.com/portyu9/portyu9/actions/runs/123456789":
            raise AssertionError("workflow run URL changed")
        if reparsed["portfolioEvidenceLedger"]["id"] != "PL1-0123456789ABCDEF":
            raise AssertionError("Portfolio Evidence Ledger ID was not recorded")
        if reparsed["predicateSchema"] != predicate_schema_identity():
            raise AssertionError("predicate schema digest was not recorded")
    print("Profile evidence attestation predicate v2 self-test passed: immutable schema + Signal Field + three Spotlights + Portfolio Evidence Ledger")


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
            f"wrote profile evidence attestation predicate v2: {output} · "
            f"{predicate['signalFieldEvidence']['id']} · {predicate['portfolioEvidenceLedger']['id']} · "
            f"{predicate['predicateSchema']['digest']}"
        )
        return 0
    except (OSError, ValueError, AssertionError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
