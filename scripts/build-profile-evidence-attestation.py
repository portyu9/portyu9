#!/usr/bin/env python3
"""Build the custom predicate used for generated profile-evidence attestations.

Subject digests are supplied by actions/attest. This predicate records source revision,
workflow identity, published paths, validation/authority boundaries, and the deterministic
Signal Field Evidence ID shared by the four attested Signal Field variants.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
import tempfile

REPOSITORY = "portyu9/portyu9"
KIND = "profile-evidence-attestation"
SCHEMA_VERSION = 1
BOUNDARY = "attest-validated-evidence"
EVIDENCE_SCHEMA = "signal-field-evidence-v1"
CLAIM = (
    "Subjects passed repository-defined validation at sourceRevision before publication; "
    "this attests artifact provenance and contract conformance, not universal certification."
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGITS = re.compile(r"^[0-9]+$")
EVIDENCE_ID = re.compile(r"^SF1-[0-9A-F]{16}$")
EVIDENCE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
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


def required_env(name: str, env: dict[str, str]) -> str:
    value = env.get(name, "").strip()
    if not value:
        raise ValueError(f"required environment variable is missing: {name}")
    return value


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


def build_predicate(env: dict[str, str], signal_field_dir: Path) -> dict[str, object]:
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
        "subjectSet": {
            "name": "generated-profile-evidence",
            "publishedPaths": list(PUBLISHED_PATHS),
        },
        "signalFieldEvidence": read_signal_field_evidence(signal_field_dir),
        "validation": {
            "signalField": list(SIGNAL_FIELD_VALIDATORS),
            "engineeringSpotlight": list(SPOTLIGHT_VALIDATORS),
            "boundary": BOUNDARY,
        },
        "authority": {
            "generation": "contents:read",
            "attestation": "contents:read,id-token:write,attestations:write",
            "publication": "contents:write",
            "separation": (
                "Generation, attestation, and publication run as distinct jobs; third-party "
                "generation code has neither repository-write nor attestation authority."
            ),
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

    subject_set = predicate.get("subjectSet")
    if not isinstance(subject_set, dict):
        raise ValueError("subjectSet is missing")
    if subject_set.get("name") != "generated-profile-evidence":
        raise ValueError("subject-set name changed")
    paths = subject_set.get("publishedPaths")
    if paths != list(PUBLISHED_PATHS):
        raise ValueError("published subject paths changed")
    if len(set(PUBLISHED_PATHS)) != 10:
        raise ValueError("published subject paths must be ten unique SVGs")

    evidence = predicate.get("signalFieldEvidence")
    if not isinstance(evidence, dict):
        raise ValueError("signalFieldEvidence is missing")
    if evidence.get("schema") != EVIDENCE_SCHEMA:
        raise ValueError("Signal Field Evidence ID schema changed")
    if not isinstance(evidence.get("id"), str) or not EVIDENCE_ID.fullmatch(str(evidence["id"])):
        raise ValueError("Signal Field Evidence ID is malformed")
    if not isinstance(evidence.get("digest"), str) or not EVIDENCE_DIGEST.fullmatch(str(evidence["digest"])):
        raise ValueError("Signal Field evidence digest is malformed")

    validation = predicate.get("validation")
    if not isinstance(validation, dict) or validation.get("boundary") != BOUNDARY:
        raise ValueError("validation boundary changed")
    if validation.get("signalField") != list(SIGNAL_FIELD_VALIDATORS):
        raise ValueError("Signal Field validator set changed")
    if validation.get("engineeringSpotlight") != list(SPOTLIGHT_VALIDATORS):
        raise ValueError("Engineering Spotlight validator set changed")

    authority = predicate.get("authority")
    if not isinstance(authority, dict):
        raise ValueError("authority block is missing")
    expected_authority = {
        "generation": "contents:read",
        "attestation": "contents:read,id-token:write,attestations:write",
        "publication": "contents:write",
    }
    for key, expected in expected_authority.items():
        if authority.get(key) != expected:
            raise ValueError(f"authority contract changed for {key}")
    if not isinstance(authority.get("separation"), str) or not authority["separation"]:
        raise ValueError("authority separation statement is missing")
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
        directory = Path(tmp)
        for filename in SIGNAL_FIELD_FILENAMES:
            (directory / filename).write_text(
                '<svg data-evidence-identity="signal-field-v2.14" '
                'data-evidence-id-schema="signal-field-evidence-v1" '
                'data-evidence-id="SF1-0123456789ABCDEF" '
                f'data-evidence-digest="sha256:{"a" * 64}"></svg>',
                encoding="utf-8",
            )
        predicate = build_predicate(fixture_env(), directory)
        validate_predicate(predicate)
        encoded = json.dumps(predicate, sort_keys=True, separators=(",", ":"))
        reparsed = json.loads(encoded)
        validate_predicate(reparsed)
        if reparsed["run"]["url"] != "https://github.com/portyu9/portyu9/actions/runs/123456789":
            raise AssertionError("workflow run URL changed")
        if reparsed["signalFieldEvidence"]["id"] != "SF1-0123456789ABCDEF":
            raise AssertionError("Signal Field Evidence ID was not recorded")
    print("Profile evidence attestation predicate self-test passed: v1 + Signal Field Evidence ID + three Spotlight slots")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 3:
            raise ValueError(
                "usage: build-profile-evidence-attestation.py <signal-field-directory> <output.json> | --self-test"
            )
        signal_field_dir = Path(sys.argv[1])
        predicate = build_predicate(dict(os.environ), signal_field_dir)
        validate_predicate(predicate)
        output = Path(sys.argv[2])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(predicate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            f"wrote profile evidence attestation predicate: {output} · "
            f"{predicate['signalFieldEvidence']['id']}"
        )
        return 0
    except (OSError, ValueError, AssertionError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
