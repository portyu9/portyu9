#!/usr/bin/env python3
"""Build the custom predicate used for generated profile-evidence attestations.

The predicate is intentionally small. Subject digests are supplied by actions/attest;
this file records the source revision, workflow identity, validation scope, published
paths, and authority separation under which those subjects were accepted.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys

REPOSITORY = "portyu9/portyu9"
KIND = "profile-evidence-attestation"
SCHEMA_VERSION = 1
BOUNDARY = "attest-validated-evidence"
CLAIM = (
    "Subjects passed repository-defined validation at sourceRevision before publication; "
    "this attests artifact provenance and contract conformance, not universal certification."
)
SHA40 = re.compile(r"^[0-9a-f]{40}$")
DIGITS = re.compile(r"^[0-9]+$")

PUBLISHED_PATHS = (
    "profile-stats/profile/signal-field-wide-light.svg",
    "profile-stats/profile/signal-field-wide-dark.svg",
    "profile-stats/profile/signal-field-compact-light.svg",
    "profile-stats/profile/signal-field-compact-dark.svg",
    "engineering-spotlight/spotlight-1-light.svg",
    "engineering-spotlight/spotlight-1-dark.svg",
    "engineering-spotlight/spotlight-2-light.svg",
    "engineering-spotlight/spotlight-2-dark.svg",
)

SIGNAL_FIELD_VALIDATORS = (
    "scripts/validate-signal-field-v213.py",
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


def build_predicate(env: dict[str, str]) -> dict[str, object]:
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
    if len(set(PUBLISHED_PATHS)) != 8:
        raise ValueError("published subject paths must be eight unique SVGs")

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
    predicate = build_predicate(fixture_env())
    validate_predicate(predicate)
    encoded = json.dumps(predicate, sort_keys=True, separators=(",", ":"))
    reparsed = json.loads(encoded)
    validate_predicate(reparsed)
    if reparsed["run"]["url"] != "https://github.com/portyu9/portyu9/actions/runs/123456789":
        raise AssertionError("workflow run URL changed")
    print("Profile evidence attestation predicate self-test passed: v1")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError(
                "usage: build-profile-evidence-attestation.py <output.json> | --self-test"
            )
        predicate = build_predicate(dict(os.environ))
        validate_predicate(predicate)
        output = Path(sys.argv[1])
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(predicate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"wrote profile evidence attestation predicate: {output}")
        return 0
    except (OSError, ValueError, AssertionError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
