#!/usr/bin/env python3
"""Pure exact short-lived mutation-lease identity proof for Automation Decision Receipts."""
from __future__ import annotations

import hashlib
import re
from typing import Any

REPOSITORY = "portyu9/portyu9"
TTL_SECONDS = 1800
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE = re.compile(r"^[1-9][0-9]*$")
WORKFLOW_PATHS = {
    ".github/workflows/profile-stats.yml",
    ".github/workflows/spotlight-link-sync.yml",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def env_value(env: dict[str, str], name: str, pattern: re.Pattern[str] | None = None) -> str:
    value = env.get(name, "").strip()
    require(bool(value), f"required environment variable is missing: {name}")
    if pattern is not None:
        require(pattern.fullmatch(value) is not None, f"{name} has invalid canonical form")
    return value


def identity_bytes(fields: list[str]) -> bytes:
    return ("\n".join(fields) + "\n").encode("utf-8")


def expected_lease_id(
    *,
    repository: str,
    repository_id: str,
    workflow_path: str,
    workflow_ref: str,
    workflow_sha: str,
    run_id: str,
    run_attempt: str,
    base_sha: str,
    candidate_id: str,
    issued_at: str,
    expires_at: str,
) -> str:
    require(workflow_path in WORKFLOW_PATHS,
            "Automation Decision Receipt lease workflow path is unreviewed")
    fields = [
        repository,
        repository_id,
        workflow_path,
        workflow_ref,
        workflow_sha,
        run_id,
        run_attempt,
        base_sha,
        candidate_id,
        issued_at,
        expires_at,
    ]
    return hashlib.sha256(identity_bytes(fields)).hexdigest()


def validate(env: dict[str, str], workflow_path: str) -> dict[str, str]:
    require(workflow_path in WORKFLOW_PATHS,
            "Automation Decision Receipt lease workflow path is unreviewed")
    repository = env_value(env, "GITHUB_REPOSITORY")
    require(repository == REPOSITORY,
            "Automation Decision Receipt lease repository identity changed")
    repository_id = env_value(env, "GITHUB_REPOSITORY_ID", POSITIVE)
    workflow_ref = env_value(env, "GITHUB_WORKFLOW_REF")
    expected_ref = f"{REPOSITORY}/{workflow_path}@refs/heads/main"
    require(workflow_ref == expected_ref,
            "Automation Decision Receipt lease workflow ref changed")
    workflow_sha = env_value(env, "GITHUB_WORKFLOW_SHA", SHA40)
    base_sha = env_value(env, "LEASE_BASE_SHA", SHA40)
    require(env_value(env, "GITHUB_SHA", SHA40) == base_sha,
            "Automation Decision Receipt lease event source SHA differs from leased base")
    require(workflow_sha == base_sha,
            "Automation Decision Receipt lease workflow source SHA differs from leased base")
    run_id = env_value(env, "GITHUB_RUN_ID", POSITIVE)
    run_attempt = env_value(env, "GITHUB_RUN_ATTEMPT", POSITIVE)
    candidate_id = env_value(env, "LEASE_CANDIDATE_ID", SHA64)
    issued_at = env_value(env, "LEASE_ISSUED_AT", POSITIVE)
    expires_at = env_value(env, "LEASE_EXPIRES_AT", POSITIVE)
    require(int(expires_at) == int(issued_at) + TTL_SECONDS,
            "Automation Decision Receipt lease expiry differs from reviewed 30-minute lifetime")
    lease_id = env_value(env, "LEASE_ID", SHA64)
    expected = expected_lease_id(
        repository=repository,
        repository_id=repository_id,
        workflow_path=workflow_path,
        workflow_ref=workflow_ref,
        workflow_sha=workflow_sha,
        run_id=run_id,
        run_attempt=run_attempt,
        base_sha=base_sha,
        candidate_id=candidate_id,
        issued_at=issued_at,
        expires_at=expires_at,
    )
    require(lease_id == expected,
            "Automation Decision Receipt lease ID differs from exact canonical lease identity")
    return {
        "leaseId": lease_id,
        "candidateId": candidate_id,
        "baseSha": base_sha,
        "issuedAt": issued_at,
        "expiresAt": expires_at,
    }


def fixture(workflow_path: str) -> dict[str, str]:
    require(workflow_path in WORKFLOW_PATHS, "lease fixture workflow path is unreviewed")
    base = "a" * 40
    candidate = "b" * 64
    env = {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_REPOSITORY_ID": "1355082509",
        "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/{workflow_path}@refs/heads/main",
        "GITHUB_WORKFLOW_SHA": base,
        "GITHUB_SHA": base,
        "GITHUB_RUN_ID": "9001",
        "GITHUB_RUN_ATTEMPT": "2",
        "LEASE_CANDIDATE_ID": candidate,
        "LEASE_BASE_SHA": base,
        "LEASE_ISSUED_AT": "1000000",
        "LEASE_EXPIRES_AT": "1001800",
    }
    env["LEASE_ID"] = expected_lease_id(
        repository=env["GITHUB_REPOSITORY"],
        repository_id=env["GITHUB_REPOSITORY_ID"],
        workflow_path=workflow_path,
        workflow_ref=env["GITHUB_WORKFLOW_REF"],
        workflow_sha=env["GITHUB_WORKFLOW_SHA"],
        run_id=env["GITHUB_RUN_ID"],
        run_attempt=env["GITHUB_RUN_ATTEMPT"],
        base_sha=env["LEASE_BASE_SHA"],
        candidate_id=env["LEASE_CANDIDATE_ID"],
        issued_at=env["LEASE_ISSUED_AT"],
        expires_at=env["LEASE_EXPIRES_AT"],
    )
    return env


def self_test() -> None:
    for path in sorted(WORKFLOW_PATHS):
        env = fixture(path)
        observed = validate(dict(env), path)
        require(observed["leaseId"] == env["LEASE_ID"],
                "Automation Decision Receipt lease self-test lost exact lease identity")

        wrong_attempt = dict(env)
        wrong_attempt["GITHUB_RUN_ATTEMPT"] = "3"
        try:
            validate(wrong_attempt, path)
        except ValueError as exc:
            require("lease ID differs" in str(exc),
                    f"Automation Decision Receipt lease run-attempt self-test failed for wrong reason: {exc}")
        else:
            raise ValueError("Automation Decision Receipt lease accepted a mismatched run attempt")

        wrong_repo_id = dict(env)
        wrong_repo_id["GITHUB_REPOSITORY_ID"] = "1"
        try:
            validate(wrong_repo_id, path)
        except ValueError as exc:
            require("lease ID differs" in str(exc),
                    f"Automation Decision Receipt lease repository-id self-test failed for wrong reason: {exc}")
        else:
            raise ValueError("Automation Decision Receipt lease accepted a mismatched repository id")

        wrong_lease = dict(env)
        wrong_lease["LEASE_ID"] = "f" * 64
        try:
            validate(wrong_lease, path)
        except ValueError as exc:
            require("lease ID differs" in str(exc),
                    f"Automation Decision Receipt lease-id self-test failed for wrong reason: {exc}")
        else:
            raise ValueError("Automation Decision Receipt lease accepted an arbitrary lease id")


if __name__ == "__main__":
    try:
        self_test()
        print("Automation Decision Receipt exact mutation-lease identity self-test passed")
    except ValueError as exc:
        print(f"ERROR: {exc}")
        raise SystemExit(1)
