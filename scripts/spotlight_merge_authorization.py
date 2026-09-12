#!/usr/bin/env python3
"""Build the deterministic Spotlight merge authorization certificate and subject."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "portyu9/portyu9"
WORKFLOW_PATH = ".github/workflows/spotlight-link-sync.yml"
WORKFLOW_REF = f"{REPOSITORY}/{WORKFLOW_PATH}@refs/heads/main"
SCHEMA_VERSION = 1
KIND = "spotlight-merge-authorization"
SUBJECT_KIND = "spotlight-merge-authorization-subject"
PREDICATE_TYPE = (
    "https://raw.githubusercontent.com/portyu9/portyu9/main/.github/attestation/"
    "spotlight-merge-authorization-v1.schema.json"
)
PREDICATE_SCHEMA = ROOT / ".github/attestation/spotlight-merge-authorization-v1.schema.json"
BOT_BRANCH_PREFIX = "automation/spotlight-links/"
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
PR_TITLE = "chore: sync rotating Spotlight links"
PR_BODY = (
    "Automation-managed README-only update. Direct Spotlight repository/workflow links "
    "and immutable card snapshot are derived from the validated published evidence. Main "
    "protection and all required checks remain in force."
)
CLAIM = (
    "This certificate authorizes only the exact Spotlight README candidate, PR, workflow-run "
    "provenance, and successful required checks recorded here. It is not a freshness proof and "
    "cannot authorize merge without independent terminal live revalidation and an unexpired "
    "matching mutation lease."
)
WORKFLOW_NAMES = ("CodeQL", "Dependency review", "Profile quality")
CHECK_NAMES = (
    "analyze-actions",
    "analyze-python",
    "dependency-review",
    "integration-pinned-upstream",
    "validate-contracts",
)
CHECK_WORKFLOW = {
    "analyze-actions": "CodeQL",
    "analyze-python": "CodeQL",
    "dependency-review": "Dependency review",
    "integration-pinned-upstream": "Profile quality",
    "validate-contracts": "Profile quality",
}
EXPECTED_RUN_ENV = {
    "CodeQL": ("CODEQL_RUN_ID", "CODEQL_CHECK_SUITE_ID"),
    "Dependency review": ("DEPENDENCY_RUN_ID", "DEPENDENCY_CHECK_SUITE_ID"),
    "Profile quality": ("PROFILE_RUN_ID", "PROFILE_CHECK_SUITE_ID"),
}
SHA40 = re.compile(r"^[0-9a-f]{40}$")
SHA64 = re.compile(r"^[0-9a-f]{64}$")
POSITIVE = re.compile(r"^[1-9][0-9]*$")
BRANCH = re.compile(r"^automation/spotlight-links/[0-9a-f]{64}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"merge authorization JSON contains duplicate key: {key}")
        result[key] = value
    return result


def strict_json(path: Path, label: str) -> dict[str, Any]:
    require(path.is_file() and not path.is_symlink(), f"{label} is missing or aliased: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not strict UTF-8 JSON: {exc}") from exc
    require(isinstance(value, dict), f"{label} root must be an object")
    return value


def env_value(env: dict[str, str], name: str, pattern: re.Pattern[str] | None = None) -> str:
    value = env.get(name, "").strip()
    require(bool(value), f"required environment variable is missing: {name}")
    if pattern is not None:
        require(pattern.fullmatch(value) is not None, f"{name} has invalid canonical form")
    return value


def positive_int(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be one positive integer")
    return value


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def write_canonical(path: Path, value: dict[str, Any]) -> str:
    data = canonical_bytes(value)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def schema_identity() -> dict[str, str]:
    require(PREDICATE_SCHEMA.is_file() and not PREDICATE_SCHEMA.is_symlink(),
            "Spotlight merge authorization schema is missing or aliased")
    return {
        "id": PREDICATE_TYPE,
        "digest": f"sha256:{hashlib.sha256(PREDICATE_SCHEMA.read_bytes()).hexdigest()}",
    }


def expected_transaction(env: dict[str, str]) -> dict[str, str]:
    base = env_value(env, "BASE_SHA", SHA40)
    generated = env_value(env, "GENERATED_SHA", SHA40)
    readme = env_value(env, "README_SHA256_AFTER", SHA64)
    candidate = env_value(env, "LEASE_CANDIDATE_ID", SHA64)
    expected_candidate = hashlib.sha256(f"{base}\n{generated}\n{readme}\n".encode("ascii")).hexdigest()
    require(candidate == expected_candidate,
            "merge authorization candidate identity differs from exact Spotlight candidate")
    issued = env_value(env, "LEASE_ISSUED_AT", POSITIVE)
    expires = env_value(env, "LEASE_EXPIRES_AT", POSITIVE)
    require(int(expires) == int(issued) + 1800,
            "merge authorization lease expiry differs from reviewed 30-minute lifetime")
    return {
        "leaseId": env_value(env, "LEASE_ID", SHA64),
        "candidateId": candidate,
        "issuedAt": issued,
        "expiresAt": expires,
    }


def expected_run_outputs(env: dict[str, str]) -> dict[str, tuple[int, int]]:
    values: dict[str, tuple[int, int]] = {}
    for name, (run_env, suite_env) in EXPECTED_RUN_ENV.items():
        run_id = int(env_value(env, run_env, POSITIVE))
        suite_id = int(env_value(env, suite_env, POSITIVE))
        values[name] = (run_id, suite_id)
    require(len({value[0] for value in values.values()}) == 3,
            "merge authorization workflow run IDs must be unique")
    require(len({value[1] for value in values.values()}) == 3,
            "merge authorization check-suite IDs must be unique")
    return values


def validate_pull_request(value: Any, env: dict[str, str]) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == {
        "number", "title", "body", "baseRef", "headRef", "headSha", "headRepository",
        "maintainerCanModify",
    }, "merge authorization pullRequest shape changed")
    number = positive_int(value["number"], "merge authorization PR number")
    require(str(number) == env_value(env, "PR_NUMBER", POSITIVE),
            "merge authorization PR number differs from approved transaction")
    head = env_value(env, "HEAD_SHA", SHA40)
    branch = env_value(env, "CANDIDATE_BRANCH", BRANCH)
    require(value == {
        "number": number,
        "title": PR_TITLE,
        "body": PR_BODY,
        "baseRef": "main",
        "headRef": branch,
        "headSha": head,
        "headRepository": REPOSITORY,
        "maintainerCanModify": False,
    }, "merge authorization PR identity changed")
    return value


def validate_candidate(value: Any, env: dict[str, str]) -> dict[str, str]:
    require(isinstance(value, dict) and set(value) == {
        "parentSha", "authorName", "authorEmail", "committerName", "committerEmail", "message",
        "readmeSha256",
    }, "merge authorization candidate shape changed")
    expected = {
        "parentSha": env_value(env, "BASE_SHA", SHA40),
        "authorName": BOT_NAME,
        "authorEmail": BOT_EMAIL,
        "committerName": BOT_NAME,
        "committerEmail": BOT_EMAIL,
        "message": PR_TITLE,
        "readmeSha256": env_value(env, "README_SHA256_AFTER", SHA64),
    }
    require(value == expected, "merge authorization candidate topology/identity changed")
    return value


def validate_workflow_runs(value: Any, env: dict[str, str]) -> list[dict[str, Any]]:
    require(isinstance(value, list) and len(value) == 3,
            "merge authorization must contain exactly three workflow runs")
    require(all(isinstance(item, dict) for item in value),
            "merge authorization workflowRuns entries must be objects")
    runs = sorted(value, key=lambda item: item.get("name", ""))
    require(tuple(item.get("name") for item in runs) == WORKFLOW_NAMES,
            "merge authorization workflow-run identities changed")
    expected_outputs = expected_run_outputs(env)
    branch = env_value(env, "CANDIDATE_BRANCH", BRANCH)
    head = env_value(env, "HEAD_SHA", SHA40)
    for item in runs:
        require(set(item) == {
            "name", "workflowId", "runId", "runAttempt", "checkSuiteId", "event", "headBranch",
            "headSha", "repository", "headRepository", "status", "conclusion",
        }, "merge authorization workflow-run shape changed")
        name = item["name"]
        run_id, suite_id = expected_outputs[name]
        positive_int(item["workflowId"], f"{name} workflowId")
        positive_int(item["runId"], f"{name} runId")
        positive_int(item["runAttempt"], f"{name} runAttempt")
        positive_int(item["checkSuiteId"], f"{name} checkSuiteId")
        require(item["runId"] == run_id and item["checkSuiteId"] == suite_id,
                f"merge authorization {name} run/check-suite identity differs from approval output")
        require(item["event"] == "pull_request" and item["headBranch"] == branch and item["headSha"] == head,
                f"merge authorization {name} source identity changed")
        require(item["repository"] == REPOSITORY and item["headRepository"] == REPOSITORY,
                f"merge authorization {name} repository identity changed")
        require(item["status"] == "completed" and item["conclusion"] == "success",
                f"merge authorization {name} is not a successful completed run")
    return runs


def validate_check_runs(value: Any, env: dict[str, str], runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    require(isinstance(value, list) and len(value) == 5,
            "merge authorization must contain exactly five check runs")
    require(all(isinstance(item, dict) for item in value),
            "merge authorization checkRuns entries must be objects")
    checks = sorted(value, key=lambda item: item.get("name", ""))
    require(tuple(item.get("name") for item in checks) == CHECK_NAMES,
            "merge authorization required check-run identities changed")
    head = env_value(env, "HEAD_SHA", SHA40)
    suites = {run["name"]: run["checkSuiteId"] for run in runs}
    for item in checks:
        require(set(item) == {"name", "checkSuiteId", "appId", "status", "conclusion", "headSha"},
                "merge authorization check-run shape changed")
        positive_int(item["checkSuiteId"], f"{item['name']} checkSuiteId")
        require(item["checkSuiteId"] == suites[CHECK_WORKFLOW[item["name"]]],
                f"merge authorization {item['name']} check suite is not bound to its canonical workflow run")
        require(item["appId"] == 15368 and item["status"] == "completed" and item["conclusion"] == "success",
                f"merge authorization {item['name']} GitHub-Actions success identity changed")
        require(item["headSha"] == head, f"merge authorization {item['name']} head SHA changed")
    return checks


def build(state: dict[str, Any], env: dict[str, str]) -> tuple[dict[str, Any], dict[str, Any]]:
    repository = env_value(env, "GITHUB_REPOSITORY")
    workflow_ref = env_value(env, "GITHUB_WORKFLOW_REF")
    source_sha = env_value(env, "GITHUB_SHA", SHA40)
    run_id = env_value(env, "GITHUB_RUN_ID", POSITIVE)
    run_attempt = env_value(env, "GITHUB_RUN_ATTEMPT", POSITIVE)
    server = env_value(env, "GITHUB_SERVER_URL").rstrip("/")
    require(repository == REPOSITORY, "merge authorization repository identity changed")
    require(workflow_ref == WORKFLOW_REF, "merge authorization workflow identity changed")
    require(source_sha == env_value(env, "BASE_SHA", SHA40),
            "merge authorization workflow source SHA differs from transaction base")
    require(server == "https://github.com", "merge authorization GitHub server identity changed")
    require(set(state) == {"pullRequest", "candidate", "workflowRuns", "checkRuns"},
            "merge authorization live-state keys changed")

    pull_request = validate_pull_request(state["pullRequest"], env)
    candidate = validate_candidate(state["candidate"], env)
    runs = validate_workflow_runs(state["workflowRuns"], env)
    checks = validate_check_runs(state["checkRuns"], env, runs)
    transaction = expected_transaction(env)
    branch = env_value(env, "CANDIDATE_BRANCH", BRANCH)
    require(branch == BOT_BRANCH_PREFIX + transaction["candidateId"],
            "merge authorization candidate branch differs from deterministic candidate ID")

    certificate = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": KIND,
        "repository": REPOSITORY,
        "workflowRef": WORKFLOW_REF,
        "run": {"id": run_id, "attempt": run_attempt, "url": f"{server}/{REPOSITORY}/actions/runs/{run_id}"},
        "predicateSchema": schema_identity(),
        "transaction": transaction,
        "source": {
            "mainSha": source_sha,
            "generatedSha": env_value(env, "GENERATED_SHA", SHA40),
            "readmeSha256After": env_value(env, "README_SHA256_AFTER", SHA64),
        },
        "pullRequest": pull_request,
        "candidate": candidate,
        "workflowRuns": runs,
        "checkRuns": checks,
        "claim": CLAIM,
    }
    certificate_sha = hashlib.sha256(canonical_bytes(certificate)).hexdigest()
    subject = {
        "schemaVersion": SCHEMA_VERSION,
        "kind": SUBJECT_KIND,
        "repository": REPOSITORY,
        "transaction": {
            "candidateId": transaction["candidateId"],
            "baseSha": source_sha,
            "generatedSha": certificate["source"]["generatedSha"],
            "headSha": env_value(env, "HEAD_SHA", SHA40),
        },
        "certificateSha256": certificate_sha,
    }
    return certificate, subject


def fixture() -> tuple[dict[str, Any], dict[str, str]]:
    base = "a" * 40
    generated = "b" * 40
    readme = "c" * 64
    candidate_id = hashlib.sha256(f"{base}\n{generated}\n{readme}\n".encode("ascii")).hexdigest()
    head = "d" * 40
    env = {
        "GITHUB_REPOSITORY": REPOSITORY,
        "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
        "GITHUB_SHA": base,
        "GITHUB_RUN_ID": "9001",
        "GITHUB_RUN_ATTEMPT": "2",
        "GITHUB_SERVER_URL": "https://github.com",
        "BASE_SHA": base,
        "GENERATED_SHA": generated,
        "README_SHA256_AFTER": readme,
        "LEASE_ID": "e" * 64,
        "LEASE_CANDIDATE_ID": candidate_id,
        "LEASE_ISSUED_AT": "1000000",
        "LEASE_EXPIRES_AT": "1001800",
        "PR_NUMBER": "123",
        "HEAD_SHA": head,
        "CANDIDATE_BRANCH": BOT_BRANCH_PREFIX + candidate_id,
        "CODEQL_RUN_ID": "2001",
        "CODEQL_CHECK_SUITE_ID": "3001",
        "DEPENDENCY_RUN_ID": "2002",
        "DEPENDENCY_CHECK_SUITE_ID": "3002",
        "PROFILE_RUN_ID": "2003",
        "PROFILE_CHECK_SUITE_ID": "3003",
    }
    branch = env["CANDIDATE_BRANCH"]
    runs = [
        {"name": "CodeQL", "workflowId": 101, "runId": 2001, "runAttempt": 1, "checkSuiteId": 3001,
         "event": "pull_request", "headBranch": branch, "headSha": head, "repository": REPOSITORY,
         "headRepository": REPOSITORY, "status": "completed", "conclusion": "success"},
        {"name": "Dependency review", "workflowId": 102, "runId": 2002, "runAttempt": 1, "checkSuiteId": 3002,
         "event": "pull_request", "headBranch": branch, "headSha": head, "repository": REPOSITORY,
         "headRepository": REPOSITORY, "status": "completed", "conclusion": "success"},
        {"name": "Profile quality", "workflowId": 103, "runId": 2003, "runAttempt": 2, "checkSuiteId": 3003,
         "event": "pull_request", "headBranch": branch, "headSha": head, "repository": REPOSITORY,
         "headRepository": REPOSITORY, "status": "completed", "conclusion": "success"},
    ]
    suites = {run["name"]: run["checkSuiteId"] for run in runs}
    checks = [{"name": name, "checkSuiteId": suites[CHECK_WORKFLOW[name]], "appId": 15368,
               "status": "completed", "conclusion": "success", "headSha": head} for name in CHECK_NAMES]
    state = {
        "pullRequest": {"number": 123, "title": PR_TITLE, "body": PR_BODY, "baseRef": "main",
                        "headRef": branch, "headSha": head, "headRepository": REPOSITORY,
                        "maintainerCanModify": False},
        "candidate": {"parentSha": base, "authorName": BOT_NAME, "authorEmail": BOT_EMAIL,
                      "committerName": BOT_NAME, "committerEmail": BOT_EMAIL, "message": PR_TITLE,
                      "readmeSha256": readme},
        "workflowRuns": runs,
        "checkRuns": checks,
    }
    return state, env


def expect_failure(state: dict[str, Any], env: dict[str, str], expected: str) -> None:
    try:
        build(state, env)
    except ValueError as exc:
        require(expected in str(exc), f"merge authorization self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"merge authorization self-test accepted forbidden drift: {expected}")


def self_test() -> None:
    state, env = fixture()
    certificate, subject = build(copy.deepcopy(state), dict(env))
    require(hashlib.sha256(canonical_bytes(certificate)).hexdigest() == subject["certificateSha256"],
            "merge authorization subject does not bind exact certificate bytes")

    wrong_candidate = dict(env)
    wrong_candidate["LEASE_CANDIDATE_ID"] = "f" * 64
    expect_failure(copy.deepcopy(state), wrong_candidate, "candidate identity")

    mutable_pr = copy.deepcopy(state)
    mutable_pr["pullRequest"]["maintainerCanModify"] = True
    expect_failure(mutable_pr, dict(env), "PR identity changed")

    wrong_suite = copy.deepcopy(state)
    wrong_suite["checkRuns"][0]["checkSuiteId"] = 3002
    expect_failure(wrong_suite, dict(env), "check suite is not bound")

    extra_check = copy.deepcopy(state)
    extra_check["checkRuns"].append(copy.deepcopy(extra_check["checkRuns"][0]))
    expect_failure(extra_check, dict(env), "exactly five check runs")

    failed_run = copy.deepcopy(state)
    failed_run["workflowRuns"][0]["conclusion"] = "failure"
    expect_failure(failed_run, dict(env), "not a successful completed run")

    stale_base = dict(env)
    stale_base["GITHUB_SHA"] = "9" * 40
    expect_failure(copy.deepcopy(state), stale_base, "workflow source SHA differs")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--state", type=Path)
    parser.add_argument("--certificate", type=Path)
    parser.add_argument("--subject", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            print("Spotlight merge authorization builder self-test passed")
            return 0
        require(args.state is not None and args.certificate is not None and args.subject is not None,
                "--state, --certificate, and --subject are required outside --self-test")
        state = strict_json(args.state, "Spotlight merge authorization live state")
        certificate, subject = build(state, dict(os.environ))
        certificate_sha = write_canonical(args.certificate, certificate)
        subject_sha = write_canonical(args.subject, subject)
        require(subject["certificateSha256"] == certificate_sha,
                "written merge authorization subject does not bind written certificate")
        print(json.dumps({"certificateSha256": certificate_sha, "subjectSha256": subject_sha},
                         sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
