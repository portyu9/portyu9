#!/usr/bin/env python3
"""Independently re-prove live Spotlight merge state and emit deterministic builder input."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any

REPOSITORY = "portyu9/portyu9"
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
PR_TITLE = "chore: sync rotating Spotlight links"
PR_BODY = (
    "Automation-managed README-only update. Direct Spotlight repository/workflow links "
    "and immutable card snapshot are derived from the validated published evidence. Main "
    "protection and all required checks remain in force."
)
WORKFLOWS = {
    "CodeQL": "codeql.yml",
    "Dependency review": "dependency-review.yml",
    "Profile quality": "profile-quality.yml",
}
TRUSTED_WORKFLOW_NAME = "Capability admission"
TRUSTED_WORKFLOW_FILE = "capability-admission.yml"
TRUSTED_CHECK_NAME = "trusted-capability-admission"
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
RUN_ENV = {
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


def env_value(name: str, pattern: re.Pattern[str] | None = None) -> str:
    value = os.environ.get(name, "").strip()
    require(bool(value), f"required environment variable is missing: {name}")
    if pattern is not None:
        require(pattern.fullmatch(value) is not None, f"{name} has invalid canonical form")
    return value


def gh_json(endpoint: str) -> Any:
    require(not endpoint.startswith("-"), "GitHub API endpoint must be one read-only path")
    completed = subprocess.run(
        ["gh", "api", endpoint],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"GitHub API returned invalid JSON for {endpoint}: {exc}") from exc


def positive(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be one positive integer")
    return value


def prepare_state() -> dict[str, Any]:
    require(env_value("GITHUB_REPOSITORY") == REPOSITORY, "unexpected Spotlight repository")
    base = env_value("BASE_SHA", SHA40)
    generated = env_value("GENERATED_SHA", SHA40)
    readme = env_value("README_SHA256_AFTER", SHA64)
    head = env_value("HEAD_SHA", SHA40)
    branch = env_value("CANDIDATE_BRANCH", BRANCH)
    pr_number = int(env_value("PR_NUMBER", POSITIVE))

    candidate_id = hashlib.sha256(f"{base}\n{generated}\n{readme}\n".encode("ascii")).hexdigest()
    require(branch == f"automation/spotlight-links/{candidate_id}",
            "Spotlight authorization candidate branch differs from deterministic candidate")

    main_ref = gh_json(f"repos/{REPOSITORY}/git/ref/heads/main")
    generated_ref = gh_json(f"repos/{REPOSITORY}/git/ref/heads/generated")
    candidate_ref = gh_json(f"repos/{REPOSITORY}/git/ref/heads/{branch}")
    require(main_ref.get("object", {}).get("sha") == base, "Spotlight authorization main SHA is stale")
    require(generated_ref.get("object", {}).get("sha") == generated,
            "Spotlight authorization generated SHA is stale")
    require(candidate_ref.get("object", {}).get("sha") == head,
            "Spotlight authorization candidate ref moved")

    pr = gh_json(f"repos/{REPOSITORY}/pulls/{pr_number}")
    expected_pr = {
        "number": pr_number,
        "title": PR_TITLE,
        "body": PR_BODY,
        "baseRef": "main",
        "headRef": branch,
        "headSha": head,
        "headRepository": REPOSITORY,
        "maintainerCanModify": False,
    }
    observed_pr = {
        "number": pr.get("number"),
        "title": pr.get("title"),
        "body": pr.get("body"),
        "baseRef": pr.get("base", {}).get("ref"),
        "headRef": pr.get("head", {}).get("ref"),
        "headSha": pr.get("head", {}).get("sha"),
        "headRepository": pr.get("head", {}).get("repo", {}).get("full_name"),
        "maintainerCanModify": pr.get("maintainer_can_modify"),
    }
    require(pr.get("state") == "open" and observed_pr == expected_pr,
            "Spotlight authorization PR identity changed")

    files = gh_json(f"repos/{REPOSITORY}/pulls/{pr_number}/files?per_page=100")
    require(isinstance(files, list) and len(files) == 1 and files[0].get("filename") == "README.md"
            and files[0].get("status") == "modified",
            "Spotlight authorization PR must remain exactly one modified README")

    commit = gh_json(f"repos/{REPOSITORY}/git/commits/{head}")
    parents = commit.get("parents")
    require(isinstance(parents, list) and len(parents) == 1 and parents[0].get("sha") == base,
            "Spotlight authorization candidate parent changed")
    candidate = {
        "parentSha": base,
        "authorName": commit.get("author", {}).get("name"),
        "authorEmail": commit.get("author", {}).get("email"),
        "committerName": commit.get("committer", {}).get("name"),
        "committerEmail": commit.get("committer", {}).get("email"),
        "message": commit.get("message"),
        "readmeSha256": readme,
    }
    require(candidate == {
        "parentSha": base,
        "authorName": BOT_NAME,
        "authorEmail": BOT_EMAIL,
        "committerName": BOT_NAME,
        "committerEmail": BOT_EMAIL,
        "message": PR_TITLE,
        "readmeSha256": readme,
    }, "Spotlight authorization candidate bot identity changed")

    compare = gh_json(f"repos/{REPOSITORY}/compare/{base}...{head}")
    require(compare.get("status") == "ahead" and compare.get("base_commit", {}).get("sha") == base
            and compare.get("merge_base_commit", {}).get("sha") == base
            and compare.get("ahead_by") == 1 and compare.get("behind_by") == 0
            and compare.get("total_commits") == 1,
            "Spotlight authorization candidate topology changed")
    compare_files = compare.get("files")
    require(isinstance(compare_files, list) and len(compare_files) == 1
            and compare_files[0].get("filename") == "README.md"
            and compare_files[0].get("status") == "modified",
            "Spotlight authorization compare surface changed")

    readme_payload = gh_json(f"repos/{REPOSITORY}/contents/README.md?ref={head}")
    encoded = readme_payload.get("content")
    require(isinstance(encoded, str), "Spotlight authorization candidate README content is missing")
    try:
        readme_bytes = base64.b64decode(encoded.replace("\n", ""), validate=True)
    except ValueError as exc:
        raise ValueError("Spotlight authorization candidate README is not canonical base64") from exc
    require(hashlib.sha256(readme_bytes).hexdigest() == readme,
            "Spotlight authorization candidate README digest changed")

    workflow_ids: dict[str, int] = {}
    for name, filename in WORKFLOWS.items():
        workflow = gh_json(f"repos/{REPOSITORY}/actions/workflows/{filename}")
        workflow_ids[name] = positive(workflow.get("id"), f"{name} workflow ID")
    trusted_workflow = gh_json(f"repos/{REPOSITORY}/actions/workflows/{TRUSTED_WORKFLOW_FILE}")
    trusted_workflow_id = positive(trusted_workflow.get("id"), "Capability admission workflow ID")

    runs_payload = gh_json(f"repos/{REPOSITORY}/actions/runs?head_sha={head}&event=pull_request&per_page=100")
    total = runs_payload.get("total_count")
    runs = runs_payload.get("workflow_runs")
    require(type(total) is int and isinstance(runs, list) and total == len(runs) == 3,
            "Spotlight authorization workflow-run response is incomplete or ambiguous")
    expected_outputs = {
        name: (int(env_value(run_env, POSITIVE)), int(env_value(suite_env, POSITIVE)))
        for name, (run_env, suite_env) in RUN_ENV.items()
    }
    workflow_runs: list[dict[str, Any]] = []
    for name in sorted(WORKFLOWS):
        matches = [run for run in runs if run.get("name") == name and run.get("workflow_id") == workflow_ids[name]]
        require(len(matches) == 1, f"Spotlight authorization canonical workflow run changed: {name}")
        run = matches[0]
        run_id = positive(run.get("id"), f"{name} run ID")
        suite_id = positive(run.get("check_suite_id"), f"{name} check suite ID")
        attempt = positive(run.get("run_attempt"), f"{name} run attempt")
        require((run_id, suite_id) == expected_outputs[name],
                f"Spotlight authorization {name} run/check-suite differs from approval output")
        item = {
            "name": name,
            "workflowId": workflow_ids[name],
            "runId": run_id,
            "runAttempt": attempt,
            "checkSuiteId": suite_id,
            "event": run.get("event"),
            "headBranch": run.get("head_branch"),
            "headSha": run.get("head_sha"),
            "repository": run.get("repository", {}).get("full_name"),
            "headRepository": run.get("head_repository", {}).get("full_name"),
            "status": run.get("status"),
            "conclusion": run.get("conclusion"),
        }
        require(item["event"] == "pull_request" and item["headBranch"] == branch and item["headSha"] == head
                and item["repository"] == REPOSITORY and item["headRepository"] == REPOSITORY
                and item["status"] == "completed" and item["conclusion"] == "success",
                f"Spotlight authorization {name} run provenance changed")
        workflow_runs.append(item)

    expected_trusted_external_id = f"spotlight-admission:{pr_number}:{base}:{head}"
    trusted_check: dict[str, Any] | None = None
    checks: list[dict[str, Any]] = []
    for attempt in range(1, 25):
        checks_payload = gh_json(f"repos/{REPOSITORY}/commits/{head}/check-runs?filter=latest&per_page=100")
        checks_total = checks_payload.get("total_count")
        observed_checks = checks_payload.get("check_runs")
        require(type(checks_total) is int and isinstance(observed_checks, list)
                and checks_total == len(observed_checks),
                "Spotlight authorization check-run response is incomplete")
        checks = observed_checks
        trusted_matches = [
            check for check in checks
            if check.get("app", {}).get("id") == 15368
            and check.get("name") == TRUSTED_CHECK_NAME
            and check.get("head_sha") == head
            and check.get("external_id") == expected_trusted_external_id
        ]
        require(len(trusted_matches) <= 1,
                "Spotlight trusted admission exact proof is ambiguous")
        if trusted_matches:
            trusted_check = trusted_matches[0]
            if trusted_check.get("status") == "completed":
                break
        if attempt == 24:
            break
        time.sleep(5)
    require(trusted_check is not None,
            "Spotlight trusted admission exact proof did not materialize")
    require(trusted_check.get("status") == "completed" and trusted_check.get("conclusion") == "success",
            "Spotlight trusted admission exact proof is not successful")

    trusted_details_url = trusted_check.get("details_url")
    require(isinstance(trusted_details_url, str), "Spotlight trusted admission details URL is missing")
    trusted_details_match = re.fullmatch(
        rf"https://github\\.com/{re.escape(REPOSITORY)}/actions/runs/([1-9][0-9]*)",
        trusted_details_url,
    )
    require(trusted_details_match is not None,
            "Spotlight trusted admission details URL is not canonical")
    trusted_run_id = int(trusted_details_match.group(1))
    trusted_run = gh_json(f"repos/{REPOSITORY}/actions/runs/{trusted_run_id}")
    require(trusted_run.get("name") == TRUSTED_WORKFLOW_NAME
            and trusted_run.get("workflow_id") == trusted_workflow_id,
            "Spotlight trusted admission canonical workflow run changed")
    require(trusted_run.get("event") == "workflow_dispatch"
            and trusted_run.get("head_branch") == "main"
            and trusted_run.get("head_sha") == base,
            "Spotlight trusted admission source identity changed")
    require(trusted_run.get("path") == ".github/workflows/capability-admission.yml",
            "Spotlight trusted admission workflow path changed")
    require(trusted_run.get("repository", {}).get("full_name") == REPOSITORY
            and trusted_run.get("head_repository", {}).get("full_name") == REPOSITORY,
            "Spotlight trusted admission repository identity changed")
    require(trusted_run.get("actor", {}).get("login") == BOT_NAME
            and trusted_run.get("triggering_actor", {}).get("login") == BOT_NAME,
            "Spotlight trusted admission actor identity changed")
    require(trusted_run.get("status") == "completed" and trusted_run.get("conclusion") == "success",
            "Spotlight trusted admission workflow is not successful")
    trusted_run_item = {
        "name": TRUSTED_WORKFLOW_NAME,
        "workflowId": trusted_workflow_id,
        "runId": positive(trusted_run.get("id"), "Capability admission run ID"),
        "runAttempt": positive(trusted_run.get("run_attempt"), "Capability admission run attempt"),
        "checkSuiteId": positive(trusted_run.get("check_suite_id"), "Capability admission check suite ID"),
        "event": trusted_run.get("event"),
        "headBranch": trusted_run.get("head_branch"),
        "headSha": trusted_run.get("head_sha"),
        "repository": trusted_run.get("repository", {}).get("full_name"),
        "headRepository": trusted_run.get("head_repository", {}).get("full_name"),
        "status": trusted_run.get("status"),
        "conclusion": trusted_run.get("conclusion"),
    }

    actions_checks = [check for check in checks if check.get("app", {}).get("id") == 15368]
    suite_by_workflow = {item["name"]: item["checkSuiteId"] for item in workflow_runs}
    check_runs: list[dict[str, Any]] = []
    for name in CHECK_NAMES:
        matches = [check for check in actions_checks if check.get("name") == name]
        require(len(matches) == 1, f"Spotlight authorization check run is ambiguous: {name}")
        check = matches[0]
        suite = positive(check.get("check_suite", {}).get("id"), f"{name} check suite ID")
        require(suite == suite_by_workflow[CHECK_WORKFLOW[name]],
                f"Spotlight authorization {name} check suite differs from canonical workflow run")
        item = {
            "name": name,
            "checkSuiteId": suite,
            "appId": check.get("app", {}).get("id"),
            "status": check.get("status"),
            "conclusion": check.get("conclusion"),
            "headSha": check.get("head_sha"),
        }
        require(item["status"] == "completed" and item["conclusion"] == "success" and item["headSha"] == head,
                f"Spotlight authorization required check is not successful on exact head: {name}")
        check_runs.append(item)

    trusted_check_item = {
        "name": TRUSTED_CHECK_NAME,
        "checkRunId": positive(trusted_check.get("id"), "trusted capability admission check run ID"),
        "checkSuiteId": positive(trusted_check.get("check_suite", {}).get("id"),
                                 "trusted capability admission check suite ID"),
        "appId": trusted_check.get("app", {}).get("id"),
        "status": trusted_check.get("status"),
        "conclusion": trusted_check.get("conclusion"),
        "headSha": trusted_check.get("head_sha"),
        "externalId": trusted_check.get("external_id"),
        "detailsUrl": trusted_details_url,
    }
    require(trusted_check_item["appId"] == 15368
            and trusted_check_item["status"] == "completed"
            and trusted_check_item["conclusion"] == "success"
            and trusted_check_item["headSha"] == head
            and trusted_check_item["externalId"] == expected_trusted_external_id,
            "Spotlight trusted admission check success identity changed")

    return {
        "pullRequest": expected_pr,
        "candidate": candidate,
        "workflowRuns": workflow_runs,
        "checkRuns": check_runs,
        "trustedAdmission": {
            "workflowRun": trusted_run_item,
            "checkRun": trusted_check_item,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        state = prepare_state()
        args.output.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        print(f"Spotlight merge authorization live state verified: {args.output}")
        return 0
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
