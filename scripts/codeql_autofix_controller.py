#!/usr/bin/env python3
"""Pure data-plane helpers for the trusted CodeQL Autofix controller.

This module performs no network calls and no repository mutation. The production workflow owns
all GitHub API calls explicitly in YAML so Workflow Capability BOM inspection can see every
read/write surface. This module only validates untrusted API response data, creates deterministic
receipt bytes, and decides whether an existing Autofix PR is eligible for protected auto-merge.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Mapping

import codeql_autofix_admission as admission
import codeql_autofix_controller_contract as contract
import codeql_autofix_discovery as discovery

REPOSITORY = contract.REPOSITORY
DEFAULT_BRANCH = contract.DEFAULT_BRANCH
DEFAULT_REF = f"refs/heads/{DEFAULT_BRANCH}"
GHAS_APP_ID = 57789
SHA40 = re.compile(r"^[0-9a-f]{40}$")
BRANCH_RE = re.compile(r"^codeql-autofix/alert-(?P<alert>[1-9][0-9]*)/run-(?P<run>[1-9][0-9]*)$")


class ControllerError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ControllerError(message)


def load(path: str) -> Any:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def dump(path: str, value: Any) -> None:
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n", encoding="utf-8")


def sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None, f"{label} must be a lowercase SHA-40")
    return value


def positive_int(value: Any, label: str) -> int:
    require(type(value) is int and value > 0, f"{label} must be a positive integer")
    return value


def validate_trigger(event_name: str, event: Any, trusted_sha: str) -> dict[str, Any]:
    trusted_sha = sha(trusted_sha, "trusted_sha")
    require(event_name in contract.ALLOWED_EVENTS, "controller event is not allowed")
    require(isinstance(event, Mapping), "event payload must be an object")
    if event_name == "workflow_run":
        run = event.get("workflow_run")
        require(isinstance(run, Mapping), "workflow_run payload is missing")
        require(run.get("name") == contract.CODEQL_WORKFLOW_NAME, "workflow_run source is not CodeQL")
        require(run.get("conclusion") == "success", "CodeQL source workflow did not succeed")
        require(run.get("head_branch") == DEFAULT_BRANCH, "CodeQL source workflow did not analyze main")
        require(run.get("head_sha") == trusted_sha, "CodeQL source workflow is stale relative to trusted controller SHA")
    elif event_name == "repository_dispatch":
        require(event.get("action") == contract.DISPATCH_TYPE, "repository_dispatch action mismatch")
    return {"event": event_name, "trustedSha": trusted_sha}


WORKFLOW_DEFINITION_IDENTITIES = {
    ".github/workflows/codeql.yml": "CodeQL",
    ".github/workflows/dependency-review.yml": "Dependency review",
    ".github/workflows/profile-quality.yml": "Profile quality",
}


def validate_read_ref_response(value: Any, expected_ref: str, expected_sha: str) -> dict[str, Any]:
    require(
        isinstance(expected_ref, str)
        and expected_ref.startswith("refs/heads/")
        and expected_ref != "refs/heads/",
        "Autofix read-ref expected ref must be a concrete heads ref",
    )
    expected_sha = sha(expected_sha, "Autofix read-ref expected SHA")
    require(isinstance(value, Mapping), "Autofix read-ref response must be an object")
    require(value.get("ref") == expected_ref, "Autofix read-ref response identity mismatch")
    obj = value.get("object")
    require(isinstance(obj, Mapping), "Autofix read-ref response object must be an object")
    require(obj.get("type") == "commit", "Autofix read-ref response object type changed")
    observed = sha(obj.get("sha"), "Autofix read-ref response SHA")
    require(observed == expected_sha, "Autofix read-ref response SHA mismatch")
    object_url = obj.get("url")
    require(
        isinstance(object_url, str) and bool(object_url.strip()),
        "Autofix read-ref response object URL must be a non-empty string",
    )
    return {"ref": expected_ref, "sha": observed, "objectUrl": object_url}


def validate_workflow_definition_response(value: Any, expected_path: str) -> dict[str, Any]:
    require(
        isinstance(expected_path, str) and expected_path in WORKFLOW_DEFINITION_IDENTITIES,
        "Autofix workflow-definition expected path is outside reviewed identity set",
    )
    expected_name = WORKFLOW_DEFINITION_IDENTITIES[expected_path]
    require(isinstance(value, Mapping), "Autofix workflow-definition response must be an object")
    workflow_id = positive_int(value.get("id"), "Autofix workflow-definition id")
    require(value.get("path") == expected_path, "Autofix workflow-definition path mismatch")
    require(value.get("name") == expected_name, "Autofix workflow-definition name mismatch")
    require(value.get("state") == "active", "Autofix workflow-definition state changed")
    for key in ("url", "html_url"):
        observed = value.get(key)
        require(
            isinstance(observed, str) and bool(observed.strip()),
            f"Autofix workflow-definition {key} must be a non-empty string",
        )
    return {
        "id": workflow_id,
        "path": expected_path,
        "name": expected_name,
        "state": "active",
    }


PROTECTED_PR_RUN_STATUSES = {"queued", "in_progress", "requested", "waiting", "pending", "completed"}
PROTECTED_PR_RUN_CONCLUSIONS = {
    "success",
    "failure",
    "neutral",
    "cancelled",
    "skipped",
    "timed_out",
    "action_required",
    "stale",
    "startup_failure",
    "waiting",
}


def validate_protected_workflow_runs_response(
    value: Any,
    *,
    expected_sha: str,
    branch: str,
    codeql_workflow_id: int,
    dependency_workflow_id: int,
    profile_workflow_id: int,
) -> dict[str, Any]:
    expected_sha = sha(expected_sha, "Autofix protected workflow-run head SHA")
    require(
        isinstance(branch, str) and BRANCH_RE.fullmatch(branch) is not None,
        "Autofix protected workflow-run branch identity is malformed",
    )
    codeql_workflow_id = positive_int(codeql_workflow_id, "Autofix CodeQL workflow id")
    dependency_workflow_id = positive_int(
        dependency_workflow_id, "Autofix Dependency Review workflow id"
    )
    profile_workflow_id = positive_int(
        profile_workflow_id, "Autofix Profile Quality workflow id"
    )
    expected_workflows = {
        codeql_workflow_id: (".github/workflows/codeql.yml", "CodeQL"),
        dependency_workflow_id: (".github/workflows/dependency-review.yml", "Dependency review"),
        profile_workflow_id: (".github/workflows/profile-quality.yml", "Profile quality"),
    }
    require(
        len(expected_workflows) == 3,
        "Autofix protected workflow ids must be three distinct positive identities",
    )

    require(isinstance(value, Mapping), "Autofix protected workflow-run response must be an object")
    total_count = value.get("total_count")
    require(
        type(total_count) is int and 0 <= total_count <= 100,
        "Autofix protected workflow-run total_count must be an integer in [0,100]",
    )
    raw_runs = value.get("workflow_runs")
    require(
        isinstance(raw_runs, list) and len(raw_runs) <= 100,
        "Autofix protected workflow_runs must be an array with at most 100 entries",
    )
    require(
        total_count == len(raw_runs),
        "Autofix protected workflow-run total_count does not match returned array length",
    )

    seen_run_ids: set[int] = set()
    seen_check_suite_ids: set[int] = set()
    seen_workflow_ids: set[int] = set()
    runs: list[dict[str, Any]] = []
    for raw in raw_runs:
        require(isinstance(raw, Mapping), "Autofix protected workflow-run collection contains a non-object")
        run_id = positive_int(raw.get("id"), "Autofix protected workflow run id")
        require(run_id not in seen_run_ids, f"duplicate Autofix protected workflow run id: {run_id}")
        seen_run_ids.add(run_id)

        workflow_id = positive_int(raw.get("workflow_id"), "Autofix protected workflow id")
        require(
            workflow_id in expected_workflows,
            "Autofix protected workflow run references an unexpected workflow id",
        )
        require(
            workflow_id not in seen_workflow_ids,
            f"duplicate Autofix protected workflow id: {workflow_id}",
        )
        seen_workflow_ids.add(workflow_id)

        check_suite_id = positive_int(
            raw.get("check_suite_id"), "Autofix protected workflow check-suite id"
        )
        require(
            check_suite_id not in seen_check_suite_ids,
            f"duplicate Autofix protected workflow check-suite id: {check_suite_id}",
        )
        seen_check_suite_ids.add(check_suite_id)
        run_attempt = positive_int(raw.get("run_attempt"), "Autofix protected workflow run attempt")

        expected_path, expected_name = expected_workflows[workflow_id]
        require(raw.get("path") == expected_path, "Autofix protected workflow run path mismatch")
        require(raw.get("name") == expected_name, "Autofix protected workflow run name mismatch")
        require(raw.get("event") == "pull_request", "Autofix protected workflow run event changed")
        require(
            sha(raw.get("head_sha"), "Autofix protected workflow run head SHA") == expected_sha,
            "Autofix protected workflow run head SHA mismatch",
        )
        require(raw.get("head_branch") == branch, "Autofix protected workflow run head branch mismatch")

        for key in ("repository", "head_repository"):
            repository = raw.get(key)
            require(
                isinstance(repository, Mapping),
                f"Autofix protected workflow run {key} must be an object",
            )
            require(
                repository.get("full_name") == REPOSITORY,
                f"Autofix protected workflow run {key} identity mismatch",
            )

        status = raw.get("status")
        require(
            isinstance(status, str) and status in PROTECTED_PR_RUN_STATUSES,
            "Autofix protected workflow run status is outside the reviewed status set",
        )
        conclusion = raw.get("conclusion")
        if status == "completed":
            require(
                isinstance(conclusion, str)
                and bool(conclusion)
                and conclusion in PROTECTED_PR_RUN_CONCLUSIONS,
                "Autofix completed protected workflow run conclusion is outside the reviewed conclusion set",
            )
        else:
            require(
                conclusion is None,
                "Autofix non-completed protected workflow run conclusion must be null",
            )

        runs.append(
            {
                "id": run_id,
                "workflowId": workflow_id,
                "checkSuiteId": check_suite_id,
                "runAttempt": run_attempt,
                "status": status,
                "conclusion": conclusion,
            }
        )

    runs.sort(key=lambda item: item["workflowId"])
    return {"totalCount": total_count, "runs": runs}


def current_main(ref_response: Any, expected_sha: str) -> dict[str, Any]:
    normalized = validate_read_ref_response(ref_response, DEFAULT_REF, expected_sha)
    return {"baseSha": normalized["sha"], "baseRef": DEFAULT_REF}


def flatten_pages(value: Any) -> list[Any]:
    require(isinstance(value, list), "paginated API response must be an array")
    if not value:
        return []
    if all(isinstance(item, list) for item in value):
        return [entry for page in value for entry in page]
    return list(value)


CODEQL_WORKFLOW_PATH = ".github/workflows/codeql.yml"
CODEQL_RUN_STATUSES = {"queued", "in_progress", "completed", "waiting", "requested", "pending"}


def normalize_codeql_dispatch_run_pages(value: Any) -> list[dict[str, Any]]:
    require(isinstance(value, list), "CodeQL workflow-run pages must be a slurped page array")
    require(1 <= len(value) <= 30, "CodeQL workflow-run page count must be between 1 and 30")
    total_count: int | None = None
    runs: list[dict[str, Any]] = []
    seen: set[int] = set()
    for page_index, page in enumerate(value):
        require(isinstance(page, Mapping), f"CodeQL workflow-run page {page_index + 1} must be an object")
        page_total = page.get("total_count")
        require(type(page_total) is int and page_total >= 0,
                f"CodeQL workflow-run page {page_index + 1} total_count must be a nonnegative integer")
        if total_count is None:
            total_count = page_total
        else:
            require(page_total == total_count, "CodeQL workflow-run total_count changed across pages")
        entries = page.get("workflow_runs")
        require(isinstance(entries, list), f"CodeQL workflow-run page {page_index + 1} workflow_runs must be an array")
        require(len(entries) <= 100, f"CodeQL workflow-run page {page_index + 1} exceeds per_page=100")
        if page_index + 1 < len(value):
            require(len(entries) == 100, "non-final CodeQL workflow-run page must contain exactly 100 entries")
        for raw in entries:
            require(isinstance(raw, Mapping), "CodeQL workflow-run collection contains a non-object")
            run_id = positive_int(raw.get("id"), "CodeQL workflow run id")
            require(run_id not in seen, f"duplicate CodeQL workflow run id: {run_id}")
            seen.add(run_id)
            require(raw.get("name") == contract.CODEQL_WORKFLOW_NAME, "CodeQL workflow run name changed")
            require(raw.get("path") == CODEQL_WORKFLOW_PATH, "CodeQL workflow run path changed")
            require(raw.get("event") == "workflow_dispatch", "CodeQL follow-up run was not workflow_dispatch")
            require(raw.get("head_branch") == DEFAULT_BRANCH, "CodeQL follow-up run did not target main")
            head_sha = sha(raw.get("head_sha"), "CodeQL workflow run head SHA")
            repository = raw.get("repository")
            require(isinstance(repository, Mapping) and repository.get("full_name") == REPOSITORY,
                    "CodeQL workflow run repository identity mismatch")
            status = raw.get("status")
            require(isinstance(status, str) and status in CODEQL_RUN_STATUSES,
                    "CodeQL workflow run status is invalid")
            conclusion = raw.get("conclusion")
            require(conclusion is None or isinstance(conclusion, str), "CodeQL workflow run conclusion is invalid")
            runs.append({
                "id": run_id,
                "headSha": head_sha,
                "status": status,
                "conclusion": conclusion,
            })
    require(total_count == len(runs), "CodeQL workflow-run pagination is incomplete")
    return runs


def select_new_codeql_dispatch_run(before_pages: Any, after_pages: Any, expected_sha: str) -> dict[str, Any]:
    expected_sha = sha(expected_sha, "expected post-merge CodeQL SHA")
    before = normalize_codeql_dispatch_run_pages(before_pages)
    after = normalize_codeql_dispatch_run_pages(after_pages)
    before_ids = {run["id"] for run in before}
    candidates = [run for run in after if run["id"] not in before_ids and run["headSha"] == expected_sha]
    if not candidates:
        return {"state": "pending", "runId": None, "headSha": expected_sha}
    require(len(candidates) == 1, "post-merge CodeQL workflow dispatch is ambiguous")
    run = candidates[0]
    return {
        "state": "bound",
        "runId": run["id"],
        "headSha": run["headSha"],
        "status": run["status"],
        "conclusion": run["conclusion"],
    }


def validate_bound_codeql_run(value: Any, expected_run_id: int, expected_sha: str) -> dict[str, Any]:
    expected_run_id = positive_int(expected_run_id, "expected CodeQL workflow run id")
    expected_sha = sha(expected_sha, "expected post-merge CodeQL SHA")
    require(isinstance(value, Mapping), "bound CodeQL workflow run must be an object")
    require(positive_int(value.get("id"), "bound CodeQL workflow run id") == expected_run_id,
            "bound CodeQL workflow run id changed")
    require(value.get("name") == contract.CODEQL_WORKFLOW_NAME, "bound CodeQL workflow run name changed")
    require(value.get("path") == CODEQL_WORKFLOW_PATH, "bound CodeQL workflow run path changed")
    require(value.get("event") == "workflow_dispatch", "bound CodeQL workflow run event changed")
    require(value.get("head_branch") == DEFAULT_BRANCH, "bound CodeQL workflow run did not target main")
    require(sha(value.get("head_sha"), "bound CodeQL workflow run head SHA") == expected_sha,
            "bound CodeQL workflow run head SHA changed")
    repository = value.get("repository")
    require(isinstance(repository, Mapping) and repository.get("full_name") == REPOSITORY,
            "bound CodeQL workflow run repository identity mismatch")
    status = value.get("status")
    require(isinstance(status, str) and status in CODEQL_RUN_STATUSES, "bound CodeQL workflow run status is invalid")
    conclusion = value.get("conclusion")
    require(conclusion is None or isinstance(conclusion, str), "bound CodeQL workflow run conclusion is invalid")
    return {"runId": expected_run_id, "headSha": expected_sha, "status": status, "conclusion": conclusion}


def unsupported_evidence_marker(*, alert_number: int, base_sha: str, rule_id: str) -> str:
    alert_number = positive_int(alert_number, "unsupported alert number")
    base_sha = sha(base_sha, "unsupported evidence base SHA")
    require(isinstance(rule_id, str) and contract.RULE_ID.fullmatch(rule_id) is not None,
            "unsupported evidence rule id is invalid")
    return (
        "<!-- codeql-autofix-unsupported:v1 "
        f"base={base_sha} alert={alert_number} rule={rule_id} -->"
    )


def normalize_commit_comment_pages(value: Any, expected_sha: str) -> list[dict[str, Any]]:
    expected_sha = sha(expected_sha, "unsupported evidence base SHA")
    require(isinstance(value, list), "commit-comment pages must be a slurped page array")
    require(1 <= len(value) <= 30, "commit-comment page count must be between 1 and 30")
    comments: list[dict[str, Any]] = []
    seen: set[int] = set()
    for page_index, page in enumerate(value):
        require(isinstance(page, list), f"commit-comment page {page_index + 1} must be an array")
        require(len(page) <= 100, f"commit-comment page {page_index + 1} exceeds per_page=100")
        if page_index + 1 < len(value):
            require(len(page) == 100, "non-final commit-comment page must contain exactly 100 entries")
        for raw in page:
            require(isinstance(raw, Mapping), "commit-comment collection contains a non-object")
            comment_id = positive_int(raw.get("id"), "commit comment id")
            require(comment_id not in seen, f"duplicate commit comment id: {comment_id}")
            seen.add(comment_id)
            require(sha(raw.get("commit_id"), "commit comment commit SHA") == expected_sha,
                    "commit comment is bound to another commit")
            body = raw.get("body")
            require(isinstance(body, str), "commit comment body must be a string")
            user = raw.get("user")
            require(isinstance(user, Mapping), "commit comment user must be an object")
            login = user.get("login")
            require(isinstance(login, str) and login != "", "commit comment user.login must be non-empty")
            comments.append({"id": comment_id, "body": body, "login": login})
    return comments


def unsupported_evidence_decision(target: Any, comment_pages: Any, expected_sha: str) -> dict[str, Any]:
    expected_sha = sha(expected_sha, "unsupported evidence base SHA")
    require(isinstance(target, Mapping), "unsupported evidence target must be an object")
    alert_number = positive_int(target.get("number"), "unsupported alert number")
    require(sha(target.get("baseSha"), "unsupported alert base SHA") == expected_sha,
            "unsupported alert is stale relative to exact main")
    rule_id = target.get("ruleId")
    require(isinstance(rule_id, str) and contract.RULE_ID.fullmatch(rule_id) is not None,
            "unsupported evidence rule id is invalid")
    severity = target.get("securitySeverity")
    require(severity is None or isinstance(severity, str), "unsupported evidence severity is invalid")
    location = target.get("location")
    require(isinstance(location, Mapping), "unsupported evidence location must be an object")
    path = location.get("path")
    start_line = location.get("startLine")
    end_line = location.get("endLine")
    require(isinstance(path, str) and path != "", "unsupported evidence path is invalid")
    start_line = positive_int(start_line, "unsupported evidence start line")
    require(type(end_line) is int and end_line >= start_line, "unsupported evidence end line is invalid")

    marker = unsupported_evidence_marker(alert_number=alert_number, base_sha=expected_sha, rule_id=rule_id)
    comments = normalize_commit_comment_pages(comment_pages, expected_sha)
    matches = [comment for comment in comments
               if comment["login"] == "github-actions[bot]" and marker in comment["body"]]
    require(len(matches) <= 1, "duplicate trusted unsupported-Autofix evidence comments exist")
    severity_text = severity if severity is not None else "unknown"
    body = (
        f"{marker}\n"
        "CodeQL Autofix could not generate a fix for an exact-main alert.\n\n"
        f"- alert: #{alert_number}\n"
        f"- rule: {rule_id}\n"
        f"- security severity: {severity_text}\n"
        f"- exact main: {expected_sha}\n"
        f"- location: {path}:{start_line}-{end_line}\n"
        "- classification: github-autofix-unsupported (exact reviewed HTTP 422 response)\n"
        "- action: alert left open; bounded trusted discovery continues to later alerts.\n"
    )
    return {"exists": len(matches) == 1, "marker": marker, "body": body, "alertNumber": alert_number}


def validate_created_unsupported_evidence(value: Any, expected_sha: str, marker: str) -> dict[str, Any]:
    expected_sha = sha(expected_sha, "created unsupported evidence base SHA")
    require(isinstance(marker, str) and marker.startswith("<!-- codeql-autofix-unsupported:v1 "),
            "created unsupported evidence marker is invalid")
    require(isinstance(value, Mapping), "created commit comment response must be an object")
    comment_id = positive_int(value.get("id"), "created commit comment id")
    require(sha(value.get("commit_id"), "created commit comment SHA") == expected_sha,
            "created unsupported evidence comment is bound to another commit")
    body = value.get("body")
    require(isinstance(body, str) and marker in body,
            "created unsupported evidence comment does not contain exact marker")
    user = value.get("user")
    require(isinstance(user, Mapping) and user.get("login") == "github-actions[bot]",
            "created unsupported evidence comment actor mismatch")
    return {"id": comment_id, "commitSha": expected_sha, "marker": marker}


def normalize_issue_comment_pages(value: Any, pr_number: int) -> list[dict[str, Any]]:
    pr_number = positive_int(pr_number, "Autofix approval-comment PR number")
    issue_url = f"https://api.github.com/repos/{REPOSITORY}/issues/{pr_number}"
    require(isinstance(value, list), "Autofix approval-comment pages must be a slurped page array")
    require(1 <= len(value) <= 20, "Autofix approval-comment page count must be between 1 and 20")
    comments: list[dict[str, Any]] = []
    seen: set[int] = set()
    for page_index, page in enumerate(value):
        require(
            isinstance(page, list),
            f"Autofix approval-comment page {page_index + 1} must be an array",
        )
        require(
            len(page) <= 100,
            f"Autofix approval-comment page {page_index + 1} exceeds per_page=100",
        )
        if page_index + 1 < len(value):
            require(
                len(page) == 100,
                "non-final Autofix approval-comment page must contain exactly 100 entries",
            )
        for raw in page:
            require(
                isinstance(raw, Mapping),
                "Autofix approval-comment collection contains a non-object",
            )
            comment_id = positive_int(raw.get("id"), "Autofix approval comment id")
            require(
                comment_id not in seen,
                f"duplicate Autofix approval comment id: {comment_id}",
            )
            seen.add(comment_id)
            require(
                raw.get("issue_url") == issue_url,
                "Autofix approval comment issue URL mismatch",
            )
            body = raw.get("body")
            require(
                isinstance(body, str),
                "Autofix approval comment body must be a string",
            )
            user = raw.get("user")
            require(
                isinstance(user, Mapping),
                "Autofix approval comment user must be an object",
            )
            login = user.get("login")
            require(
                isinstance(login, str) and bool(login),
                "Autofix approval comment user.login must be non-empty",
            )
            html_url = raw.get("html_url")
            require(
                isinstance(html_url, str) and bool(html_url),
                "Autofix approval comment html_url must be non-empty",
            )
            comments.append(
                {
                    "id": comment_id,
                    "login": login,
                    "body": body,
                    "issueUrl": issue_url,
                }
            )
    return comments


def approval_comment_evidence(
    comment_pages: Any,
    *,
    pr_number: int,
    marker: str,
) -> dict[str, Any]:
    pr_number = positive_int(pr_number, "Autofix approval-comment PR number")
    require(
        isinstance(marker, str)
        and re.fullmatch(
            r"<!-- portyu9-automation-approval:v1 head=[0-9a-f]{40} -->",
            marker,
        )
        is not None,
        "Autofix approval-comment marker is malformed",
    )
    comments = normalize_issue_comment_pages(comment_pages, pr_number)
    matches = [
        comment
        for comment in comments
        if comment["login"] == "github-actions[bot]" and marker in comment["body"]
    ]
    require(
        len(matches) <= 1,
        "duplicate trusted Autofix approval comments exist",
    )
    return {
        "exists": len(matches) == 1,
        "commentId": matches[0]["id"] if matches else None,
        "prNumber": pr_number,
        "marker": marker,
    }


def validate_created_approval_comment(
    value: Any,
    *,
    pr_number: int,
    expected_body: str,
) -> dict[str, Any]:
    pr_number = positive_int(pr_number, "created Autofix approval-comment PR number")
    require(
        isinstance(expected_body, str) and bool(expected_body),
        "created Autofix approval-comment expected body must be non-empty",
    )
    marker = expected_body.split("\n", 1)[0]
    require(
        re.fullmatch(
            r"<!-- portyu9-automation-approval:v1 head=[0-9a-f]{40} -->",
            marker,
        )
        is not None,
        "created Autofix approval-comment marker is malformed",
    )
    issue_url = f"https://api.github.com/repos/{REPOSITORY}/issues/{pr_number}"
    require(
        isinstance(value, Mapping),
        "created Autofix approval-comment response must be an object",
    )
    comment_id = positive_int(value.get("id"), "created Autofix approval comment id")
    require(
        value.get("issue_url") == issue_url,
        "created Autofix approval comment issue URL mismatch",
    )
    require(
        value.get("body") == expected_body,
        "created Autofix approval comment body mismatch",
    )
    user = value.get("user")
    require(
        isinstance(user, Mapping) and user.get("login") == "github-actions[bot]",
        "created Autofix approval comment actor mismatch",
    )
    html_url = value.get("html_url")
    require(
        isinstance(html_url, str) and bool(html_url),
        "created Autofix approval comment html_url must be non-empty",
    )
    return {
        "id": comment_id,
        "prNumber": pr_number,
        "actor": "github-actions[bot]",
        "marker": marker,
    }


def discover_target(alert_pages: Any, base_sha: str) -> dict[str, Any]:
    alerts = flatten_pages(alert_pages)
    record = discovery.discover(alerts, base_sha=base_sha, pagination_complete=True)
    target = discovery.select_one(record)
    return {"discovery": record, "target": target}


def locate_existing(pr_pages: Any, alert_number: int) -> dict[str, Any]:
    alert_number = positive_int(alert_number, "alert number")
    matches: list[dict[str, Any]] = []
    for raw in flatten_pages(pr_pages):
        require(isinstance(raw, Mapping), "pull request list contains a non-object")
        if raw.get("state") != "open":
            continue
        base = raw.get("base")
        head = raw.get("head")
        require(isinstance(base, Mapping) and isinstance(head, Mapping), "pull request list item lacks base/head")
        if base.get("ref") != DEFAULT_BRANCH:
            continue
        ref = head.get("ref")
        if not isinstance(ref, str):
            continue
        match = BRANCH_RE.fullmatch(ref)
        if match is None or int(match.group("alert")) != alert_number:
            continue
        matches.append({
            "prNumber": positive_int(raw.get("number"), "existing PR number"),
            "nodeId": raw.get("node_id"),
            "branch": ref,
            "originRunId": int(match.group("run")),
            "headSha": sha(head.get("sha"), "existing PR head SHA"),
            "baseSha": sha(base.get("sha"), "existing PR base SHA"),
            "draft": raw.get("draft"),
        })
    require(len(matches) <= 1, "multiple open Autofix PRs exist for one alert")
    return {"exists": bool(matches), "pr": matches[0] if matches else None}


def classify_branch_ref_inventory(value: Any, branch: str) -> dict[str, Any]:
    require(isinstance(branch, str) and BRANCH_RE.fullmatch(branch) is not None,
            "Autofix branch identity is malformed")
    expected_ref = f"refs/heads/{branch}"
    require(isinstance(value, list), "matching-ref response must be an array")
    require(len(value) <= 1, "matching-ref response is ambiguous")

    if not value:
        return {"state": "absent", "ref": expected_ref, "sha": None}

    entry = value[0]
    require(isinstance(entry, Mapping), "matching-ref response contains a non-object")
    observed_ref = entry.get("ref")
    require(type(observed_ref) is str, "matching-ref response ref must be a string")
    require(observed_ref == expected_ref, "matching-ref response contains a non-exact ref")
    obj = entry.get("object")
    require(isinstance(obj, Mapping), "matching-ref response is missing object")
    require(obj.get("type") == "commit", "matching-ref response object type changed")
    observed_sha = sha(obj.get("sha"), "matching-ref object SHA")
    return {"state": "existing", "ref": expected_ref, "sha": observed_sha}


def normalize_status(target: Mapping[str, Any], status_response: Any) -> dict[str, Any]:
    return discovery.normalize_autofix_status(target, status_response)


def validate_created_ref_response(value: Any, branch: str, expected_sha: str) -> dict[str, Any]:
    require(isinstance(branch, str) and BRANCH_RE.fullmatch(branch) is not None,
            "Autofix created-ref branch identity is malformed")
    expected_ref = f"refs/heads/{branch}"
    expected_sha = sha(expected_sha, "Autofix created-ref expected SHA")
    require(isinstance(value, Mapping), "Autofix created-ref response must be an object")
    observed_ref = value.get("ref")
    require(type(observed_ref) is str, "Autofix created-ref response ref must be a string")
    require(observed_ref == expected_ref, "Autofix created-ref response ref mismatch")
    obj = value.get("object")
    require(isinstance(obj, Mapping), "Autofix created-ref response object must be an object")
    require(obj.get("type") == "commit", "Autofix created-ref response object type changed")
    observed_sha = sha(obj.get("sha"), "Autofix created-ref response SHA")
    require(observed_sha == expected_sha, "Autofix created-ref response SHA mismatch")
    return {"ref": expected_ref, "sha": observed_sha}


def validate_pull_request_response(
    value: Any,
    *,
    pr_number: int,
    repository: str,
    base_sha: str,
    branch: str,
    head_sha: str,
) -> dict[str, Any]:
    pr_number = positive_int(pr_number, "Autofix pull-request PR number")
    require(isinstance(repository, str) and repository == REPOSITORY,
            "Autofix pull-request repository identity changed")
    require(isinstance(branch, str) and BRANCH_RE.fullmatch(branch) is not None,
            "Autofix pull-request branch identity is malformed")
    base_sha = sha(base_sha, "Autofix pull-request base SHA")
    head_sha = sha(head_sha, "Autofix pull-request head SHA")

    require(isinstance(value, Mapping), "Autofix pull-request response must be an object")
    require(
        positive_int(value.get("number"), "Autofix pull-request response PR number") == pr_number,
        "Autofix pull-request response PR number mismatch",
    )
    require(value.get("state") == "open", "Autofix pull-request response state changed")
    require(
        type(value.get("draft")) is bool and value.get("draft") is False,
        "Autofix pull-request response draft state changed",
    )

    base = value.get("base")
    head = value.get("head")
    require(isinstance(base, Mapping), "Autofix pull-request response base must be an object")
    require(isinstance(head, Mapping), "Autofix pull-request response head must be an object")
    require(base.get("ref") == DEFAULT_BRANCH, "Autofix pull-request response base ref changed")
    require(
        sha(base.get("sha"), "Autofix pull-request response base SHA") == base_sha,
        "Autofix pull-request response base SHA mismatch",
    )
    require(head.get("ref") == branch, "Autofix pull-request response head ref mismatch")
    require(
        sha(head.get("sha"), "Autofix pull-request response head SHA") == head_sha,
        "Autofix pull-request response head SHA mismatch",
    )
    for label, side in (("base", base), ("head", head)):
        side_repo = side.get("repo")
        require(
            isinstance(side_repo, Mapping),
            f"Autofix pull-request response {label} repository must be an object",
        )
        require(
            side_repo.get("full_name") == repository,
            f"Autofix pull-request response {label} repository mismatch",
        )

    return {
        "prNumber": pr_number,
        "state": "open",
        "draft": False,
        "baseRef": DEFAULT_BRANCH,
        "baseSha": base_sha,
        "headRef": branch,
        "headSha": head_sha,
        "repository": repository,
    }


def validate_reviewer_request_response(
    value: Any,
    *,
    pr_number: int,
    repository: str,
    base_sha: str,
    branch: str,
    head_sha: str,
) -> dict[str, Any]:
    pr_number = positive_int(pr_number, "Autofix reviewer-request PR number")
    require(isinstance(repository, str) and repository == "portyu9/portyu9",
            "Autofix reviewer-request repository identity changed")
    require(isinstance(branch, str) and BRANCH_RE.fullmatch(branch) is not None,
            "Autofix reviewer-request branch identity is malformed")
    base_sha = sha(base_sha, "Autofix reviewer-request base SHA")
    head_sha = sha(head_sha, "Autofix reviewer-request head SHA")
    require(isinstance(value, Mapping), "Autofix reviewer-request response must be an object")
    require(positive_int(value.get("number"), "Autofix reviewer-request response PR number") == pr_number,
            "Autofix reviewer-request response PR number mismatch")
    require(value.get("state") == "open", "Autofix reviewer-request response state changed")
    require(type(value.get("draft")) is bool and value.get("draft") is False,
            "Autofix reviewer-request response draft state changed")

    base = value.get("base")
    head = value.get("head")
    require(isinstance(base, Mapping), "Autofix reviewer-request response base must be an object")
    require(isinstance(head, Mapping), "Autofix reviewer-request response head must be an object")
    require(base.get("ref") == "main", "Autofix reviewer-request response base ref changed")
    require(sha(base.get("sha"), "Autofix reviewer-request response base SHA") == base_sha,
            "Autofix reviewer-request response base SHA mismatch")
    require(head.get("ref") == branch, "Autofix reviewer-request response head ref mismatch")
    require(sha(head.get("sha"), "Autofix reviewer-request response head SHA") == head_sha,
            "Autofix reviewer-request response head SHA mismatch")
    for label, side in (("base", base), ("head", head)):
        side_repo = side.get("repo")
        require(isinstance(side_repo, Mapping),
                f"Autofix reviewer-request response {label} repository must be an object")
        require(side_repo.get("full_name") == repository,
                f"Autofix reviewer-request response {label} repository mismatch")

    reviewers = value.get("requested_reviewers")
    require(isinstance(reviewers, list),
            "Autofix reviewer-request response requested_reviewers must be an array")
    require(len(reviewers) <= 100,
            "Autofix reviewer-request response requested_reviewers exceeds bound")
    logins: list[str] = []
    ids: set[int] = set()
    for raw in reviewers:
        require(isinstance(raw, Mapping),
                "Autofix reviewer-request response contains a non-object reviewer")
        login = raw.get("login")
        require(isinstance(login, str) and bool(login.strip()),
                "Autofix reviewer-request response reviewer login must be a non-empty string")
        reviewer_id = positive_int(raw.get("id"), "Autofix reviewer-request response reviewer id")
        require(reviewer_id not in ids,
                "Autofix reviewer-request response contains duplicate reviewer ids")
        require(login not in logins,
                "Autofix reviewer-request response contains duplicate reviewer logins")
        ids.add(reviewer_id)
        logins.append(login)
    require(logins.count("portyu9") == 1,
            "Autofix reviewer-request response must contain exactly one portyu9 reviewer")
    return {"prNumber": pr_number, "reviewer": "portyu9", "headSha": head_sha}


def validate_commit_response(value: Any, branch: str) -> dict[str, Any]:
    require(isinstance(value, Mapping), "Autofix commit response must be an object")
    expected_ref = f"refs/heads/{branch}"
    require(value.get("target_ref") == expected_ref, "Autofix commit response target_ref mismatch")
    return {"targetRef": expected_ref, "headSha": sha(value.get("sha"), "Autofix commit SHA")}


def validate_merge_success_response(value: Any) -> dict[str, Any]:
    require(isinstance(value, Mapping), "Autofix merge success response must be an object")
    require(type(value.get("merged")) is bool, "Autofix merge success response merged must be a boolean")
    require(value.get("merged") is True, "Autofix merge success response did not report merged=true")
    merge_sha = sha(value.get("sha"), "Autofix merge success response sha")
    message = value.get("message")
    require(isinstance(message, str) and bool(message.strip()),
            "Autofix merge success response message must be a non-empty string")
    return {"merged": True, "sha": merge_sha, "message": message}


def validate_compare(value: Any, base_sha: str, head_sha: str) -> dict[str, Any]:
    base_sha = sha(base_sha, "compare base SHA")
    head_sha = sha(head_sha, "compare head SHA")
    require(isinstance(value, Mapping), "compare response must be an object")
    base = value.get("base_commit")
    merge_base = value.get("merge_base_commit")
    require(isinstance(base, Mapping) and base.get("sha") == base_sha, "compare base identity mismatch")
    require(isinstance(merge_base, Mapping) and merge_base.get("sha") == base_sha,
            "Autofix branch is not a direct descendant of the exact base")
    require(value.get("status") == "ahead", "Autofix compare has an unexpected ancestry status")
    require(value.get("ahead_by") == 1, "Autofix must add exactly one commit")
    require(value.get("total_commits") == 1, "Autofix compare must report exactly one commit")
    commits = value.get("commits")
    require(isinstance(commits, list), "Autofix compare is missing commits")
    require(len(commits) == 1, "Autofix compare must contain exactly one commit")
    head = commits[0]
    require(isinstance(head, Mapping) and head.get("sha") == head_sha, "compare head identity mismatch")
    files = value.get("files")
    require(isinstance(files, list), "Autofix compare is missing changed files")
    paths: list[str] = []
    for item in files:
        require(isinstance(item, Mapping), "Autofix compare contains a malformed file entry")
        filename = item.get("filename")
        require(isinstance(filename, str), "Autofix compare file lacks filename")
        require(item.get("status") in {"modified", "added", "removed", "renamed"}, "Autofix compare file status changed")
        paths.append(filename)
    allowed = admission.validate_changed_files(paths)
    return {"baseSha": base_sha, "headSha": head_sha, "changedFiles": list(allowed)}


def normalize_prior_attempt_history(
    value: Any,
    *,
    run_id: int,
    run_attempt: int,
    event_name: str,
    base_sha: str,
) -> list[dict[str, Any]]:
    run_id = positive_int(run_id, "run id")
    run_attempt = positive_int(run_attempt, "run attempt")
    base_sha = sha(base_sha, "retry-history base SHA")
    require(
        run_attempt <= contract.MAX_RECORDED_ATTEMPTS,
        "Autofix receipt run attempt exceeds bounded retry-history limit",
    )
    require(isinstance(value, list), "Autofix retry-history input must be an array")
    require(
        len(value) == run_attempt - 1,
        "Autofix retry-history must contain every prior attempt exactly once",
    )
    history: list[dict[str, Any]] = []
    for expected_attempt, raw in enumerate(value, start=1):
        require(isinstance(raw, Mapping), "Autofix retry-history contains a non-object attempt")
        require(
            positive_int(raw.get("id"), f"Autofix retry-history attempt {expected_attempt} run id") == run_id,
            "Autofix retry-history run id changed",
        )
        require(
            positive_int(raw.get("run_attempt"), f"Autofix retry-history attempt {expected_attempt} number")
            == expected_attempt,
            "Autofix retry-history attempts are not contiguous",
        )
        require(
            raw.get("name") == contract.WORKFLOW_NAME
            and raw.get("path") == contract.WORKFLOW_PATH
            and raw.get("event") == event_name,
            "Autofix retry-history workflow identity changed",
        )
        require(
            raw.get("head_branch") == DEFAULT_BRANCH
            and sha(raw.get("head_sha"), "Autofix retry-history head SHA") == base_sha,
            "Autofix retry-history source identity changed",
        )
        repository = raw.get("repository")
        head_repository = raw.get("head_repository")
        require(
            isinstance(repository, Mapping)
            and repository.get("full_name") == REPOSITORY
            and isinstance(head_repository, Mapping)
            and head_repository.get("full_name") == REPOSITORY,
            "Autofix retry-history repository identity changed",
        )
        require(raw.get("status") == "completed", "Autofix retry-history prior attempt is not terminal")
        conclusion = raw.get("conclusion")
        require(
            isinstance(conclusion, str) and conclusion in contract.PRIOR_ATTEMPT_CONCLUSIONS,
            "Autofix retry-history prior attempt conclusion is invalid",
        )
        actor = raw.get("actor")
        triggering_actor = raw.get("triggering_actor")
        actor_login = actor.get("login") if isinstance(actor, Mapping) else None
        triggering_login = triggering_actor.get("login") if isinstance(triggering_actor, Mapping) else None
        require(
            isinstance(actor_login, str) and bool(actor_login)
            and isinstance(triggering_login, str) and bool(triggering_login),
            "Autofix retry-history actor identity is missing",
        )
        history.append({
            "attempt": expected_attempt,
            "checkSuiteId": positive_int(
                raw.get("check_suite_id"),
                f"Autofix retry-history attempt {expected_attempt} check suite id",
            ),
            "status": "completed",
            "conclusion": conclusion,
            "actor": actor_login,
            "triggeringActor": triggering_login,
        })
    return history


def build_receipt(*, run_id: int, run_attempt: int, event_name: str, base_sha: str, target: Mapping[str, Any],
                  branch: str, head_sha: str, pr_response: Any, prior_attempts: Any) -> dict[str, Any]:
    run_id = positive_int(run_id, "run id")
    run_attempt = positive_int(run_attempt, "run attempt")
    alert = positive_int(target.get("number"), "target alert number")
    base_sha = sha(base_sha, "receipt base SHA")
    head_sha = sha(head_sha, "receipt head SHA")
    require(branch == contract.branch_name(run_id, alert), "receipt branch identity mismatch")
    require(isinstance(pr_response, Mapping), "created PR response must be an object")
    require(pr_response.get("state") == "open", "created Autofix PR is not open")
    require(pr_response.get("draft") is False, "created Autofix PR unexpectedly became draft")
    base = pr_response.get("base")
    head = pr_response.get("head")
    require(isinstance(base, Mapping) and base.get("ref") == DEFAULT_BRANCH and base.get("sha") == base_sha,
            "created Autofix PR base mismatch")
    require(isinstance(head, Mapping) and head.get("ref") == branch and head.get("sha") == head_sha,
            "created Autofix PR head mismatch")
    rule_id = target.get("ruleId")
    require(isinstance(rule_id, str), "target rule id is missing")
    retry_history = normalize_prior_attempt_history(
        prior_attempts,
        run_id=run_id,
        run_attempt=run_attempt,
        event_name=event_name,
        base_sha=base_sha,
    )
    receipt = {
        "controllerId": contract.CONTROLLER_ID,
        "flowId": contract.FLOW_ID,
        "repository": REPOSITORY,
        "workflowPath": contract.WORKFLOW_PATH,
        "runId": run_id,
        "runAttempt": run_attempt,
        "retryHistory": retry_history,
        "event": event_name,
        "baseSha": base_sha,
        "alertNumber": alert,
        "ruleId": rule_id,
        "targetBranch": branch,
        "autofixCommitSha": head_sha,
        "prNumber": positive_int(pr_response.get("number"), "created PR number"),
    }
    return receipt


def select_artifact(value: Any, run_id: int, alert_number: int) -> dict[str, Any]:
    run_id = positive_int(run_id, "artifact run id")
    alert_number = positive_int(alert_number, "artifact alert number")
    require(isinstance(value, Mapping), "artifact list response must be an object")
    total_count = value.get("total_count")
    require(
        type(total_count) is int and total_count >= 0,
        "artifact list total_count must be a nonnegative integer",
    )
    artifacts = value.get("artifacts")
    require(isinstance(artifacts, list), "artifact list is missing artifacts")
    require(total_count == len(artifacts), "artifact list response is incomplete")
    require(total_count <= 100, "artifact list exceeds one complete reviewed page")

    normalized: list[dict[str, Any]] = []
    for raw in artifacts:
        require(isinstance(raw, Mapping), "artifact list contains a non-object")
        artifact = dict(raw)
        positive_int(artifact.get("id"), "artifact id")
        name = artifact.get("name")
        require(isinstance(name, str) and bool(name), "artifact name must be a non-empty string")
        normalized.append(artifact)

    expected = contract.receipt_name(run_id, alert_number)
    matches = [artifact for artifact in normalized if artifact["name"] == expected]
    require(len(matches) == 1, "expected exactly one controller receipt artifact")
    artifact = matches[0]

    require(type(artifact.get("expired")) is bool, "receipt artifact expired must be a boolean")
    require(artifact["expired"] is False, "controller receipt artifact is expired")
    digest = artifact.get("digest")
    require(
        isinstance(digest, str) and contract.DIGEST.fullmatch(digest) is not None,
        "receipt artifact digest must be a sha256 digest",
    )
    workflow_run = artifact.get("workflow_run")
    require(isinstance(workflow_run, Mapping), "receipt artifact workflow_run must be an object")
    require(
        positive_int(workflow_run.get("id"), "receipt artifact workflow_run id") == run_id,
        "receipt artifact belongs to another workflow run",
    )
    require(
        workflow_run.get("head_branch") == DEFAULT_BRANCH,
        "receipt artifact workflow_run head branch changed",
    )
    sha(workflow_run.get("head_sha"), "receipt artifact workflow_run head SHA")
    return artifact


def required_check_evidence(check_pages: Any, head_sha: str) -> list[dict[str, Any]]:
    head_sha = sha(head_sha, "required-check head SHA")
    expected = set(admission.REQUIRED_CHECKS)
    selected: list[dict[str, Any]] = []
    for raw in flatten_pages(check_pages):
        require(isinstance(raw, Mapping), "check-runs response contains a non-object")
        name = raw.get("name")
        if name not in expected:
            continue
        app = raw.get("app")
        require(isinstance(app, Mapping), f"required check lacks app identity: {name}")
        selected.append({
            "name": name,
            "status": raw.get("status"),
            "conclusion": raw.get("conclusion"),
            "appId": app.get("id"),
            "headSha": raw.get("head_sha"),
        })
    return selected


def validate_check_run_readiness(
    value: Any, head_sha: str, check_name: str, app_id: int
) -> dict[str, Any]:
    """Validate one bounded exact-head check-run collection before readiness decisions."""
    head_sha = sha(head_sha, "readiness check head SHA")
    require(isinstance(check_name, str) and bool(check_name),
            "readiness check name must be a non-empty string")
    app_id = positive_int(app_id, "readiness check app id")
    require(isinstance(value, Mapping), "readiness check-runs response must be an object")
    total = value.get("total_count")
    require(type(total) is int and 0 <= total <= 100,
            "readiness check-runs total_count must be an integer in [0,100]")
    runs = value.get("check_runs")
    require(isinstance(runs, list) and len(runs) <= 100,
            "readiness check_runs must be an array bounded to 100 items")
    require(total == len(runs),
            "readiness check-runs total_count does not match returned array length")

    seen_ids: set[int] = set()
    normalized: list[dict[str, Any]] = []
    for raw in runs:
        require(isinstance(raw, Mapping), "readiness check-runs response contains a non-object")
        check_id = positive_int(raw.get("id"), "readiness check-run id")
        require(check_id not in seen_ids, "readiness check-run ids must be unique")
        seen_ids.add(check_id)
        require(raw.get("name") == check_name,
                "readiness check-run name differs from the exact queried check")
        require(sha(raw.get("head_sha"), "readiness check-run head SHA") == head_sha,
                "readiness check-run head SHA differs from the exact candidate")
        app = raw.get("app")
        require(isinstance(app, Mapping), "readiness check-run lacks app identity")
        observed_app_id = app.get("id")
        require(type(observed_app_id) is int and observed_app_id == app_id,
                "readiness check-run app identity mismatch")
        status = raw.get("status")
        require(isinstance(status, str) and status in CODEQL_RUN_STATUSES,
                "readiness check-run status is outside the reviewed status set")
        conclusion = raw.get("conclusion")
        if status == "completed":
            require(isinstance(conclusion, str) and bool(conclusion),
                    "completed readiness check-run conclusion must be a non-empty string")
        else:
            require(conclusion is None,
                    "nonterminal readiness check-run conclusion must be null")
        normalized.append({
            "id": check_id,
            "status": status,
            "conclusion": conclusion,
        })

    if total == 0:
        return {"state": "missing", "count": 0}
    if total > 1:
        return {"state": "ambiguous", "count": total}
    check = normalized[0]
    if check["status"] != "completed":
        return {"state": "pending", "count": 1, **check}
    if check["conclusion"] == "success":
        return {"state": "success", "count": 1, **check}
    return {"state": "failure", "count": 1, **check}


def security_evidence(ghas_response: Any, pr_alert_pages: Any, alert_number: int, head_sha: str) -> dict[str, Any]:
    alert_number = positive_int(alert_number, "security alert number")
    head_sha = sha(head_sha, "security head SHA")
    require(isinstance(ghas_response, Mapping), "GHAS check-runs response must be an object")
    checks = ghas_response.get("check_runs")
    require(isinstance(checks, list) and len(checks) == 1, "expected exactly one latest GHAS CodeQL aggregate")
    aggregate = checks[0]
    require(isinstance(aggregate, Mapping), "GHAS aggregate is malformed")
    app = aggregate.get("app")
    require(isinstance(app, Mapping) and app.get("id") == GHAS_APP_ID, "GHAS aggregate app identity mismatch")
    require(aggregate.get("name") == "CodeQL" and aggregate.get("head_sha") == head_sha,
            "GHAS aggregate identity mismatch")

    findings: list[dict[str, Any]] = []
    target_present = False
    for raw in flatten_pages(pr_alert_pages):
        require(isinstance(raw, Mapping), "PR code-scanning response contains a non-object")
        if raw.get("state") != "open":
            continue
        tool = raw.get("tool")
        if not isinstance(tool, Mapping) or tool.get("name") != discovery.TOOL_NAME:
            continue
        number = positive_int(raw.get("number"), "PR code-scanning alert number")
        rule = raw.get("rule")
        require(isinstance(rule, Mapping), "PR CodeQL alert lacks rule")
        rule_id = rule.get("id")
        severity = rule.get("security_severity_level")
        if number == alert_number:
            target_present = True
        else:
            findings.append({"ruleId": rule_id, "severity": severity or "unknown"})
    return {
        "headSha": head_sha,
        "advancedSecurityConclusion": aggregate.get("conclusion"),
        "targetAlertNumber": alert_number,
        "targetAlertPresent": target_present,
        "newFindings": findings,
    }


def unresolved_threads(value: Any) -> int:
    require(isinstance(value, Mapping), "review-thread GraphQL response must be an object")
    require(value.get("errors") is None, "review-thread GraphQL response contains errors")
    data = value.get("data")
    require(isinstance(data, Mapping), "review-thread GraphQL response lacks data")
    repo = data.get("repository")
    require(isinstance(repo, Mapping), "review-thread response lacks repository")
    pr = repo.get("pullRequest")
    require(isinstance(pr, Mapping), "review-thread response lacks pullRequest")
    threads = pr.get("reviewThreads")
    require(isinstance(threads, Mapping), "review-thread response lacks reviewThreads")
    page_info = threads.get("pageInfo")
    require(isinstance(page_info, Mapping), "review-thread response lacks pageInfo")
    require(type(page_info.get("hasNextPage")) is bool,
            "review-thread hasNextPage must be a boolean")
    require(page_info.get("hasNextPage") is False, "review-thread pagination is incomplete")
    nodes = threads.get("nodes")
    require(isinstance(nodes, list), "review-thread response lacks nodes")

    unresolved = 0
    for node in nodes:
        require(isinstance(node, Mapping), "review-thread response contains a non-object node")
        resolved = node.get("isResolved")
        require(type(resolved) is bool, "review-thread isResolved must be a boolean")
        if resolved is False:
            unresolved += 1
    return unresolved


def admit_existing(*, receipt: Any, workflow_run: Any, artifact: Any, pr_response: Any, main_ref: Any,
                   check_pages: Any, ghas_response: Any, pr_alert_pages: Any, thread_response: Any) -> dict[str, Any]:
    provenance = contract.validate_receipt(receipt, workflow_run=workflow_run, artifact=artifact)
    require(isinstance(pr_response, Mapping), "Autofix PR response must be an object")
    require(pr_response.get("number") == provenance["prNumber"], "Autofix PR number differs from receipt")
    base = pr_response.get("base")
    head = pr_response.get("head")
    require(isinstance(base, Mapping) and isinstance(head, Mapping), "Autofix PR lacks base/head")
    current_main_sha = current_main(main_ref, provenance["baseSha"])["baseSha"]
    head_sha = sha(head.get("sha"), "current Autofix PR head SHA")
    record = {
        "repository": REPOSITORY,
        "baseRef": base.get("ref"),
        "baseSha": provenance["baseSha"],
        "currentMainSha": current_main_sha,
        "headSha": provenance["headSha"],
        "currentHeadSha": head_sha,
        "alertNumber": provenance["alertNumber"],
        "alertsAddressed": [provenance["alertNumber"]],
        "provenance": provenance,
        "changedFiles": pr_response.get("changedFiles"),
        "unresolvedReviewThreads": unresolved_threads(thread_response),
        "draft": pr_response.get("draft"),
        "mergeable": pr_response.get("mergeable"),
        "requiredChecks": required_check_evidence(check_pages, head_sha),
        "security": security_evidence(ghas_response, pr_alert_pages, provenance["alertNumber"], head_sha),
    }
    return admission.evaluate(record)


def self_test() -> None:
    base = "a" * 40
    head = "b" * 40
    event = {"workflow_run": {"name": "CodeQL", "conclusion": "success", "head_branch": "main", "head_sha": base}}
    require(validate_trigger("workflow_run", event, base)["trustedSha"] == base, "trigger positive fixture changed")
    ref_url = f"https://api.github.com/repos/{REPOSITORY}/git/commits/{base}"
    current_main(
        {"ref": DEFAULT_REF, "object": {"type": "commit", "sha": base, "url": ref_url}},
        base,
    )

    ref_branch_read = "codeql-autofix/alert-4/run-123"
    ref_branch_name = f"refs/heads/{ref_branch_read}"
    read_ref = validate_read_ref_response(
        {"ref": ref_branch_name, "object": {"type": "commit", "sha": head, "url": f"https://api.github.com/repos/{REPOSITORY}/git/commits/{head}"}},
        ref_branch_name,
        head,
    )
    require(read_ref["sha"] == head and read_ref["ref"] == ref_branch_name,
            "Autofix read-ref response positive fixture changed")
    read_ref_mutations = (
        ([], "must be an object"),
        ({"ref": DEFAULT_REF, "object": {"type": "commit", "sha": head, "url": ref_url}}, "identity mismatch"),
        ({"ref": ref_branch_name, "object": None}, "object must be an object"),
        ({"ref": ref_branch_name, "object": {"type": "tag", "sha": head, "url": ref_url}}, "object type changed"),
        ({"ref": ref_branch_name, "object": {"type": "commit", "sha": "BAD", "url": ref_url}}, "lowercase SHA-40"),
        ({"ref": ref_branch_name, "object": {"type": "commit", "sha": base, "url": ref_url}}, "SHA mismatch"),
        ({"ref": ref_branch_name, "object": {"type": "commit", "sha": head}}, "URL must be a non-empty string"),
        ({"ref": ref_branch_name, "object": {"type": "commit", "sha": head, "url": 7}}, "URL must be a non-empty string"),
    )
    for mutated, expected in read_ref_mutations:
        try:
            validate_read_ref_response(mutated, ref_branch_name, head)
        except ControllerError as exc:
            require(expected in str(exc), f"read-ref response self-test failed for the wrong reason: {exc}")
        else:
            require(False, f"read-ref response self-test accepted forbidden mutation expected to trigger: {expected}")

    workflow_fixture = {
        "id": 12345,
        "path": ".github/workflows/codeql.yml",
        "name": "CodeQL",
        "state": "active",
        "url": "https://api.github.com/repos/portyu9/portyu9/actions/workflows/12345",
        "html_url": "https://github.com/portyu9/portyu9/actions/workflows/codeql.yml",
    }
    require(
        validate_workflow_definition_response(workflow_fixture, ".github/workflows/codeql.yml")
        == {"id": 12345, "path": ".github/workflows/codeql.yml", "name": "CodeQL", "state": "active"},
        "Autofix workflow-definition response positive fixture changed",
    )
    workflow_mutations = (
        ([], "must be an object"),
        ({**workflow_fixture, "id": True}, "must be a positive integer"),
        ({**workflow_fixture, "id": "12345"}, "must be a positive integer"),
        ({**workflow_fixture, "path": ".github/workflows/other.yml"}, "path mismatch"),
        ({**workflow_fixture, "name": "Other"}, "name mismatch"),
        ({**workflow_fixture, "state": "disabled_manually"}, "state changed"),
        ({**workflow_fixture, "url": ""}, "url must be a non-empty string"),
        ({**workflow_fixture, "html_url": None}, "html_url must be a non-empty string"),
    )
    for mutated, expected in workflow_mutations:
        try:
            validate_workflow_definition_response(mutated, ".github/workflows/codeql.yml")
        except ControllerError as exc:
            require(expected in str(exc),
                    f"workflow-definition response self-test failed for the wrong reason: {exc}")
        else:
            require(False,
                    f"workflow-definition response self-test accepted forbidden mutation expected to trigger: {expected}")

    protected_branch = "codeql-autofix/alert-4/run-123"
    protected_workflow_ids = (1001, 1002, 1003)

    def protected_run(
        run_id: Any,
        workflow_id: Any,
        check_suite_id: Any,
        *,
        run_attempt: Any = 1,
        path: Any | None = None,
        name: Any | None = None,
        event_name: Any = "pull_request",
        observed_head: Any = head,
        observed_branch: Any = protected_branch,
        repository: Any = REPOSITORY,
        head_repository: Any = REPOSITORY,
        status: Any = "queued",
        conclusion: Any = None,
    ) -> dict[str, Any]:
        identities = {
            1001: (".github/workflows/codeql.yml", "CodeQL"),
            1002: (".github/workflows/dependency-review.yml", "Dependency review"),
            1003: (".github/workflows/profile-quality.yml", "Profile quality"),
        }
        expected_path, expected_name = identities.get(workflow_id, (".github/workflows/codeql.yml", "CodeQL"))
        return {
            "id": run_id,
            "workflow_id": workflow_id,
            "check_suite_id": check_suite_id,
            "run_attempt": run_attempt,
            "path": expected_path if path is None else path,
            "name": expected_name if name is None else name,
            "event": event_name,
            "head_sha": observed_head,
            "head_branch": observed_branch,
            "repository": {"full_name": repository} if isinstance(repository, str) else repository,
            "head_repository": (
                {"full_name": head_repository} if isinstance(head_repository, str) else head_repository
            ),
            "status": status,
            "conclusion": conclusion,
        }

    protected_response = {
        "total_count": 3,
        "workflow_runs": [
            protected_run(201, 1001, 301, status="completed", conclusion="success"),
            protected_run(202, 1002, 302, status="completed", conclusion="action_required"),
            protected_run(203, 1003, 303, status="waiting", conclusion=None),
        ],
    }
    normalized_protected = validate_protected_workflow_runs_response(
        protected_response,
        expected_sha=head,
        branch=protected_branch,
        codeql_workflow_id=protected_workflow_ids[0],
        dependency_workflow_id=protected_workflow_ids[1],
        profile_workflow_id=protected_workflow_ids[2],
    )
    require(
        normalized_protected["totalCount"] == 3
        and [run["workflowId"] for run in normalized_protected["runs"]] == [1001, 1002, 1003],
        "Autofix protected workflow-run response positive fixture changed",
    )
    protected_mutations = (
        ([], "must be an object"),
        ({"total_count": True, "workflow_runs": []}, "integer in [0,100]"),
        ({"total_count": 101, "workflow_runs": []}, "integer in [0,100]"),
        ({"total_count": 1, "workflow_runs": []}, "does not match returned array length"),
        ({"total_count": 1, "workflow_runs": [None]}, "contains a non-object"),
        ({"total_count": 1, "workflow_runs": [protected_run(True, 1001, 301)]}, "must be a positive integer"),
        ({
            "total_count": 2,
            "workflow_runs": [protected_run(201, 1001, 301), protected_run(201, 1002, 302)],
        }, "duplicate Autofix protected workflow run id"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 9999, 301)]}, "unexpected workflow id"),
        ({
            "total_count": 2,
            "workflow_runs": [protected_run(201, 1001, 301), protected_run(202, 1001, 302)],
        }, "duplicate Autofix protected workflow id"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, True)]}, "must be a positive integer"),
        ({
            "total_count": 2,
            "workflow_runs": [protected_run(201, 1001, 301), protected_run(202, 1002, 301)],
        }, "duplicate Autofix protected workflow check-suite id"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, run_attempt=0)]}, "must be a positive integer"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, path=".github/workflows/other.yml")]}, "path mismatch"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, name="Other")]}, "name mismatch"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, event_name="push")]}, "event changed"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, observed_head="BAD")]}, "lowercase SHA-40"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, observed_head="c" * 40)]}, "head SHA mismatch"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, observed_branch="other")]}, "head branch mismatch"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, repository=None)]}, "repository must be an object"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, head_repository="other/repo")]}, "head_repository identity mismatch"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, status="mystery")]}, "outside the reviewed status set"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, status="queued", conclusion="success")]}, "must be null"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, status="completed", conclusion=None)]}, "reviewed conclusion set"),
        ({"total_count": 1, "workflow_runs": [protected_run(201, 1001, 301, status="completed", conclusion="mystery")]}, "reviewed conclusion set"),
    )
    for mutated, expected in protected_mutations:
        try:
            validate_protected_workflow_runs_response(
                mutated,
                expected_sha=head,
                branch=protected_branch,
                codeql_workflow_id=protected_workflow_ids[0],
                dependency_workflow_id=protected_workflow_ids[1],
                profile_workflow_id=protected_workflow_ids[2],
            )
        except ControllerError as exc:
            require(
                expected in str(exc),
                f"protected workflow-run response self-test failed for the wrong reason: {exc}",
            )
        else:
            require(
                False,
                f"protected workflow-run response self-test accepted forbidden mutation expected to trigger: {expected}",
            )

    def codeql_run(run_id: int, head_sha: str = base, *, status: str = "queued", conclusion: Any = None) -> dict[str, Any]:
        return {
            "id": run_id,
            "name": contract.CODEQL_WORKFLOW_NAME,
            "path": CODEQL_WORKFLOW_PATH,
            "event": "workflow_dispatch",
            "head_branch": DEFAULT_BRANCH,
            "head_sha": head_sha,
            "status": status,
            "conclusion": conclusion,
            "repository": {"full_name": REPOSITORY},
        }

    before_runs = [{"total_count": 1, "workflow_runs": [codeql_run(101, "c" * 40, status="completed", conclusion="success")]}]
    pending = select_new_codeql_dispatch_run(before_runs, before_runs, base)
    require(pending == {"state": "pending", "runId": None, "headSha": base},
            "post-merge CodeQL pending fixture changed")
    after_runs = [{"total_count": 2, "workflow_runs": [
        codeql_run(102, base),
        codeql_run(101, "c" * 40, status="completed", conclusion="success"),
    ]}]
    bound = select_new_codeql_dispatch_run(before_runs, after_runs, base)
    require(bound["state"] == "bound" and bound["runId"] == 102,
            "post-merge CodeQL exact-run binding fixture changed")
    verified = validate_bound_codeql_run(codeql_run(102, base, status="completed", conclusion="success"), 102, base)
    require(verified["status"] == "completed" and verified["conclusion"] == "success",
            "post-merge CodeQL completion fixture changed")
    ambiguous_runs = [{"total_count": 3, "workflow_runs": [
        codeql_run(103, base),
        codeql_run(102, base),
        codeql_run(101, "c" * 40, status="completed", conclusion="success"),
    ]}]
    try:
        select_new_codeql_dispatch_run(before_runs, ambiguous_runs, base)
    except ControllerError as exc:
        require("ambiguous" in str(exc), f"post-merge CodeQL ambiguity failed for wrong reason: {exc}")
    else:
        require(False, "post-merge CodeQL binding accepted multiple newly dispatched exact-SHA runs")
    try:
        validate_bound_codeql_run(codeql_run(102, "d" * 40), 102, base)
    except ControllerError as exc:
        require("head SHA changed" in str(exc), f"post-merge CodeQL stale-run fixture failed for wrong reason: {exc}")
    else:
        require(False, "post-merge CodeQL validation accepted a stale run")

    evidence_target = {
        "number": 10,
        "ruleId": "py/unsupported",
        "securitySeverity": "high",
        "baseSha": base,
        "location": {"path": "scripts/example.py", "startLine": 7, "endLine": 9},
    }
    evidence = unsupported_evidence_decision(evidence_target, [[]], base)
    require(evidence["exists"] is False and "alert=10" in evidence["marker"],
            "unsupported evidence absence fixture changed")
    existing_comment = {
        "id": 44,
        "commit_id": base,
        "body": evidence["body"],
        "user": {"login": "github-actions[bot]"},
    }
    existing = unsupported_evidence_decision(evidence_target, [[existing_comment]], base)
    require(existing["exists"] is True, "unsupported evidence deduplication fixture changed")
    created = validate_created_unsupported_evidence(existing_comment, base, evidence["marker"])
    require(created["id"] == 44, "unsupported evidence creation fixture changed")
    spoofed_comment = {**existing_comment, "id": 45, "user": {"login": "human"}}
    require(
        unsupported_evidence_decision(evidence_target, [[spoofed_comment]], base)["exists"] is False,
        "human marker must not suppress trusted unsupported evidence",
    )
    duplicate = {**existing_comment, "id": 46}
    try:
        unsupported_evidence_decision(evidence_target, [[existing_comment, duplicate]], base)
    except ControllerError as exc:
        require("duplicate trusted" in str(exc), f"unsupported evidence duplicate fixture failed for wrong reason: {exc}")
    else:
        require(False, "unsupported evidence accepted duplicate trusted markers")
    try:
        unsupported_evidence_decision({**evidence_target, "baseSha": "c" * 40}, [[]], base)
    except ControllerError as exc:
        require("stale" in str(exc), f"unsupported evidence stale-base fixture failed for wrong reason: {exc}")
    else:
        require(False, "unsupported evidence accepted stale alert identity")

    approval_pr = 17
    approval_marker = f"<!-- portyu9-automation-approval:v1 head={head} -->"
    approval_body = approval_marker + "\nAutomation-approved exact head."
    approval_issue_url = f"https://api.github.com/repos/{REPOSITORY}/issues/{approval_pr}"
    approval_comment = {
        "id": 77,
        "issue_url": approval_issue_url,
        "html_url": "https://github.com/portyu9/portyu9/pull/17#issuecomment-77",
        "body": approval_body,
        "user": {"login": "github-actions[bot]"},
    }
    approval = approval_comment_evidence(
        [[approval_comment]],
        pr_number=approval_pr,
        marker=approval_marker,
    )
    require(
        approval == {
            "exists": True,
            "commentId": 77,
            "prNumber": approval_pr,
            "marker": approval_marker,
        },
        "Autofix approval-comment evidence positive fixture changed",
    )
    human_marker = {
        **approval_comment,
        "id": 78,
        "user": {"login": "portyu9"},
    }
    require(
        approval_comment_evidence(
            [[human_marker]],
            pr_number=approval_pr,
            marker=approval_marker,
        )["exists"]
        is False,
        "human marker must not suppress the trusted Autofix approval comment",
    )
    try:
        approval_comment_evidence(
            [[approval_comment, {**approval_comment, "id": 79}]],
            pr_number=approval_pr,
            marker=approval_marker,
        )
    except ControllerError as exc:
        require(
            "duplicate trusted" in str(exc),
            f"approval-comment duplicate fixture failed for the wrong reason: {exc}",
        )
    else:
        require(False, "approval-comment evidence accepted duplicate trusted markers")

    approval_mutations = (
        ({}, "slurped page array"),
        ([], "between 1 and 20"),
        ([[None]], "contains a non-object"),
        ([[{**approval_comment, "id": True}]], "positive integer"),
        ([[approval_comment, approval_comment]], "duplicate Autofix approval comment id"),
        ([[{**approval_comment, "issue_url": "https://api.github.com/repos/other/repo/issues/17"}]], "issue URL mismatch"),
        ([[{**approval_comment, "body": None}]], "body must be a string"),
        ([[{**approval_comment, "user": None}]], "user must be an object"),
        ([[{**approval_comment, "user": {"login": ""}}]], "user.login must be non-empty"),
        ([[{**approval_comment, "html_url": ""}]], "html_url must be non-empty"),
    )
    for mutated, expected in approval_mutations:
        try:
            approval_comment_evidence(
                mutated,
                pr_number=approval_pr,
                marker=approval_marker,
            )
        except ControllerError as exc:
            require(
                expected in str(exc),
                f"approval-comment evidence self-test failed for the wrong reason: {exc}",
            )
        else:
            require(
                False,
                f"approval-comment evidence accepted forbidden mutation expected to trigger: {expected}",
            )
    try:
        approval_comment_evidence(
            [[approval_comment]],
            pr_number=approval_pr,
            marker="not-a-marker",
        )
    except ControllerError as exc:
        require(
            "marker is malformed" in str(exc),
            f"approval-comment marker self-test failed for the wrong reason: {exc}",
        )
    else:
        require(False, "approval-comment evidence accepted malformed marker")

    created_approval = validate_created_approval_comment(
        approval_comment,
        pr_number=approval_pr,
        expected_body=approval_body,
    )
    require(
        created_approval["id"] == 77
        and created_approval["actor"] == "github-actions[bot]",
        "created Autofix approval-comment positive fixture changed",
    )
    created_approval_mutations = (
        ([], "must be an object"),
        ({**approval_comment, "id": 0}, "positive integer"),
        ({**approval_comment, "issue_url": "https://api.github.com/repos/other/repo/issues/17"}, "issue URL mismatch"),
        ({**approval_comment, "body": "wrong"}, "body mismatch"),
        ({**approval_comment, "user": {"login": "portyu9"}}, "actor mismatch"),
        ({**approval_comment, "html_url": ""}, "html_url must be non-empty"),
    )
    for mutated, expected in created_approval_mutations:
        try:
            validate_created_approval_comment(
                mutated,
                pr_number=approval_pr,
                expected_body=approval_body,
            )
        except ControllerError as exc:
            require(
                expected in str(exc),
                f"created approval-comment self-test failed for the wrong reason: {exc}",
            )
        else:
            require(
                False,
                f"created approval-comment accepted forbidden mutation expected to trigger: {expected}",
            )

    pages = [[{"number": 1, "state": "open", "base": {"ref": "main", "sha": base},
               "head": {"ref": "codeql-autofix/alert-4/run-123", "sha": head}, "draft": False, "node_id": "PR_x"}]]
    located = locate_existing(pages, 4)
    require(located["exists"] and located["pr"]["originRunId"] == 123, "existing PR locator changed")
    require(flatten_pages([[1], [2]]) == [1, 2], "pagination flattening changed")

    prior_attempt = {
        "id": 123,
        "run_attempt": 1,
        "name": contract.WORKFLOW_NAME,
        "path": contract.WORKFLOW_PATH,
        "event": "workflow_run",
        "head_branch": DEFAULT_BRANCH,
        "head_sha": base,
        "status": "completed",
        "conclusion": "cancelled",
        "check_suite_id": 3001,
        "actor": {"login": "portyu9"},
        "triggering_actor": {"login": "portyu9"},
        "repository": {"full_name": REPOSITORY},
        "head_repository": {"full_name": REPOSITORY},
    }
    history = normalize_prior_attempt_history(
        [prior_attempt],
        run_id=123,
        run_attempt=2,
        event_name="workflow_run",
        base_sha=base,
    )
    require(history == [{
        "attempt": 1,
        "checkSuiteId": 3001,
        "status": "completed",
        "conclusion": "cancelled",
        "actor": "portyu9",
        "triggeringActor": "portyu9",
    }], "Autofix retry-history positive fixture changed")
    retry_mutations = (
        ([], 2, "every prior attempt"),
        ([{**prior_attempt, "run_attempt": 2}], 2, "not contiguous"),
        ([{**prior_attempt, "status": "in_progress", "conclusion": None}], 2, "not terminal"),
        ([{**prior_attempt, "head_sha": "c" * 40}], 2, "source identity changed"),
        ([{**prior_attempt, "actor": {}}], 2, "actor identity is missing"),
    )
    for mutated, attempt_number, expected in retry_mutations:
        try:
            normalize_prior_attempt_history(
                mutated,
                run_id=123,
                run_attempt=attempt_number,
                event_name="workflow_run",
                base_sha=base,
            )
        except ControllerError as exc:
            require(expected in str(exc), f"retry-history self-test failed for the wrong reason: {exc}")
        else:
            require(False, f"retry-history self-test accepted forbidden mutation expected to trigger: {expected}")

    artifact = {
        "id": 91,
        "name": contract.receipt_name(123, 4),
        "expired": False,
        "digest": "sha256:" + "d" * 64,
        "workflow_run": {"id": 123, "head_branch": DEFAULT_BRANCH, "head_sha": base},
    }
    selected = select_artifact({"total_count": 1, "artifacts": [artifact]}, 123, 4)
    require(selected["id"] == 91, "artifact-list positive fixture changed")
    artifact_mutations = (
        ({"artifacts": [artifact]}, "total_count must be a nonnegative integer"),
        ({"total_count": True, "artifacts": [artifact]}, "total_count must be a nonnegative integer"),
        ({"total_count": -1, "artifacts": [artifact]}, "total_count must be a nonnegative integer"),
        ({"total_count": 2, "artifacts": [artifact]}, "artifact list response is incomplete"),
        ({"total_count": 1, "artifacts": [None]}, "artifact list contains a non-object"),
        ({"total_count": 1, "artifacts": [{**artifact, "id": 0}]}, "artifact id must be a positive integer"),
        ({"total_count": 1, "artifacts": [{**artifact, "name": 7}]}, "artifact name must be a non-empty string"),
        ({"total_count": 1, "artifacts": [{**artifact, "expired": "false"}]}, "receipt artifact expired must be a boolean"),
        ({"total_count": 1, "artifacts": [{**artifact, "expired": True}]}, "controller receipt artifact is expired"),
        ({"total_count": 1, "artifacts": [{**artifact, "digest": "sha256:not-a-digest"}]}, "receipt artifact digest must be a sha256 digest"),
        ({"total_count": 1, "artifacts": [{**artifact, "workflow_run": None}]}, "receipt artifact workflow_run must be an object"),
        ({"total_count": 1, "artifacts": [{**artifact, "workflow_run": {"id": "123", "head_branch": DEFAULT_BRANCH, "head_sha": base}}]}, "workflow_run id must be a positive integer"),
        ({"total_count": 1, "artifacts": [{**artifact, "workflow_run": {"id": 124, "head_branch": DEFAULT_BRANCH, "head_sha": base}}]}, "belongs to another workflow run"),
        ({"total_count": 1, "artifacts": [{**artifact, "workflow_run": {"id": 123, "head_branch": "other", "head_sha": base}}]}, "head branch changed"),
        ({"total_count": 1, "artifacts": [{**artifact, "workflow_run": {"id": 123, "head_branch": DEFAULT_BRANCH, "head_sha": "BAD"}}]}, "lowercase SHA-40"),
        ({"total_count": 1, "artifacts": [{**artifact, "name": "other"}]}, "expected exactly one controller receipt artifact"),
        ({"total_count": 2, "artifacts": [artifact, {**artifact, "id": 92}]}, "expected exactly one controller receipt artifact"),
    )
    for mutated, expected in artifact_mutations:
        try:
            select_artifact(mutated, 123, 4)
        except ControllerError as exc:
            require(expected in str(exc), f"artifact-list self-test failed for the wrong reason: {exc}")
        else:
            require(False, f"artifact-list self-test accepted forbidden mutation expected to trigger: {expected}")

    oversized_artifacts = {
        "total_count": 101,
        "artifacts": [{"id": index + 1, "name": f"other-{index}"} for index in range(101)],
    }
    try:
        select_artifact(oversized_artifacts, 123, 4)
    except ControllerError as exc:
        require("exceeds one complete reviewed page" in str(exc), f"artifact-list page-bound self-test failed: {exc}")
    else:
        require(False, "artifact-list self-test accepted more than one reviewed page")

    thread_response = {
        "data": {
            "repository": {
                "pullRequest": {
                    "reviewThreads": {
                        "nodes": [{"isResolved": True}, {"isResolved": False}],
                        "pageInfo": {"hasNextPage": False},
                    }
                }
            }
        }
    }
    require(unresolved_threads(thread_response) == 1, "review-thread positive fixture changed")
    thread_mutations = (
        ({**thread_response, "errors": [{"message": "partial GraphQL failure"}]}, "contains errors"),
        ({"data": {"repository": {"pullRequest": {"reviewThreads": {
            "nodes": [{"isResolved": False}], "pageInfo": {"hasNextPage": True}
        }}}}}, "pagination is incomplete"),
        ({"data": {"repository": {"pullRequest": {"reviewThreads": {
            "nodes": [None], "pageInfo": {"hasNextPage": False}
        }}}}}, "non-object node"),
        ({"data": {"repository": {"pullRequest": {"reviewThreads": {
            "nodes": [{}], "pageInfo": {"hasNextPage": False}
        }}}}}, "isResolved must be a boolean"),
        ({"data": {"repository": {"pullRequest": {"reviewThreads": {
            "nodes": [{"isResolved": "false"}], "pageInfo": {"hasNextPage": False}
        }}}}}, "isResolved must be a boolean"),
        ({"data": {"repository": {"pullRequest": {"reviewThreads": {
            "nodes": [{"isResolved": 0}], "pageInfo": {"hasNextPage": False}
        }}}}}, "isResolved must be a boolean"),
        ({"data": {"repository": {"pullRequest": {"reviewThreads": {
            "nodes": [{"isResolved": None}], "pageInfo": {"hasNextPage": False}
        }}}}}, "isResolved must be a boolean"),
        ({"data": {"repository": {"pullRequest": {"reviewThreads": {
            "nodes": [], "pageInfo": {"hasNextPage": "false"}
        }}}}}, "hasNextPage must be a boolean"),
    )
    for mutated, expected in thread_mutations:
        try:
            unresolved_threads(mutated)
        except ControllerError as exc:
            require(expected in str(exc), f"review-thread self-test failed for the wrong reason: {exc}")
        else:
            require(False, f"review-thread self-test accepted forbidden mutation expected to trigger: {expected}")

    readiness_name = "trusted-capability-admission"
    readiness_app = 15368

    def readiness_fixture(
        *, check_id: Any = 11, name: Any = readiness_name, observed_head: Any = head,
        observed_app: Any = readiness_app, status: Any = "completed",
        conclusion: Any = "success",
    ) -> dict[str, Any]:
        return {
            "total_count": 1,
            "check_runs": [{
                "id": check_id,
                "name": name,
                "head_sha": observed_head,
                "app": {"id": observed_app},
                "status": status,
                "conclusion": conclusion,
            }],
        }

    require(
        validate_check_run_readiness(readiness_fixture(), head, readiness_name, readiness_app)["state"] == "success",
        "readiness check-run success fixture changed",
    )
    require(
        validate_check_run_readiness(
            readiness_fixture(status="queued", conclusion=None), head, readiness_name, readiness_app
        )["state"] == "pending",
        "readiness check-run pending fixture changed",
    )
    require(
        validate_check_run_readiness(
            readiness_fixture(conclusion="failure"), head, readiness_name, readiness_app
        )["state"] == "failure",
        "readiness check-run failure fixture changed",
    )
    require(
        validate_check_run_readiness(
            {"total_count": 0, "check_runs": []}, head, readiness_name, readiness_app
        ) == {"state": "missing", "count": 0},
        "readiness check-run missing fixture changed",
    )
    ambiguous = {
        "total_count": 2,
        "check_runs": [
            readiness_fixture(check_id=11)["check_runs"][0],
            readiness_fixture(check_id=12)["check_runs"][0],
        ],
    }
    require(
        validate_check_run_readiness(ambiguous, head, readiness_name, readiness_app)
        == {"state": "ambiguous", "count": 2},
        "readiness check-run ambiguity fixture changed",
    )
    readiness_mutations = (
        ([], "must be an object"),
        ({"total_count": True, "check_runs": []}, "integer in [0,100]"),
        ({"total_count": 101, "check_runs": []}, "integer in [0,100]"),
        ({"total_count": 1, "check_runs": []}, "does not match returned array length"),
        ({"total_count": 1, "check_runs": [None]}, "contains a non-object"),
        (readiness_fixture(check_id=True), "must be a positive integer"),
        (readiness_fixture(check_id=0), "must be a positive integer"),
        ({
            "total_count": 2,
            "check_runs": [
                readiness_fixture(check_id=11)["check_runs"][0],
                readiness_fixture(check_id=11)["check_runs"][0],
            ],
        }, "ids must be unique"),
        (readiness_fixture(name="wrong"), "name differs"),
        (readiness_fixture(observed_head="BAD"), "lowercase SHA-40"),
        (readiness_fixture(observed_head="c" * 40), "differs from the exact candidate"),
        (readiness_fixture(observed_app="15368"), "app identity mismatch"),
        (readiness_fixture(observed_app=57789), "app identity mismatch"),
        (readiness_fixture(status="unknown", conclusion=None), "outside the reviewed status set"),
        (readiness_fixture(status="queued", conclusion="success"), "must be null"),
        (readiness_fixture(status="completed", conclusion=None), "must be a non-empty string"),
        (readiness_fixture(status="completed", conclusion=""), "must be a non-empty string"),
    )
    for mutated, expected in readiness_mutations:
        try:
            validate_check_run_readiness(mutated, head, readiness_name, readiness_app)
        except ControllerError as exc:
            require(expected in str(exc),
                    f"readiness check-run self-test failed for the wrong reason: {exc}")
        else:
            require(False,
                    f"readiness check-run self-test accepted forbidden mutation expected to trigger: {expected}")

    ref_branch = "codeql-autofix/alert-4/run-123"
    expected_ref = f"refs/heads/{ref_branch}"
    require(
        classify_branch_ref_inventory([], ref_branch)
        == {"state": "absent", "ref": expected_ref, "sha": None},
        "matching-ref absence fixture changed",
    )
    existing_ref = [{"ref": expected_ref, "object": {"type": "commit", "sha": head}}]
    require(
        classify_branch_ref_inventory(existing_ref, ref_branch)
        == {"state": "existing", "ref": expected_ref, "sha": head},
        "matching-ref existing fixture changed",
    )
    ref_mutations = (
        ({}, "must be an array"),
        ([None], "non-object"),
        ([{"ref": 7, "object": {"type": "commit", "sha": head}}], "ref must be a string"),
        ([{"ref": expected_ref + "/nested", "object": {"type": "commit", "sha": head}}], "non-exact ref"),
        ([{"ref": expected_ref}], "missing object"),
        ([{"ref": expected_ref, "object": {"type": "tag", "sha": head}}], "object type changed"),
        ([{"ref": expected_ref, "object": {"type": "commit", "sha": 7}}], "lowercase SHA-40"),
        ([{"ref": expected_ref, "object": {"type": "commit", "sha": head}},
          {"ref": expected_ref, "object": {"type": "commit", "sha": head}}], "ambiguous"),
    )
    for mutated, expected in ref_mutations:
        try:
            classify_branch_ref_inventory(mutated, ref_branch)
        except ControllerError as exc:
            require(expected in str(exc), f"matching-ref self-test failed for the wrong reason: {exc}")
        else:
            require(False, f"matching-ref self-test accepted forbidden mutation expected to trigger: {expected}")

    created_ref = {"ref": expected_ref, "object": {"type": "commit", "sha": base}}
    require(
        validate_created_ref_response(created_ref, ref_branch, base)
        == {"ref": expected_ref, "sha": base},
        "Autofix created-ref response positive fixture changed",
    )
    created_ref_mutations = (
        ([], "must be an object"),
        ({"ref": 7, "object": {"type": "commit", "sha": base}}, "ref must be a string"),
        ({"ref": "refs/heads/wrong", "object": {"type": "commit", "sha": base}}, "ref mismatch"),
        ({"ref": expected_ref, "object": None}, "object must be an object"),
        ({"ref": expected_ref, "object": {"type": "tag", "sha": base}}, "object type changed"),
        ({"ref": expected_ref, "object": {"type": "commit", "sha": 7}}, "lowercase SHA-40"),
        ({"ref": expected_ref, "object": {"type": "commit", "sha": head}}, "SHA mismatch"),
    )
    for mutated, expected in created_ref_mutations:
        try:
            validate_created_ref_response(mutated, ref_branch, base)
        except ControllerError as exc:
            require(expected in str(exc), f"created-ref response self-test failed for the wrong reason: {exc}")
        else:
            require(False, f"created-ref response self-test accepted forbidden mutation expected to trigger: {expected}")

    reviewer_response = {
        "number": 17,
        "state": "open",
        "draft": False,
        "base": {"ref": "main", "sha": base, "repo": {"full_name": "portyu9/portyu9"}},
        "head": {"ref": ref_branch, "sha": head, "repo": {"full_name": "portyu9/portyu9"}},
        "requested_reviewers": [{"login": "portyu9", "id": 35150859}],
    }
    reviewer_args = {
        "pr_number": 17,
        "repository": "portyu9/portyu9",
        "base_sha": base,
        "branch": ref_branch,
        "head_sha": head,
    }
    require(
        validate_reviewer_request_response(reviewer_response, **reviewer_args)
        == {"prNumber": 17, "reviewer": "portyu9", "headSha": head},
        "Autofix reviewer-request response positive fixture changed",
    )
    reviewer_mutations = (
        ([], "must be an object"),
        ({**reviewer_response, "number": 18}, "PR number mismatch"),
        ({**reviewer_response, "state": "closed"}, "state changed"),
        ({**reviewer_response, "draft": "false"}, "draft state changed"),
        ({**reviewer_response, "base": {**reviewer_response["base"], "sha": "c" * 40}}, "base SHA mismatch"),
        ({**reviewer_response, "head": {**reviewer_response["head"], "ref": "wrong"}}, "head ref mismatch"),
        ({**reviewer_response, "head": {**reviewer_response["head"], "repo": {"full_name": "other/repo"}}},
         "head repository mismatch"),
        ({**reviewer_response, "requested_reviewers": None}, "must be an array"),
        ({**reviewer_response, "requested_reviewers": [None]}, "non-object reviewer"),
        ({**reviewer_response, "requested_reviewers": [{"login": "", "id": 1}]}, "login must be a non-empty string"),
        ({**reviewer_response, "requested_reviewers": [{"login": "portyu9", "id": 1}, {"login": "portyu9", "id": 2}]},
         "duplicate reviewer logins"),
        ({**reviewer_response, "requested_reviewers": [{"login": "other", "id": 1}]},
         "exactly one portyu9 reviewer"),
    )
    for mutated, expected in reviewer_mutations:
        try:
            validate_reviewer_request_response(mutated, **reviewer_args)
        except ControllerError as exc:
            require(expected in str(exc), f"reviewer-request response self-test failed for the wrong reason: {exc}")
        else:
            require(False, f"reviewer-request response self-test accepted forbidden mutation expected to trigger: {expected}")

    pr_response = {
        "number": 17,
        "state": "open",
        "draft": False,
        "base": {"ref": "main", "sha": base, "repo": {"full_name": REPOSITORY}},
        "head": {"ref": ref_branch, "sha": head, "repo": {"full_name": REPOSITORY}},
    }
    pr_args = {
        "pr_number": 17,
        "repository": REPOSITORY,
        "base_sha": base,
        "branch": ref_branch,
        "head_sha": head,
    }
    require(
        validate_pull_request_response(pr_response, **pr_args)
        == {
            "prNumber": 17,
            "state": "open",
            "draft": False,
            "baseRef": "main",
            "baseSha": base,
            "headRef": ref_branch,
            "headSha": head,
            "repository": REPOSITORY,
        },
        "Autofix pull-request response positive fixture changed",
    )
    pr_mutations = (
        ([], "must be an object"),
        ({**pr_response, "number": True}, "must be a positive integer"),
        ({**pr_response, "number": "17"}, "must be a positive integer"),
        ({**pr_response, "number": 18}, "PR number mismatch"),
        ({**pr_response, "state": "closed"}, "state changed"),
        ({**pr_response, "draft": "false"}, "draft state changed"),
        ({**pr_response, "draft": True}, "draft state changed"),
        ({**pr_response, "base": None}, "base must be an object"),
        ({**pr_response, "head": None}, "head must be an object"),
        ({**pr_response, "base": {**pr_response["base"], "ref": "other"}}, "base ref changed"),
        ({**pr_response, "base": {**pr_response["base"], "sha": "BAD"}}, "lowercase SHA-40"),
        ({**pr_response, "base": {**pr_response["base"], "sha": "c" * 40}}, "base SHA mismatch"),
        ({**pr_response, "head": {**pr_response["head"], "ref": "wrong"}}, "head ref mismatch"),
        ({**pr_response, "head": {**pr_response["head"], "sha": "BAD"}}, "lowercase SHA-40"),
        ({**pr_response, "head": {**pr_response["head"], "sha": "c" * 40}}, "head SHA mismatch"),
        ({**pr_response, "base": {**pr_response["base"], "repo": None}}, "base repository must be an object"),
        ({**pr_response, "head": {**pr_response["head"], "repo": None}}, "head repository must be an object"),
        ({**pr_response, "base": {**pr_response["base"], "repo": {"full_name": "other/repo"}}},
         "base repository mismatch"),
        ({**pr_response, "head": {**pr_response["head"], "repo": {"full_name": "other/repo"}}},
         "head repository mismatch"),
    )
    for mutated, expected in pr_mutations:
        try:
            validate_pull_request_response(mutated, **pr_args)
        except ControllerError as exc:
            require(expected in str(exc),
                    f"pull-request response self-test failed for the wrong reason: {exc}")
        else:
            require(False,
                    f"pull-request response self-test accepted forbidden mutation expected to trigger: {expected}")

    merge_success = {"merged": True, "sha": head, "message": "Pull Request successfully merged"}
    require(
        validate_merge_success_response(merge_success)
        == {"merged": True, "sha": head, "message": "Pull Request successfully merged"},
        "Autofix merge-success response positive fixture changed",
    )
    merge_success_mutations = (
        ([], "must be an object"),
        ({"merged": "true", "sha": head, "message": "merged"}, "merged must be a boolean"),
        ({"merged": 1, "sha": head, "message": "merged"}, "merged must be a boolean"),
        ({"merged": False, "sha": head, "message": "not merged"}, "did not report merged=true"),
        ({"merged": True, "sha": "BAD", "message": "merged"}, "lowercase SHA-40"),
        ({"merged": True, "message": "merged"}, "lowercase SHA-40"),
        ({"merged": True, "sha": head}, "message must be a non-empty string"),
        ({"merged": True, "sha": head, "message": 7}, "message must be a non-empty string"),
        ({"merged": True, "sha": head, "message": "   "}, "message must be a non-empty string"),
    )
    for mutated, expected in merge_success_mutations:
        try:
            validate_merge_success_response(mutated)
        except ControllerError as exc:
            require(expected in str(exc), f"merge-success response self-test failed for the wrong reason: {exc}")
        else:
            require(False, f"merge-success response self-test accepted forbidden mutation expected to trigger: {expected}")

    compare = {
        "base_commit": {"sha": base},
        "merge_base_commit": {"sha": base},
        "status": "ahead",
        "ahead_by": 1,
        "total_commits": 1,
        "commits": [{"sha": head}],
        "files": [{"filename": "scripts/autofix_acceptance_fixture.py", "status": "modified"}],
    }
    require(validate_compare(compare, base, head)["headSha"] == head, "compare positive fixture changed")
    compare_mutations = (
        ({**compare, "total_commits": 2}, "exactly one commit"),
        ({**compare, "commits": []}, "exactly one commit"),
        ({**compare, "commits": [{"sha": head}, {"sha": "c" * 40}]}, "exactly one commit"),
        ({**compare, "commits": [{"sha": "c" * 40}]}, "compare head identity mismatch"),
    )
    for mutated, expected in compare_mutations:
        try:
            validate_compare(mutated, base, head)
        except ControllerError as exc:
            require(expected in str(exc), f"compare self-test failed for the wrong reason: {exc}")
        else:
            require(False, f"compare self-test accepted forbidden mutation expected to trigger: {expected}")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("trigger")
    p.add_argument("--event-name", required=True)
    p.add_argument("--event-file", required=True)
    p.add_argument("--trusted-sha", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("main")
    p.add_argument("--ref-file", required=True)
    p.add_argument("--expected-sha", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("read-ref-response")
    p.add_argument("--response-file", required=True)
    p.add_argument("--expected-ref", required=True)
    p.add_argument("--expected-sha", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("workflow-definition-response")
    p.add_argument("--response-file", required=True)
    p.add_argument("--expected-path", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("protected-workflow-runs-response")
    p.add_argument("--response-file", required=True)
    p.add_argument("--head-sha", required=True)
    p.add_argument("--branch", required=True)
    p.add_argument("--codeql-workflow-id", type=int, required=True)
    p.add_argument("--dependency-workflow-id", type=int, required=True)
    p.add_argument("--profile-workflow-id", type=int, required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("discover")
    p.add_argument("--alerts-file", required=True)
    p.add_argument("--base-sha", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("locate")
    p.add_argument("--prs-file", required=True)
    p.add_argument("--alert", type=int, required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("status")
    p.add_argument("--target-file", required=True)
    p.add_argument("--status-file", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("unsupported-evidence")
    p.add_argument("--target-file", required=True)
    p.add_argument("--comments-file", required=True)
    p.add_argument("--expected-sha", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("unsupported-evidence-created")
    p.add_argument("--comment-file", required=True)
    p.add_argument("--expected-sha", required=True)
    p.add_argument("--marker", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("approval-comment-evidence")
    p.add_argument("--comments-file", required=True)
    p.add_argument("--pr-number", type=int, required=True)
    p.add_argument("--marker", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("approval-comment-created")
    p.add_argument("--comment-file", required=True)
    p.add_argument("--pr-number", type=int, required=True)
    p.add_argument("--expected-body", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("ref-state")
    p.add_argument("--refs-file", required=True)
    p.add_argument("--branch", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("created-ref-response")
    p.add_argument("--response-file", required=True)
    p.add_argument("--branch", required=True)
    p.add_argument("--expected-sha", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("reviewer-request-response")
    p.add_argument("--response-file", required=True)
    p.add_argument("--pr-number", type=int, required=True)
    p.add_argument("--repository", required=True)
    p.add_argument("--base-sha", required=True)
    p.add_argument("--branch", required=True)
    p.add_argument("--head-sha", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("pull-request-response")
    p.add_argument("--response-file", required=True)
    p.add_argument("--pr-number", type=int, required=True)
    p.add_argument("--repository", required=True)
    p.add_argument("--base-sha", required=True)
    p.add_argument("--branch", required=True)
    p.add_argument("--head-sha", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("commit")
    p.add_argument("--response-file", required=True)
    p.add_argument("--branch", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("compare")
    p.add_argument("--compare-file", required=True)
    p.add_argument("--base-sha", required=True)
    p.add_argument("--head-sha", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("readiness-check")
    p.add_argument("--response-file", required=True)
    p.add_argument("--head-sha", required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--app-id", type=int, required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("merge-success-response")
    p.add_argument("--response-file", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("followup-select")
    p.add_argument("--before-file", required=True)
    p.add_argument("--after-file", required=True)
    p.add_argument("--expected-sha", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("followup-run")
    p.add_argument("--run-file", required=True)
    p.add_argument("--run-id", type=int, required=True)
    p.add_argument("--expected-sha", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("receipt")
    p.add_argument("--run-id", type=int, required=True)
    p.add_argument("--run-attempt", type=int, required=True)
    p.add_argument("--event-name", required=True)
    p.add_argument("--base-sha", required=True)
    p.add_argument("--target-file", required=True)
    p.add_argument("--branch", required=True)
    p.add_argument("--head-sha", required=True)
    p.add_argument("--pr-file", required=True)
    p.add_argument("--attempt-history-file", required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("artifact")
    p.add_argument("--artifacts-file", required=True)
    p.add_argument("--run-id", type=int, required=True)
    p.add_argument("--alert", type=int, required=True)
    p.add_argument("--out", required=True)

    p = sub.add_parser("admit")
    for name in ("receipt", "workflow-run", "artifact", "pr", "main-ref", "checks", "ghas", "pr-alerts", "threads", "out"):
        p.add_argument(f"--{name}", required=True)

    args = parser.parse_args()
    if args.command == "trigger":
        dump(args.out, validate_trigger(args.event_name, load(args.event_file), args.trusted_sha))
    elif args.command == "main":
        dump(args.out, current_main(load(args.ref_file), args.expected_sha))
    elif args.command == "read-ref-response":
        dump(args.out, validate_read_ref_response(
            load(args.response_file), args.expected_ref, args.expected_sha
        ))
    elif args.command == "workflow-definition-response":
        dump(args.out, validate_workflow_definition_response(
            load(args.response_file), args.expected_path
        ))
    elif args.command == "protected-workflow-runs-response":
        dump(args.out, validate_protected_workflow_runs_response(
            load(args.response_file),
            expected_sha=args.head_sha,
            branch=args.branch,
            codeql_workflow_id=args.codeql_workflow_id,
            dependency_workflow_id=args.dependency_workflow_id,
            profile_workflow_id=args.profile_workflow_id,
        ))
    elif args.command == "discover":
        dump(args.out, discover_target(load(args.alerts_file), args.base_sha))
    elif args.command == "locate":
        dump(args.out, locate_existing(load(args.prs_file), args.alert))
    elif args.command == "status":
        target = load(args.target_file)
        require(isinstance(target, Mapping), "target file must be an object")
        dump(args.out, normalize_status(target, load(args.status_file)))
    elif args.command == "unsupported-evidence":
        dump(args.out, unsupported_evidence_decision(
            load(args.target_file), load(args.comments_file), args.expected_sha
        ))
    elif args.command == "unsupported-evidence-created":
        dump(args.out, validate_created_unsupported_evidence(
            load(args.comment_file), args.expected_sha, args.marker
        ))
    elif args.command == "approval-comment-evidence":
        dump(args.out, approval_comment_evidence(
            load(args.comments_file),
            pr_number=args.pr_number,
            marker=args.marker,
        ))
    elif args.command == "approval-comment-created":
        dump(args.out, validate_created_approval_comment(
            load(args.comment_file),
            pr_number=args.pr_number,
            expected_body=args.expected_body,
        ))
    elif args.command == "ref-state":
        dump(args.out, classify_branch_ref_inventory(load(args.refs_file), args.branch))
    elif args.command == "created-ref-response":
        dump(args.out, validate_created_ref_response(load(args.response_file), args.branch, args.expected_sha))
    elif args.command == "reviewer-request-response":
        dump(args.out, validate_reviewer_request_response(
            load(args.response_file),
            pr_number=args.pr_number,
            repository=args.repository,
            base_sha=args.base_sha,
            branch=args.branch,
            head_sha=args.head_sha,
        ))
    elif args.command == "pull-request-response":
        dump(args.out, validate_pull_request_response(
            load(args.response_file),
            pr_number=args.pr_number,
            repository=args.repository,
            base_sha=args.base_sha,
            branch=args.branch,
            head_sha=args.head_sha,
        ))
    elif args.command == "commit":
        dump(args.out, validate_commit_response(load(args.response_file), args.branch))
    elif args.command == "compare":
        dump(args.out, validate_compare(load(args.compare_file), args.base_sha, args.head_sha))
    elif args.command == "readiness-check":
        dump(args.out, validate_check_run_readiness(
            load(args.response_file), args.head_sha, args.name, args.app_id
        ))
    elif args.command == "merge-success-response":
        dump(args.out, validate_merge_success_response(load(args.response_file)))
    elif args.command == "followup-select":
        dump(args.out, select_new_codeql_dispatch_run(load(args.before_file), load(args.after_file), args.expected_sha))
    elif args.command == "followup-run":
        dump(args.out, validate_bound_codeql_run(load(args.run_file), args.run_id, args.expected_sha))
    elif args.command == "receipt":
        target = load(args.target_file)
        require(isinstance(target, Mapping), "target file must be an object")
        dump(args.out, build_receipt(run_id=args.run_id, run_attempt=args.run_attempt, event_name=args.event_name,
                                     base_sha=args.base_sha, target=target, branch=args.branch, head_sha=args.head_sha,
                                     pr_response=load(args.pr_file), prior_attempts=load(args.attempt_history_file)))
    elif args.command == "artifact":
        dump(args.out, select_artifact(load(args.artifacts_file), args.run_id, args.alert))
    elif args.command == "admit":
        pr = load(args.pr)
        require(isinstance(pr, Mapping), "PR response must be an object")
        files = pr.get("files")
        require(isinstance(files, list), "PR response wrapper must include files")
        pr_payload = pr.get("pullRequest")
        require(isinstance(pr_payload, Mapping), "PR response wrapper must include pullRequest")
        enriched = dict(pr_payload)
        enriched["changedFiles"] = files
        decision = admit_existing(receipt=load(args.receipt), workflow_run=load(args.workflow_run),
                                  artifact=load(args.artifact), pr_response=enriched, main_ref=load(args.main_ref),
                                  check_pages=load(args.checks), ghas_response=load(args.ghas),
                                  pr_alert_pages=load(args.pr_alerts), thread_response=load(args.threads))
        dump(args.out, decision)
    return 0


if __name__ == "__main__":
    self_test()
    raise SystemExit(main())
