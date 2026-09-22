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


def current_main(ref_response: Any, expected_sha: str) -> dict[str, Any]:
    expected_sha = sha(expected_sha, "expected main SHA")
    require(isinstance(ref_response, Mapping), "main ref response must be an object")
    obj = ref_response.get("object")
    require(isinstance(obj, Mapping), "main ref response is missing object")
    observed = sha(obj.get("sha"), "main ref object SHA")
    require(observed == expected_sha, "main moved after controller checkout")
    return {"baseSha": observed, "baseRef": DEFAULT_REF}


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


def validate_commit_response(value: Any, branch: str) -> dict[str, Any]:
    require(isinstance(value, Mapping), "Autofix commit response must be an object")
    expected_ref = f"refs/heads/{branch}"
    require(value.get("target_ref") == expected_ref, "Autofix commit response target_ref mismatch")
    return {"targetRef": expected_ref, "headSha": sha(value.get("sha"), "Autofix commit SHA")}


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


def build_receipt(*, run_id: int, run_attempt: int, event_name: str, base_sha: str, target: Mapping[str, Any],
                  branch: str, head_sha: str, pr_response: Any) -> dict[str, Any]:
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
    receipt = {
        "controllerId": contract.CONTROLLER_ID,
        "flowId": contract.FLOW_ID,
        "repository": REPOSITORY,
        "workflowPath": contract.WORKFLOW_PATH,
        "runId": run_id,
        "runAttempt": run_attempt,
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
    current_main({"object": {"sha": base}}, base)

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

    pages = [[{"number": 1, "state": "open", "base": {"ref": "main", "sha": base},
               "head": {"ref": "codeql-autofix/alert-4/run-123", "sha": head}, "draft": False, "node_id": "PR_x"}]]
    located = locate_existing(pages, 4)
    require(located["exists"] and located["pr"]["originRunId"] == 123, "existing PR locator changed")
    require(flatten_pages([[1], [2]]) == [1, 2], "pagination flattening changed")

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

    p = sub.add_parser("ref-state")
    p.add_argument("--refs-file", required=True)
    p.add_argument("--branch", required=True)
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
    elif args.command == "discover":
        dump(args.out, discover_target(load(args.alerts_file), args.base_sha))
    elif args.command == "locate":
        dump(args.out, locate_existing(load(args.prs_file), args.alert))
    elif args.command == "status":
        target = load(args.target_file)
        require(isinstance(target, Mapping), "target file must be an object")
        dump(args.out, normalize_status(target, load(args.status_file)))
    elif args.command == "ref-state":
        dump(args.out, classify_branch_ref_inventory(load(args.refs_file), args.branch))
    elif args.command == "commit":
        dump(args.out, validate_commit_response(load(args.response_file), args.branch))
    elif args.command == "compare":
        dump(args.out, validate_compare(load(args.compare_file), args.base_sha, args.head_sha))
    elif args.command == "followup-select":
        dump(args.out, select_new_codeql_dispatch_run(load(args.before_file), load(args.after_file), args.expected_sha))
    elif args.command == "followup-run":
        dump(args.out, validate_bound_codeql_run(load(args.run_file), args.run_id, args.expected_sha))
    elif args.command == "receipt":
        target = load(args.target_file)
        require(isinstance(target, Mapping), "target file must be an object")
        dump(args.out, build_receipt(run_id=args.run_id, run_attempt=args.run_attempt, event_name=args.event_name,
                                     base_sha=args.base_sha, target=target, branch=args.branch, head_sha=args.head_sha,
                                     pr_response=load(args.pr_file)))
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
