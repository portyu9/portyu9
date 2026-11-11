#!/usr/bin/env python3
"""Bind governed required checks to latest real GitHub Actions runs and jobs.

Read-only, bounded, fail-closed evidence validation. No workflow dispatch,
review, status publication or merge authority is provided by this module.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from typing import Any, Mapping

SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = "portyu9/portyu9"
APP_ID = 15368
MAX_ITEMS = 100
MAX_ATTEMPT = 20
WORKFLOWS = {
    "profile": (".github/workflows/profile-quality.yml", "Profile quality",
                frozenset({"pull_request"}),
                ("validate-contracts", "integration-pinned-upstream",
                 "trusted-capability-admission")),
    "dependency": (".github/workflows/dependency-review.yml", "Dependency review",
                   frozenset({"pull_request"}), ("dependency-review",)),
    "codeql": (".github/workflows/codeql.yml", "CodeQL",
               frozenset({"pull_request", "workflow_dispatch"}),
               ("analyze-actions", "analyze-python")),
}
RUN_STATES = frozenset({"queued", "in_progress", "requested",
                        "waiting", "pending", "completed"})
CONCLUSIONS = frozenset({"success", "failure", "cancelled", "skipped",
                         "timed_out", "action_required", "neutral", "stale",
                         "startup_failure"})


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(f"Authentic required-check proof: {message}")


def integer(value: Any, name: str, *, maximum: int | None = None) -> int:
    require(type(value) is int and value > 0 and (maximum is None or value <= maximum),
            f"{name} must be a positive bounded integer")
    return value


def sha(value: Any, name: str) -> str:
    require(type(value) is str and SHA.fullmatch(value) is not None,
            f"{name} must be canonical lowercase SHA40")
    return value


def envelope(value: Any, key: str) -> list[Any]:
    require(isinstance(value, Mapping), f"{key} response must be an object")
    total = value.get("total_count")
    require(type(total) is int and 0 <= total <= MAX_ITEMS,
            f"{key} total_count exceeds bound or is invalid")
    items = value.get(key)
    require(type(items) is list and len(items) <= MAX_ITEMS and len(items) == total,
            f"{key} response is truncated, oversized or malformed")
    return items


def run_status(item: Mapping[str, Any], what: str) -> None:
    state = item.get("status")
    conclusion = item.get("conclusion")
    require(state in RUN_STATES, f"{what} has unreviewed status")
    if state == "completed":
        require(conclusion in CONCLUSIONS, f"{what} has unreviewed conclusion")
    else:
        require(conclusion is None, f"{what} has nonterminal conclusion")


def repository_identity(run: Mapping[str, Any], field: str, repo: str) -> None:
    obj = run.get(field)
    require(isinstance(obj, Mapping) and obj.get("full_name") == repo,
            f"workflow run {field} repository identity mismatch")


def select_runs(value: Any, *, head: str, branch: str, repo: str) -> dict[str, Any]:
    sha(head, "head")
    require(repo == REPOSITORY, "repository binding changed")
    require(type(branch) is str and bool(branch) and branch.strip() == branch,
            "head branch is empty or padded")
    items = envelope(value, "workflow_runs")
    seen_ids: set[int] = set()
    candidates: dict[str, list[dict[str, Any]]] = {key: [] for key in WORKFLOWS}

    for item in items:
        require(isinstance(item, Mapping), "workflow run entry is not an object")
        run_id = integer(item.get("id"), "workflow run id")
        require(run_id not in seen_ids, "duplicate workflow run id")
        seen_ids.add(run_id)
        sha(item.get("head_sha"), "workflow run head")
        require(item["head_sha"] == head, "mixed workflow-run head subjects")
        require(item.get("head_branch") == branch, "mixed workflow-run branches")
        repository_identity(item, "repository", repo)
        repository_identity(item, "head_repository", repo)
        require(type(item.get("name")) is str and bool(item["name"]),
                "workflow run name is invalid")
        require(type(item.get("path")) is str and bool(item["path"]),
                "workflow run path is invalid")
        require(type(item.get("event")) is str and bool(item["event"]),
                "workflow run event is invalid")
        run_status(item, "workflow run")
        for key, (path, name, events, _names) in WORKFLOWS.items():
            if item["path"] != path and item["name"] != name:
                continue
            require(item["path"] == path and item["name"] == name,
                    f"{key} canonical workflow name/path mismatch")
            require(item["event"] in events, f"{key} workflow event is not authorized")
            workflow_id = integer(item.get("workflow_id"), f"{key} workflow id")
            suite_id = integer(item.get("check_suite_id"), f"{key} suite id")
            attempt = integer(item.get("run_attempt"), f"{key} attempt",
                              maximum=MAX_ATTEMPT)
            candidates[key].append({
                "id": run_id, "workflowId": workflow_id,
                "suiteId": suite_id, "attempt": attempt,
                "status": item["status"], "conclusion": item["conclusion"],
            })

    selected: dict[str, Any] = {}
    for key, matching in candidates.items():
        if not matching:
            return {"state": "pending", "reason": f"canonical {key} run absent", "runs": {}}
        # A workflow has exactly one stable ID. Multiple runs/attempts may
        # exist, but the newest run may never borrow an older successful job.
        require(len({r["workflowId"] for r in matching}) == 1,
                f"{key} workflow ID changed across exact-head runs")
        require(len({r["suiteId"] for r in matching}) == len(matching),
                f"{key} check-suite identity was reused across distinct runs")
        selected[key] = max(matching, key=lambda r: r["id"])
    return {"state": "selected", "runs": selected}


def verify_ready(
    *,
    checks: Any,
    runs: Any,
    jobs: Mapping[str, Any],
    selection: Any,
    head: str,
    branch: str,
    repo: str,
) -> dict[str, Any]:
    canonical = select_runs(runs, head=head, branch=branch, repo=repo)
    require(canonical["state"] == "selected",
            "canonical workflow selection is not complete")
    require(selection == canonical, "selected workflows differ from authenticated source")
    require(type(jobs) is dict and set(jobs) == set(WORKFLOWS),
            "latest job collections are incomplete or contain extra sources")
    entries = envelope(checks, "check_runs")
    checks_by_id: dict[int, Mapping[str, Any]] = {}
    for entry in entries:
        require(isinstance(entry, Mapping), "check entry is not an object")
        check_id = integer(entry.get("id"), "check id")
        require(check_id not in checks_by_id, "duplicate check id")
        checks_by_id[check_id] = entry
        require(sha(entry.get("head_sha"), "check head") == head,
                "check has mixed subject")
        app = entry.get("app")
        require(isinstance(app, Mapping) and app.get("id") == APP_ID,
                "check is not from the trusted GitHub Actions app")
        run_status(entry, "check")
        suite = entry.get("check_suite")
        require(isinstance(suite, Mapping), "check suite is absent")
        integer(suite.get("id"), "check suite id")
        require(type(entry.get("name")) is str and bool(entry["name"]),
                "check name is invalid")

    missing: list[str] = []
    blocked: list[str] = []
    accepted: list[dict[str, Any]] = []
    for key, (_path, name, _events, required) in WORKFLOWS.items():
        selected = canonical["runs"][key]
        if selected["status"] != "completed":
            missing.append(f"{key} workflow run is active")
        jobs_entries = envelope(jobs[key], "jobs")
        observed: dict[str, list[Mapping[str, Any]]] = {n: [] for n in required}
        seen_job_ids: set[int] = set()
        for job in jobs_entries:
            require(isinstance(job, Mapping), f"{key} job is not an object")
            job_id = integer(job.get("id"), f"{key} job id")
            require(job_id not in seen_job_ids, f"{key} duplicate job id")
            seen_job_ids.add(job_id)
            require(job.get("run_id") == selected["id"],
                    f"{key} job belongs to another workflow run")
            require(sha(job.get("head_sha"), f"{key} job head") == head,
                    f"{key} job head mismatch")
            require(job.get("workflow_name") == name,
                    f"{key} job workflow name mismatch")
            attempt = integer(job.get("run_attempt"), f"{key} job run attempt",
                              maximum=MAX_ATTEMPT)
            require(attempt <= selected["attempt"],
                    f"{key} job attempt exceeds latest workflow run attempt")
            require(
                job.get("check_run_url")
                == f"https://api.github.com/repos/{repo}/check-runs/{job_id}",
                f"{key} job check-run URL is not canonical",
            )
            require(type(job.get("name")) is str and bool(job["name"]),
                    f"{key} job name is invalid")
            run_status(job, f"{key} job")
            if job["name"] in observed:
                observed[job["name"]].append(job)

        if selected["status"] == "completed" and selected["conclusion"] != "success":
            # The review gate necessarily fails before the exact owner approval
            # exists. Only that *one* authentic failed job may defer the Profile
            # Quality workflow conclusion; no other failure is permissible.
            # Required checks remain independently proved below and the
            # terminal governed review gate still must succeed before merge.
            gate_name = "trusted-governed-bot-review"
            gate = [j for j in jobs_entries if j["name"] == gate_name]
            others = [j for j in jobs_entries
                      if j["name"] not in (*required, gate_name)]
            if key != "profile" or selected["conclusion"] != "failure":
                blocked.append(f"{key} latest workflow run failed: {selected['conclusion']}")
            elif len(gate) != 1 or any(
                j["status"] != "completed" or j["conclusion"] not in ("success", "skipped")
                for j in others
            ):
                blocked.append("profile has ambiguous gate or unrelated failing job")
            else:
                gate_job = gate[0]
                matched_gate = [c for c in checks_by_id.values()
                                if c["name"] == gate_name
                                and c["check_suite"]["id"] == selected["suiteId"]]
                require(len(matched_gate) == 1,
                        "profile pre-review gate check is absent or ambiguous")
                gate_check = matched_gate[0]
                require(gate_check["id"] == gate_job["id"]
                        and gate_check.get("details_url")
                        == f"https://github.com/{repo}/actions/runs/{selected['id']}/job/{gate_job['id']}",
                        "profile pre-review gate job is not authentic")
                if not (
                    gate_job["status"] == gate_check["status"] == "completed"
                    and gate_job["conclusion"] == gate_check["conclusion"] == "failure"
                ):
                    blocked.append("profile failure is not the exact pre-review gate")

        for required_name in required:
            matches = observed[required_name]
            require(len(matches) <= 1, f"{key} duplicate latest required job: {required_name}")
            if not matches:
                missing.append(f"{key}/{required_name} latest job absent")
                continue
            job = matches[0]
            matching = [c for c in checks_by_id.values()
                        if c["name"] == required_name
                        and c["check_suite"]["id"] == selected["suiteId"]]
            require(len(matching) == 1,
                    f"{key}/{required_name} exact suite check is absent or ambiguous")
            check = matching[0]
            require(check["id"] == job["id"],
                    f"{key}/{required_name} check is not the latest authentic job")
            require(
                check.get("details_url")
                == f"https://github.com/{repo}/actions/runs/{selected['id']}/job/{job['id']}",
                f"{key}/{required_name} check details are not canonical",
            )
            if job["status"] != "completed" or check["status"] != "completed":
                missing.append(f"{key}/{required_name} is active")
            elif job["conclusion"] != "success" or check["conclusion"] != "success":
                blocked.append(f"{key}/{required_name} latest authentic job failed")
            accepted.append({"name": required_name, "jobId": job["id"],
                             "runId": selected["id"], "suiteId": selected["suiteId"],
                             "attempt": job["run_attempt"]})
    state = "blocked" if blocked else "pending" if missing else "ready"
    return {"state": state, "blocked": blocked, "pending": missing,
            "selected": accepted}


def load(path: str) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            require(key not in result, f"duplicate JSON key: {key}")
            result[key] = value
        return result
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique)


def save(path: str, value: Any) -> None:
    Path(path).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n",
                          encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("select", "verify", "self-test"))
    parser.add_argument("--runs")
    parser.add_argument("--checks")
    parser.add_argument("--profile-jobs")
    parser.add_argument("--dependency-jobs")
    parser.add_argument("--codeql-jobs")
    parser.add_argument("--selection")
    parser.add_argument("--head")
    parser.add_argument("--branch")
    parser.add_argument("--repository", default=REPOSITORY)
    parser.add_argument("--out")
    args = parser.parse_args()
    if args.command == "self-test":
        self_test()
        return
    require(all((args.runs, args.head, args.branch, args.out)),
            "required read-only evidence inputs missing")
    if args.command == "select":
        outcome = select_runs(load(args.runs), head=args.head, branch=args.branch,
                              repo=args.repository)
    else:
        require(all((args.checks, args.profile_jobs, args.dependency_jobs,
                     args.codeql_jobs, args.selection)), "required check or job evidence missing")
        outcome = verify_ready(
            checks=load(args.checks), runs=load(args.runs),
            jobs={"profile": load(args.profile_jobs),
                  "dependency": load(args.dependency_jobs),
                  "codeql": load(args.codeql_jobs)},
            selection=load(args.selection), head=args.head, branch=args.branch,
            repo=args.repository,
        )
    save(args.out, outcome)


def self_test() -> None:
    # This executable suite tests the *production* selector and verifier.
    head, branch, repo = "a" * 40, "dependabot/github_actions/example", REPOSITORY
    runs: list[dict[str, Any]] = []
    job_sets: dict[str, Any] = {}
    check_items: list[dict[str, Any]] = []
    run_data = {
        "profile": (103, 1003, 2003),
        "dependency": (104, 1004, 2004),
        "codeql": (105, 1005, 2005),
    }
    for key, (run_id, workflow_id, suite_id) in run_data.items():
        path, name, events, required = WORKFLOWS[key]
        runs.append({
            "id": run_id, "workflow_id": workflow_id, "check_suite_id": suite_id,
            "name": name, "path": path,
            "event": "workflow_dispatch" if key == "codeql" else "pull_request",
            "head_sha": head, "head_branch": branch, "run_attempt": 2,
            "status": "completed", "conclusion": "success",
            "repository": {"full_name": repo}, "head_repository": {"full_name": repo},
        })
        jobs = []
        for j, job_name in enumerate(required):
            job_id = (run_id * 100) + j
            jobs.append({
                "id": job_id, "run_id": run_id, "run_attempt": 2,
                "name": job_name, "head_sha": head, "workflow_name": name,
                "status": "completed", "conclusion": "success",
                "check_run_url": f"https://api.github.com/repos/{repo}/check-runs/{job_id}",
            })
            check_items.append({
                "id": job_id, "name": job_name, "head_sha": head,
                "app": {"id": APP_ID}, "check_suite": {"id": suite_id},
                "details_url": f"https://github.com/{repo}/actions/runs/{run_id}/job/{job_id}",
                "status": "completed", "conclusion": "success",
            })
        job_sets[key] = {"total_count": len(jobs), "jobs": jobs}

    def snapshot(items: list[Any], key: str) -> dict[str, Any]:
        return {"total_count": len(items), key: items}

    workflows = snapshot(runs, "workflow_runs")
    checks = snapshot(check_items, "check_runs")
    selected = select_runs(workflows, head=head, branch=branch, repo=repo)
    args = {"checks": checks, "runs": workflows, "jobs": job_sets,
            "selection": selected, "head": head, "branch": branch, "repo": repo}
    require(verify_ready(**args)["state"] == "ready", "happy path changed")

    # Older failed same-name check from another suite must be irrelevant.
    historical = dict(check_items[0], id=800, check_suite={"id": 8000},
                      conclusion="failure",
                      details_url=f"https://github.com/{repo}/actions/runs/80/job/800")
    require(verify_ready(**{**args, "checks": snapshot(check_items + [historical], "check_runs")})
            ["state"] == "ready", "older failed suite poisoned current success")

    # The exact governed owner-review gate fails before approval. This is
    # not permission to waive an unrelated failing required job or run.
    profile_run = runs[0]
    profile_gate_id = 13003
    profile_gate_job = {
        "id": profile_gate_id, "run_id": profile_run["id"],
        "run_attempt": profile_run["run_attempt"],
        "name": "trusted-governed-bot-review",
        "head_sha": head, "workflow_name": "Profile quality",
        "status": "completed", "conclusion": "failure",
        "check_run_url": f"https://api.github.com/repos/{repo}/check-runs/{profile_gate_id}",
    }
    profile_gate_check = {
        "id": profile_gate_id, "name": "trusted-governed-bot-review",
        "head_sha": head, "app": {"id": APP_ID},
        "check_suite": {"id": profile_run["check_suite_id"]},
        "details_url": f"https://github.com/{repo}/actions/runs/{profile_run['id']}/job/{profile_gate_id}",
        "status": "completed", "conclusion": "failure",
    }
    pre_review_run = dict(profile_run, conclusion="failure")
    pre_review_runs = snapshot([pre_review_run, *runs[1:]], "workflow_runs")
    pre_review_jobs = snapshot([*job_sets["profile"]["jobs"], profile_gate_job], "jobs")
    pre_review_checks = snapshot([*check_items, profile_gate_check], "check_runs")
    pre_review = {
        **args,
        "runs": pre_review_runs,
        "selection": select_runs(pre_review_runs, head=head, branch=branch, repo=repo),
        "jobs": {**job_sets, "profile": pre_review_jobs},
        "checks": pre_review_checks,
    }
    require(verify_ready(**pre_review)["state"] == "ready",
            "exact authentic pre-review profile gate should not deadlock owner approval")
    for name, corrupted in (
        ("absent", snapshot(job_sets["profile"]["jobs"], "jobs")),
        ("duplicate", snapshot([*pre_review_jobs["jobs"], profile_gate_job], "jobs")),
        ("other failure", snapshot([*pre_review_jobs["jobs"],
          dict(profile_gate_job, id=13004, name="extra",
               check_run_url=f"https://api.github.com/repos/{repo}/check-runs/13004")], "jobs")),
    ):
        bad = {**pre_review, "jobs": {**job_sets, "profile": corrupted}}
        if name == "other failure":
            require(verify_ready(**bad)["state"] == "blocked",
                    "unrelated profile failure was mistaken for a pre-review gate")
        else:
            try:
                result = verify_ready(**bad)
            except ValueError:
                continue
            require(result["state"] != "ready",
                    f"{name} profile gate was incorrectly accepted")
    for wrong_state in ("success", "skipped", "cancelled"):
        incorrect = dict(profile_gate_job, conclusion=wrong_state)
        bad = {**pre_review, "jobs": {**job_sets, "profile":
               snapshot([*job_sets["profile"]["jobs"], incorrect], "jobs")}}
        require(verify_ready(**bad)["state"] == "blocked",
                "non-failing owner review was used to explain a failing profile run")
    for invalid_check in (
        dict(profile_gate_check, id=13005),
        dict(profile_gate_check, check_suite={"id": 7777}),
        dict(profile_gate_check, conclusion="success"),
    ):
        bad_checks = snapshot([*check_items, invalid_check], "check_runs")
        bad = {**pre_review, "checks": bad_checks}
        try:
            result = verify_ready(**bad)
        except ValueError:
            continue
        require(result["state"] != "ready",
                "counterfeit pre-review check cleared a failing profile run")
    newer_failed = dict(pre_review_run, conclusion="timed_out")
    timed_out_runs = snapshot([newer_failed, *runs[1:]], "workflow_runs")
    require(verify_ready(**{**pre_review, "runs": timed_out_runs,
            "selection": select_runs(timed_out_runs, head=head, branch=branch, repo=repo)})
            ["state"] == "blocked",
            "non-review workflow failure was accepted as a pre-review deferral")

    def forbidden(change: dict[str, Any], reason: str) -> None:
        try:
            verify_ready(**{**args, **change})
        except ValueError:
            return
        raise ValueError(f"forbidden {reason} evidence was accepted")

    forbidden({"checks": snapshot(check_items + [check_items[0]], "check_runs")},
              "duplicate check id")
    forbidden({"checks": snapshot(check_items[:-1], "check_runs")},
              "missing exact-suite check")
    forbidden({"checks": {"total_count": len(check_items) + 1,
                           "check_runs": check_items}}, "truncated checks")
    forbidden({"runs": snapshot(runs + [runs[0]], "workflow_runs")},
              "duplicate workflow id/run")
    forbidden({"runs": snapshot([dict(runs[0], head_sha="b" * 40), *runs[1:]],
                                 "workflow_runs")}, "mixed head")
    forbidden({"runs": snapshot([dict(runs[0], path="other"), *runs[1:]],
                                 "workflow_runs")}, "workflow path substitution")
    forbidden({"runs": snapshot([dict(runs[0], run_attempt=0), *runs[1:]],
                                 "workflow_runs")}, "invalid attempt")
    forbidden({"jobs": {**job_sets, "profile": {"total_count": 1,
               "jobs": job_sets["profile"]["jobs"]}}}, "truncated jobs")
    bad_url = dict(job_sets["profile"]["jobs"][0], check_run_url="https://example.invalid/")
    forbidden({"jobs": {**job_sets, "profile": snapshot(
              [bad_url, *job_sets["profile"]["jobs"][1:]], "jobs")}},
              "job/check URL mismatch")

    def outcome(runs_override: list[dict[str, Any]], expected: str) -> None:
        new_runs = snapshot(runs_override, "workflow_runs")
        new_selected = select_runs(new_runs, head=head, branch=branch, repo=repo)
        new_args = {**args, "runs": new_runs, "selection": new_selected}
        require(verify_ready(**new_args)["state"] == expected,
                f"latest authentic workflow {expected} case changed")
    outcome([*runs[:2], dict(runs[2], status="completed", conclusion="failure")],
            "blocked")
    outcome([*runs[:2], dict(runs[2], status="in_progress", conclusion=None)],
            "pending")

    newer = dict(runs[0], id=999, check_suite_id=9999, run_attempt=1,
                 status="completed", conclusion="failure")
    newest_runs = snapshot([*runs, newer], "workflow_runs")
    newer_selected = select_runs(newest_runs, head=head, branch=branch, repo=repo)
    require(newer_selected["runs"]["profile"]["id"] == 999,
            "selected an older green workflow over newer red run")
    require(newer_selected["runs"]["profile"]["conclusion"] == "failure",
            "newer failed workflow was not blocked")
    require(select_runs(snapshot(runs[:1], "workflow_runs"),
                        head=head, branch=branch, repo=repo)["state"] == "pending",
            "missing canonical workflow should not fabricate success")

    mutated = dict(job_sets["dependency"]["jobs"][0], status="completed",
                   conclusion="failure")
    require(verify_ready(**{**args, "jobs": {**job_sets,
             "dependency": snapshot([mutated], "jobs")}})["state"] == "blocked",
            "newer failed job was incorrectly accepted")
    old_job = dict(job_sets["codeql"]["jobs"][0], run_attempt=1)
    require(verify_ready(**{**args, "jobs": {**job_sets,
             "codeql": snapshot([old_job, job_sets["codeql"]["jobs"][1]], "jobs")}})
            ["state"] == "ready",
            "unchanged successful latest job carried from earlier attempt was rejected")
    print("Authentic required-check selection: production regression fixtures PASS")


if __name__ == "__main__":
    main()
