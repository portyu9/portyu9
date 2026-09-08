#!/usr/bin/env python3
"""Shared evidence-scope/result helpers with no portfolio catalog."""
from __future__ import annotations

import datetime as dt
from typing import Any


def request_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "portyu9-profile-evidence",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def conclusion_signal(conclusion: str) -> str:
    value = conclusion.lower().strip()
    if value == "success":
        return "PASSING"
    if value in {"failure", "timed_out", "startup_failure"}:
        return "FAILING"
    if value in {"cancelled", "skipped", "neutral", "action_required"}:
        return value.replace("_", " ").upper()
    if value == "stale":
        return "STALE_RESULT"
    return "UNKNOWN"


def aggregate_jobs(spec: dict[str, Any], jobs: list[dict[str, Any]]) -> str:
    """Aggregate a reviewed job scope only when every named identity is unambiguous."""
    exact = tuple(spec.get("jobs") or ())
    prefixes = tuple(spec.get("job_prefixes") or ())
    required_steps = tuple(spec.get("required_steps") or ())
    selected: list[dict[str, Any]] = []

    # The registry normally rejects these forms before collection. Keep the runtime
    # aggregator fail-closed as well so a malformed caller can never broaden or hide the
    # claimed scope through duplicate names or mixed exact/prefix selection semantics.
    if exact and prefixes:
        return "NO SIGNAL"
    if any(len(values) != len(set(values)) for values in (exact, prefixes, required_steps)):
        return "NO SIGNAL"
    if required_steps and not prefixes:
        return "NO SIGNAL"

    if exact:
        by_name: dict[str, list[dict[str, Any]]] = {name: [] for name in exact}
        for job in jobs:
            name = str(job.get("name") or "")
            if name in by_name:
                by_name[name].append(job)
        # Exact evidence means exact identity: zero matches is missing evidence and more
        # than one match is ambiguous evidence. Never silently choose one duplicate job.
        if any(len(by_name[name]) != 1 for name in exact):
            return "NO SIGNAL"
        selected.extend(by_name[name][0] for name in exact)

    if prefixes:
        matched = [job for job in jobs if any(str(job.get("name") or "").startswith(prefix) for prefix in prefixes)]
        if not matched:
            return "NO SIGNAL"
        selected.extend(matched)

    if not exact and not prefixes:
        return "PASSING"

    if any(str(job.get("status") or "") != "completed" for job in selected):
        return "RUNNING"

    conclusions = [conclusion_signal(str(job.get("conclusion") or "")) for job in selected]
    if any(value == "FAILING" for value in conclusions):
        return "FAILING"
    if any(value != "PASSING" for value in conclusions):
        return conclusions[0] if len(set(conclusions)) == 1 else "UNKNOWN"

    if required_steps:
        for job in selected:
            by_step_name: dict[str, list[str]] = {name: [] for name in required_steps}
            for step in (job.get("steps") or []):
                if not isinstance(step, dict):
                    continue
                name = str(step.get("name") or "")
                if name in by_step_name:
                    by_step_name[name].append(str(step.get("conclusion") or ""))
            # Required step identities are exact within each selected job. A duplicate
            # display name is ambiguous just like a duplicate exact job display name.
            if any(len(by_step_name[name]) != 1 for name in required_steps):
                return "NO SIGNAL"
            for step_name in required_steps:
                conclusion = by_step_name[step_name][0]
                if conclusion != "success":
                    return conclusion_signal(conclusion)
    return "PASSING"


def evidence_scope(spec: dict[str, Any]) -> str:
    if spec.get("jobs"):
        return "jobs:" + "|".join(str(item) for item in spec["jobs"])
    if spec.get("job_prefixes"):
        scope = "job-prefix:" + "|".join(str(item) for item in spec["job_prefixes"])
        if spec.get("required_steps"):
            scope += ";steps:" + "|".join(str(item) for item in spec["required_steps"])
        return scope
    return "workflow"


def evidence_age_days(day: dt.date, timestamp: str) -> int:
    if not timestamp:
        return 0
    parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return max(0, (day - parsed.date()).days)


def self_test() -> None:
    """Regression-proof exact job and required-step ambiguity handling."""
    exact = {"jobs": ["Lab A", "Lab B"]}
    exact_jobs = [
        {"id": 1, "name": "Lab A", "status": "completed", "conclusion": "success"},
        {"id": 2, "name": "Lab B", "status": "completed", "conclusion": "success"},
    ]
    if aggregate_jobs(exact, exact_jobs) != "PASSING":
        raise ValueError("unique exact-job evidence fixture must pass")
    duplicate_job = exact_jobs + [
        {"id": 3, "name": "Lab A", "status": "completed", "conclusion": "failure"},
    ]
    if aggregate_jobs(exact, duplicate_job) != "NO SIGNAL":
        raise ValueError("duplicate exact-job names must fail closed as NO SIGNAL")
    if aggregate_jobs({"jobs": ["Lab A", "Lab A"]}, exact_jobs) != "NO SIGNAL":
        raise ValueError("duplicate exact-job contract entries must fail closed")
    if aggregate_jobs({"jobs": ["Lab A"], "job_prefixes": ["Lab "]}, exact_jobs) != "NO SIGNAL":
        raise ValueError("mixed exact/prefix job scope must fail closed")

    prefix = {"job_prefixes": ["Quality / Python "], "required_steps": ["Tests", "Bandit"]}
    prefix_jobs = [
        {
            "id": 4,
            "name": "Quality / Python 3.13",
            "status": "completed",
            "conclusion": "success",
            "steps": [
                {"name": "Tests", "conclusion": "success"},
                {"name": "Bandit", "conclusion": "success"},
            ],
        }
    ]
    if aggregate_jobs(prefix, prefix_jobs) != "PASSING":
        raise ValueError("unique required-step evidence fixture must pass")
    duplicate_step = [dict(prefix_jobs[0], steps=[
        {"name": "Tests", "conclusion": "failure"},
        {"name": "Tests", "conclusion": "success"},
        {"name": "Bandit", "conclusion": "success"},
    ])]
    if aggregate_jobs(prefix, duplicate_step) != "NO SIGNAL":
        raise ValueError("duplicate required-step names must fail closed as NO SIGNAL")
    if aggregate_jobs({"jobs": ["Lab A"], "required_steps": ["Tests"]}, exact_jobs) != "NO SIGNAL":
        raise ValueError("required steps without prefix scope must fail closed")
