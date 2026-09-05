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
    exact = tuple(spec.get("jobs") or ())
    prefixes = tuple(spec.get("job_prefixes") or ())
    required_steps = tuple(spec.get("required_steps") or ())
    selected: list[dict[str, Any]] = []

    if exact:
        by_name = {str(job.get("name") or ""): job for job in jobs}
        if any(name not in by_name for name in exact):
            return "NO SIGNAL"
        selected.extend(by_name[name] for name in exact)

    if prefixes:
        matched = [job for job in jobs if any(str(job.get("name") or "").startswith(prefix) for prefix in prefixes)]
        if not matched:
            return "NO SIGNAL"
        selected.extend(matched)

    if not exact and not prefixes:
        return "PASSING"

    selected = list({int(job.get("id") or 0): job for job in selected}.values())
    if any(str(job.get("status") or "") != "completed" for job in selected):
        return "RUNNING"

    conclusions = [conclusion_signal(str(job.get("conclusion") or "")) for job in selected]
    if any(value == "FAILING" for value in conclusions):
        return "FAILING"
    if any(value != "PASSING" for value in conclusions):
        return conclusions[0] if len(set(conclusions)) == 1 else "UNKNOWN"

    if required_steps:
        for job in selected:
            steps = {
                str(step.get("name") or ""): str(step.get("conclusion") or "")
                for step in (job.get("steps") or [])
                if isinstance(step, dict)
            }
            for step_name in required_steps:
                if step_name not in steps:
                    return "NO SIGNAL"
                if steps[step_name] != "success":
                    return conclusion_signal(steps[step_name])
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
