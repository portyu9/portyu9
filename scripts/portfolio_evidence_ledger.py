#!/usr/bin/env python3
"""Portfolio Evidence Ledger v2 implementation backed by the canonical registry."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

import portfolio_evidence_helpers as evidence
import portfolio_system_registry as registry

OWNER = registry.OWNER
VERSION = "portfolio-evidence-ledger-v2"
KIND = "portfolio-evidence-ledger"
OUTPUT = "portfolio-evidence-ledger.json"
EVIDENCE_SEMANTICS = "execution-result-subject-binding-freshness-v1"
SHA40_ZERO = "0" * 40

API_ATTEMPTS = 3
API_TIMEOUT_SECONDS = 12
API_BACKOFF_SECONDS = (1.0, 2.0)
API_MAX_RETRY_AFTER_SECONDS = 5.0
RETRYABLE_HTTP_STATUS = frozenset({408, 429, 500, 502, 503, 504})


def canonical_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def retryable_http_error(exc: urllib.error.HTTPError) -> bool:
    if exc.code in RETRYABLE_HTTP_STATUS:
        return True
    if exc.code != 403:
        return False
    headers = exc.headers or {}
    return headers.get("X-RateLimit-Remaining") == "0" or bool(headers.get("Retry-After"))


def retry_delay_seconds(exc: BaseException, failure_index: int) -> float:
    default = API_BACKOFF_SECONDS[min(failure_index, len(API_BACKOFF_SECONDS) - 1)]
    if not isinstance(exc, urllib.error.HTTPError) or not exc.headers:
        return default
    raw = str(exc.headers.get("Retry-After") or "").strip()
    try:
        requested = float(raw)
    except ValueError:
        return default
    return max(0.0, min(requested, API_MAX_RETRY_AFTER_SECONDS))


def fetch_json(
    url: str,
    token: str | None,
    *,
    opener: Callable[..., Any] = urllib.request.urlopen,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    request = urllib.request.Request(url, headers=evidence.request_headers(token))
    for attempt in range(API_ATTEMPTS):
        try:
            with opener(request, timeout=API_TIMEOUT_SECONDS) as response:
                payload = json.load(response)
            if not isinstance(payload, dict):
                raise ValueError("GitHub API response must be an object")
            return payload
        except urllib.error.HTTPError as exc:
            if attempt + 1 >= API_ATTEMPTS or not retryable_http_error(exc):
                raise
            sleeper(retry_delay_seconds(exc, attempt))
        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
            if attempt + 1 >= API_ATTEMPTS:
                raise
            sleeper(retry_delay_seconds(exc, attempt))
    raise RuntimeError("unreachable GitHub API retry state")


def main_revision(repo: str, token: str | None) -> str:
    payload = fetch_json(f"https://api.github.com/repos/{OWNER}/{repo}/git/ref/heads/main", token)
    sha = str((payload.get("object") or {}).get("sha") or "")
    if len(sha) != 40 or any(ch not in "0123456789abcdef" for ch in sha):
        raise ValueError(f"{repo}: current main revision is malformed")
    return sha


def latest_workflow_run(repo: str, workflow: str, token: str | None) -> dict[str, Any]:
    encoded = urllib.parse.quote(workflow, safe="")
    endpoint = (
        f"https://api.github.com/repos/{OWNER}/{repo}/actions/workflows/{encoded}/runs"
        "?branch=main&event=push&per_page=1"
    )
    payload = fetch_json(endpoint, token)
    runs = payload.get("workflow_runs") or []
    return runs[0] if runs and isinstance(runs[0], dict) else {}


def workflow_jobs(repo: str, run_id: int, token: str | None) -> list[dict[str, Any]]:
    payload = fetch_json(f"https://api.github.com/repos/{OWNER}/{repo}/actions/runs/{run_id}/jobs?per_page=100", token)
    return [job for job in (payload.get("jobs") or []) if isinstance(job, dict)]


def binding_state(subject: str, head_sha: str, has_run: bool) -> str:
    if not has_run:
        return "UNAVAILABLE"
    if subject == SHA40_ZERO:
        return "SUBJECT_UNAVAILABLE"
    if head_sha == SHA40_ZERO:
        return "RUN_HEAD_UNAVAILABLE"
    return "CURRENT_SUBJECT" if head_sha == subject else "DIFFERENT_SUBJECT"


def freshness_state(timestamp: str, age_days: int, offline: bool) -> str:
    if offline:
        return "SYNTHETIC"
    if not timestamp:
        return "UNAVAILABLE"
    return "SAME_DAY" if age_days == 0 else "AGED"


def offline_signal(repo: str, spec: dict[str, Any], day: dt.date, index: int) -> dict[str, Any]:
    seed = hashlib.sha256(f"{VERSION}:{repo}:{spec['label']}:{day.isoformat()}".encode()).hexdigest()
    run_id = int(seed[40:52], 16)
    run_number = 100 + (int(seed[52:58], 16) % 900)
    return {
        "label": spec["label"],
        "workflow": spec["workflow"],
        "scope": evidence.evidence_scope(spec),
        "result": "UNKNOWN",
        "binding": "SYNTHETIC",
        "freshness": "SYNTHETIC",
        "run_id": run_id,
        "run_number": run_number,
        "run_url": f"https://github.com/{OWNER}/{repo}/actions/runs/{run_id}",
        "head_sha": seed[:40],
        "completed_at_utc": f"{day.isoformat()}T00:00:00Z",
        "age_days": 0,
        "offline": True,
        "ordinal": index,
    }


def collect_evidence_dimensions(
    system: dict[str, Any], day: dt.date, token: str | None, offline: bool
) -> tuple[str, list[dict[str, Any]]]:
    repo = str(system["repo"])
    specs = list(system["evidence"])
    if offline:
        subject = hashlib.sha256(f"{VERSION}:{repo}:subject:{day.isoformat()}".encode()).hexdigest()[:40]
        return subject, [offline_signal(repo, spec, day, index) for index, spec in enumerate(specs, 1)]

    try:
        subject = main_revision(repo, token)
    except (urllib.error.URLError, TimeoutError, ConnectionResetError, json.JSONDecodeError, ValueError):
        subject = SHA40_ZERO

    run_cache: dict[str, dict[str, Any]] = {}
    jobs_cache: dict[int, list[dict[str, Any]]] = {}
    records: list[dict[str, Any]] = []
    for index, spec in enumerate(specs, 1):
        workflow = str(spec["workflow"])
        try:
            if workflow not in run_cache:
                run_cache[workflow] = latest_workflow_run(repo, workflow, token)
            run = run_cache[workflow]
        except (urllib.error.URLError, TimeoutError, ConnectionResetError, json.JSONDecodeError, ValueError):
            run = {}

        if not run:
            records.append({
                "label": spec["label"], "workflow": workflow, "scope": evidence.evidence_scope(spec),
                "result": "UNAVAILABLE", "binding": "UNAVAILABLE", "freshness": "UNAVAILABLE",
                "run_id": 0, "run_number": 0, "run_url": "", "head_sha": SHA40_ZERO,
                "completed_at_utc": "", "age_days": 0, "offline": False, "ordinal": index,
            })
            continue

        run_id = int(run.get("id") or 0)
        raw_head = str(run.get("head_sha") or "")
        head_sha = raw_head if len(raw_head) == 40 and all(ch in "0123456789abcdef" for ch in raw_head) else SHA40_ZERO
        status = str(run.get("status") or "")
        completed = str(run.get("updated_at") or run.get("run_started_at") or run.get("created_at") or "")
        result = "RUNNING" if status != "completed" else evidence.conclusion_signal(str(run.get("conclusion") or ""))
        if result == "PASSING" and (spec.get("jobs") or spec.get("job_prefixes")):
            try:
                if run_id not in jobs_cache:
                    jobs_cache[run_id] = workflow_jobs(repo, run_id, token)
                result = evidence.aggregate_jobs(spec, jobs_cache[run_id])
            except (urllib.error.URLError, TimeoutError, ConnectionResetError, json.JSONDecodeError, ValueError):
                result = "UNAVAILABLE"
        age = evidence.evidence_age_days(day, completed) if completed else 0
        records.append({
            "label": spec["label"], "workflow": workflow, "scope": evidence.evidence_scope(spec),
            "result": result, "binding": binding_state(subject, head_sha, True),
            "freshness": freshness_state(completed, age, False), "run_id": run_id,
            "run_number": int(run.get("run_number") or 0), "run_url": str(run.get("html_url") or ""),
            "head_sha": head_sha, "completed_at_utc": completed, "age_days": age,
            "offline": False, "ordinal": index,
        })
    return subject, records


def collect_system(system: dict[str, Any], day: dt.date, token: str | None, offline: bool) -> dict[str, Any]:
    subject, signals = collect_evidence_dimensions(system, day, token, offline)
    contract = [
        {"label": spec["label"], "workflow": spec["workflow"], "scope": evidence.evidence_scope(spec)}
        for spec in system["evidence"]
    ]
    ages = [int(signal["age_days"]) for signal in signals if signal.get("freshness") != "UNAVAILABLE"]
    return {
        "repository": f"{OWNER}/{system['repo']}",
        "title": system["title"],
        "classification": system["classification"],
        "subject_revision": subject,
        "evidence_max_age_days": max(ages, default=0),
        "evidence_contract": contract,
        "signals": signals,
    }


def summarize(systems: list[dict[str, Any]], field: str) -> dict[str, int]:
    summary: dict[str, int] = {}
    for system in systems:
        for signal in system["signals"]:
            value = str(signal.get(field) or "UNAVAILABLE")
            summary[value] = summary.get(value, 0) + 1
    return dict(sorted(summary.items()))


def build_ledger(day: dt.date, token: str | None, offline: bool) -> dict[str, Any]:
    reviewed = registry.systems()
    if len(reviewed) != 13:
        raise ValueError("portfolio registry must contain exactly 13 reviewed systems")
    systems = [collect_system(system, day, token, offline) for system in reviewed]
    core: dict[str, Any] = {
        "version": VERSION,
        "kind": KIND,
        "owner": OWNER,
        "as_of_date_utc": day.isoformat(),
        "evidence_semantics": EVIDENCE_SEMANTICS,
        "subject_policy": "current-main-revision-per-system",
        "freshness_basis": "UTC whole-day age from workflow evidence timestamp",
        "classification_policy": registry.CLASSIFICATION_POLICY,
        "portfolio_registry": {"version": registry.VERSION, "digest": registry.registry_digest()},
        "system_count": len(systems),
        "result_summary": summarize(systems, "result"),
        "binding_summary": summarize(systems, "binding"),
        "freshness_summary": summarize(systems, "freshness"),
        "systems": systems,
    }
    digest = canonical_digest(core)
    return {**core, "evidence_id": f"PL2-{digest[:16].upper()}", "evidence_digest": f"sha256:{digest}"}


def generate(output_dir: Path, day: dt.date, token: str | None, offline: bool) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    ledger = build_ledger(day, token, offline)
    (output_dir / OUTPUT).write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return ledger
