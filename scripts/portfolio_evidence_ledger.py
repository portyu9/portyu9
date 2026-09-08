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
API_ORIGIN = "https://api.github.com"
TRUSTED_WORKFLOW_EVENTS = frozenset({"push", "workflow_dispatch"})

API_ATTEMPTS = 3
API_TIMEOUT_SECONDS = 12
API_BACKOFF_SECONDS = (1.0, 2.0)
API_MAX_RETRY_AFTER_SECONDS = 5.0
RETRYABLE_HTTP_STATUS = frozenset({408, 429, 500, 502, 503, 504})
JOB_PAGE_SIZE = 100


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def validate_api_url(url: str) -> str:
    """Return an exact-origin GitHub API URL or fail before attaching credentials."""
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https", f"GitHub API URL must use https: {url}")
    require(parsed.netloc == "api.github.com", f"GitHub API origin changed: {url}")
    require(parsed.username is None and parsed.password is None, f"GitHub API URL must not contain userinfo: {url}")
    require(parsed.port is None, f"GitHub API URL must not contain a port override: {url}")
    require(parsed.fragment == "", f"GitHub API URL must not contain a fragment: {url}")
    require(parsed.path.startswith("/"), f"GitHub API URL path is malformed: {url}")
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Reject redirects so a token-bearing request cannot be replayed to another URL."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        return None


def open_no_redirect(request: urllib.request.Request, *, timeout: float) -> Any:
    return urllib.request.build_opener(NoRedirect()).open(request, timeout=timeout)


def api_request(url: str, token: str | None) -> urllib.request.Request:
    safe_url = validate_api_url(url)
    request = urllib.request.Request(safe_url, headers=evidence.request_headers(None))
    if token:
        request.add_unredirected_header("Authorization", f"Bearer {token}")
    return request


def transport_self_test() -> None:
    good = "https://api.github.com/repos/portyu9/example/actions/runs?branch=main"
    require(validate_api_url(good) == good, "GitHub API origin self-test rejected the canonical endpoint")
    for unsafe in (
        "http://api.github.com/repos/portyu9/example",
        "https://api.github.com.evil.example/repos/portyu9/example",
        "https://api.github.com:443/repos/portyu9/example",
        "https://user@api.github.com/repos/portyu9/example",
        "https://api.github.com/repos/portyu9/example#fragment",
    ):
        try:
            validate_api_url(unsafe)
        except ValueError:
            pass
        else:
            raise ValueError(f"GitHub API origin self-test accepted unsafe URL: {unsafe}")

    request = api_request(good, "fixture-token")
    auth = {name.lower(): value for name, value in request.unredirected_hdrs.items()}
    ordinary = {name.lower(): value for name, value in request.headers.items()}
    require(auth.get("authorization") == "Bearer fixture-token",
            "bearer token must be attached as an unredirected-only header")
    require("authorization" not in ordinary,
            "bearer token must not be attached as a redirect-copyable ordinary header")
    require(NoRedirect().redirect_request(None, None, 302, "fixture", {}, "https://example.com") is None,
            "redirect handler must refuse every redirect request")


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
    opener: Callable[..., Any] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    request = api_request(url, token)
    transport = opener or open_no_redirect
    for attempt in range(API_ATTEMPTS):
        try:
            with transport(request, timeout=API_TIMEOUT_SECONDS) as response:
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


def select_workflow_run(runs: Any, subject: str | None) -> dict[str, Any]:
    """Prefer the newest trusted run bound to subject, then preserve a trusted fallback."""
    if not isinstance(runs, list):
        return {}
    trusted = [
        run for run in runs
        if isinstance(run, dict) and str(run.get("event") or "") in TRUSTED_WORKFLOW_EVENTS
    ]
    trusted.sort(key=lambda run: str(run.get("created_at") or ""), reverse=True)
    if subject and subject != SHA40_ZERO:
        for run in trusted:
            if str(run.get("head_sha") or "") == subject:
                return run
    return trusted[0] if trusted else {}


def latest_workflow_run(repo: str, workflow: str, subject: str, token: str | None) -> dict[str, Any]:
    encoded = urllib.parse.quote(workflow, safe="")
    base = f"https://api.github.com/repos/{OWNER}/{repo}/actions/workflows/{encoded}/runs"
    if subject != SHA40_ZERO:
        exact = fetch_json(f"{base}?branch=main&head_sha={subject}&per_page=20", token)
        selected = select_workflow_run(exact.get("workflow_runs") or [], subject)
        if selected:
            return selected
    recent = fetch_json(f"{base}?branch=main&per_page=20", token)
    return select_workflow_run(recent.get("workflow_runs") or [], subject)


def workflow_jobs(
    repo: str,
    run_id: int,
    token: str | None,
    *,
    fetcher: Callable[[str, str | None], dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Fetch every job page and reject incomplete or internally inconsistent snapshots."""
    base = f"https://api.github.com/repos/{OWNER}/{repo}/actions/runs/{run_id}/jobs"
    fetch_page = fetcher or fetch_json
    first = fetch_page(f"{base}?per_page={JOB_PAGE_SIZE}&page=1", token)
    total = first.get("total_count")
    require(
        isinstance(total, int) and not isinstance(total, bool) and total >= 0,
        f"{repo}: workflow job total_count is malformed for run {run_id}",
    )
    expected_pages = max(1, (total + JOB_PAGE_SIZE - 1) // JOB_PAGE_SIZE)
    collected: list[dict[str, Any]] = []
    seen_ids: set[int] = set()

    for page in range(1, expected_pages + 1):
        payload = first if page == 1 else fetch_page(
            f"{base}?per_page={JOB_PAGE_SIZE}&page={page}", token
        )
        page_total = payload.get("total_count")
        require(
            isinstance(page_total, int) and not isinstance(page_total, bool) and page_total == total,
            f"{repo}: workflow job total_count changed while paging run {run_id}",
        )
        page_jobs = payload.get("jobs")
        require(isinstance(page_jobs, list), f"{repo}: workflow jobs page {page} is malformed for run {run_id}")
        expected_size = (
            0
            if total == 0
            else JOB_PAGE_SIZE
            if page < expected_pages
            else total - JOB_PAGE_SIZE * (expected_pages - 1)
        )
        require(
            len(page_jobs) == expected_size,
            f"{repo}: workflow jobs page {page} is incomplete for run {run_id}: "
            f"expected {expected_size}, observed {len(page_jobs)}",
        )
        for job in page_jobs:
            require(isinstance(job, dict), f"{repo}: workflow job entry is malformed for run {run_id}")
            job_id = job.get("id")
            require(
                isinstance(job_id, int) and not isinstance(job_id, bool) and job_id > 0,
                f"{repo}: workflow job id is malformed for run {run_id}",
            )
            require(job_id not in seen_ids, f"{repo}: duplicate workflow job id {job_id} for run {run_id}")
            seen_ids.add(job_id)
            collected.append(job)

    require(
        len(collected) == total,
        f"{repo}: workflow job pagination did not close for run {run_id}: expected {total}, observed {len(collected)}",
    )
    return collected


def workflow_jobs_self_test() -> None:
    """Regression-proof pagination completeness before job-scoped evidence aggregation."""
    first_page = [
        {
            "id": index,
            "name": "Required" if index == 1 else f"Filler {index}",
            "status": "completed",
            "conclusion": "success",
        }
        for index in range(1, JOB_PAGE_SIZE + 1)
    ]
    second_page = [{
        "id": JOB_PAGE_SIZE + 1,
        "name": "Required",
        "status": "completed",
        "conclusion": "failure",
    }]
    pages = {
        1: {"total_count": JOB_PAGE_SIZE + 1, "jobs": first_page},
        2: {"total_count": JOB_PAGE_SIZE + 1, "jobs": second_page},
    }
    requested: list[int] = []

    def fixture_fetch(url: str, token: str | None) -> dict[str, Any]:
        require(token is None, "workflow jobs fixture unexpectedly received a token")
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        page = int((query.get("page") or ["0"])[0])
        requested.append(page)
        return pages[page]

    jobs = workflow_jobs("fixture-repo", 7, None, fetcher=fixture_fetch)
    require(requested == [1, 2], "workflow jobs pagination fixture did not fetch every page")
    require(len(jobs) == JOB_PAGE_SIZE + 1, "workflow jobs pagination fixture lost a job")
    require(
        evidence.aggregate_jobs({"jobs": ["Required"]}, jobs) == "NO SIGNAL",
        "page-two duplicate job name must remain visible to ambiguity aggregation",
    )

    failure_cases = (
        (
            {
                1: {"total_count": JOB_PAGE_SIZE + 1, "jobs": first_page[:-1]},
                2: pages[2],
            },
            "incomplete",
        ),
        (
            {
                1: pages[1],
                2: {"total_count": JOB_PAGE_SIZE + 2, "jobs": second_page},
            },
            "total_count changed",
        ),
        (
            {
                1: pages[1],
                2: {"total_count": JOB_PAGE_SIZE + 1, "jobs": [dict(second_page[0], id=1)]},
            },
            "duplicate workflow job id",
        ),
    )
    for fixture_pages, expected in failure_cases:
        def failing_fetch(url: str, token: str | None, *, data: dict[int, dict[str, Any]] = fixture_pages) -> dict[str, Any]:
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            return data[int((query.get("page") or ["0"])[0])]

        try:
            workflow_jobs("fixture-repo", 8, None, fetcher=failing_fetch)
        except ValueError as exc:
            require(expected in str(exc), f"workflow jobs pagination failed for wrong reason: {exc}")
        else:
            raise ValueError(f"workflow jobs pagination self-test accepted malformed pagination: {expected}")


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
                run_cache[workflow] = latest_workflow_run(repo, workflow, subject, token)
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
    transport_self_test()
    workflow_jobs_self_test()
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
