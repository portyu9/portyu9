#!/usr/bin/env python3
"""Legacy direct Engineering Spotlight v2 generator backed by canonical registry.

Production rendering is Ledger-backed and network-free. This compatibility engine keeps
its former direct-generation API for historical tests/tools, but repository identity,
evidence contracts, and presentation metadata now come only from portfolio-systems-v1.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import random
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

import engineering_spotlight_renderer as renderer
import portfolio_evidence_helpers as helpers
import portfolio_system_registry as registry

OWNER = registry.OWNER
VERSION = "engineering-spotlight-v2"
EVIDENCE_MODEL = "per-system-evidence-contract-v2"
SHA40_ZERO = "0" * 40
POOL = registry.legacy_spotlight_pool()
_BY_REPO = registry.system_by_repo()
DEFAULT_EVIDENCE = tuple(dict(item) for item in _BY_REPO["qa-automation-graphql"]["evidence"])
AGENT_EVIDENCE = tuple(dict(item) for item in _BY_REPO["qa-automation-ai-agent-evals"]["evidence"])

request_headers = helpers.request_headers
conclusion_signal = helpers.conclusion_signal
aggregate_jobs = helpers.aggregate_jobs
evidence_scope = helpers.evidence_scope
evidence_age_days = helpers.evidence_age_days


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--date", help="UTC date as YYYY-MM-DD; defaults to current UTC date")
    parser.add_argument("--offline", action="store_true", help="Render deterministic synthetic UNKNOWN evidence without GitHub API calls")
    return parser.parse_args()


def utc_date(raw: str | None) -> dt.date:
    return dt.date.fromisoformat(raw) if raw else dt.datetime.now(dt.timezone.utc).date()


def select_systems(day: dt.date) -> list[dict[str, Any]]:
    seed = int(hashlib.sha256(f"{VERSION}:{day.isoformat()}".encode()).hexdigest(), 16)
    return random.Random(seed).sample(list(POOL), 2)


def fetch_json(url: str, token: str | None) -> dict[str, Any]:
    with urllib.request.urlopen(urllib.request.Request(url, headers=request_headers(token)), timeout=12) as response:
        payload = json.load(response)
    if not isinstance(payload, dict):
        raise ValueError("GitHub API response must be an object")
    return payload


def main_revision(repo: str, token: str | None) -> str:
    payload = fetch_json(f"https://api.github.com/repos/{OWNER}/{repo}/git/ref/heads/main", token)
    sha = str((payload.get("object") or {}).get("sha") or "")
    if len(sha) != 40 or any(ch not in "0123456789abcdef" for ch in sha):
        raise ValueError(f"{repo}: current main revision is malformed")
    return sha


def latest_workflow_run(repo: str, workflow: str, token: str | None) -> dict[str, Any]:
    encoded = urllib.parse.quote(workflow, safe="")
    endpoint = f"https://api.github.com/repos/{OWNER}/{repo}/actions/workflows/{encoded}/runs?branch=main&event=push&per_page=1"
    payload = fetch_json(endpoint, token)
    runs = payload.get("workflow_runs") or []
    return runs[0] if runs and isinstance(runs[0], dict) else {}


def workflow_jobs(repo: str, run_id: int, token: str | None) -> list[dict[str, Any]]:
    payload = fetch_json(f"https://api.github.com/repos/{OWNER}/{repo}/actions/runs/{run_id}/jobs?per_page=100", token)
    return [job for job in (payload.get("jobs") or []) if isinstance(job, dict)]


def offline_evidence(repo: str, spec: dict[str, Any], day: dt.date, index: int) -> dict[str, Any]:
    seed = hashlib.sha256(f"{VERSION}:{repo}:{spec['label']}:{day.isoformat()}".encode()).hexdigest()
    run_id = int(seed[40:52], 16)
    run_number = 100 + (int(seed[52:58], 16) % 900)
    return {
        "label": spec["label"], "workflow": spec["workflow"], "scope": evidence_scope(spec),
        "signal": "UNKNOWN", "run_id": run_id, "run_number": run_number,
        "run_url": f"https://github.com/{OWNER}/{repo}/actions/runs/{run_id}",
        "head_sha": seed[:40], "completed_at_utc": f"{day.isoformat()}T00:00:00Z",
        "age_days": 0, "offline": True, "ordinal": index,
    }


def collect_evidence(system: dict[str, Any], day: dt.date, token: str | None, offline: bool) -> tuple[str, list[dict[str, Any]]]:
    repo = str(system["repo"])
    specs = list(system["evidence"])
    if offline:
        subject = hashlib.sha256(f"{VERSION}:{repo}:subject:{day.isoformat()}".encode()).hexdigest()[:40]
        return subject, [offline_evidence(repo, spec, day, index) for index, spec in enumerate(specs, 1)]
    try:
        subject = main_revision(repo, token)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        subject = SHA40_ZERO
    run_cache: dict[str, dict[str, Any]] = {}
    jobs_cache: dict[int, list[dict[str, Any]]] = {}
    results: list[dict[str, Any]] = []
    for index, spec in enumerate(specs, 1):
        workflow = str(spec["workflow"])
        try:
            if workflow not in run_cache:
                run_cache[workflow] = latest_workflow_run(repo, workflow, token)
            run = run_cache[workflow]
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
            run = {}
        if not run:
            results.append({
                "label": spec["label"], "workflow": workflow, "scope": evidence_scope(spec),
                "signal": "UNAVAILABLE", "run_id": 0, "run_number": 0, "run_url": "",
                "head_sha": SHA40_ZERO, "completed_at_utc": "", "age_days": 0,
                "offline": False, "ordinal": index,
            })
            continue
        run_id = int(run.get("id") or 0)
        head_sha = str(run.get("head_sha") or "")
        status = str(run.get("status") or "")
        completed = str(run.get("updated_at") or run.get("run_started_at") or run.get("created_at") or "")
        signal = "RUNNING" if status != "completed" else conclusion_signal(str(run.get("conclusion") or ""))
        if subject == SHA40_ZERO or head_sha != subject:
            signal = "STALE"
        elif signal == "PASSING" and (spec.get("jobs") or spec.get("job_prefixes")):
            try:
                if run_id not in jobs_cache:
                    jobs_cache[run_id] = workflow_jobs(repo, run_id, token)
                signal = aggregate_jobs(spec, jobs_cache[run_id])
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
                signal = "UNAVAILABLE"
        results.append({
            "label": spec["label"], "workflow": workflow, "scope": evidence_scope(spec), "signal": signal,
            "run_id": run_id, "run_number": int(run.get("run_number") or 0), "run_url": str(run.get("html_url") or ""),
            "head_sha": head_sha if len(head_sha) == 40 else SHA40_ZERO, "completed_at_utc": completed,
            "age_days": evidence_age_days(day, completed), "offline": False, "ordinal": index,
        })
    return subject, results


def render_card(system: dict[str, Any], slot: int, day: dt.date, subject: str, evidence: list[dict[str, Any]], theme: str) -> str:
    return renderer.render_card(system, slot, day, subject, evidence, theme, version=VERSION, owner=OWNER)


def validate_pool() -> None:
    registry.load_registry()
    repos = [str(system["repo"]) for system in POOL]
    if len(POOL) != 10 or len(set(repos)) != 10:
        raise ValueError("Spotlight v2 pool must contain exactly 10 distinct reviewed repositories")
    for system in POOL:
        evidence = system.get("evidence")
        if not isinstance(evidence, tuple) or len(evidence) != 2:
            raise ValueError(f"{system['repo']}: exactly two evidence signals are required")
        labels = [str(item.get("label") or "") for item in evidence]
        if len(set(labels)) != 2 or any(not label for label in labels):
            raise ValueError(f"{system['repo']}: evidence labels must be two distinct non-empty values")


def main() -> int:
    try:
        args = parse_args()
        validate_pool()
        day = utc_date(args.date)
        selected = select_systems(day)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        token = os.environ.get("GITHUB_TOKEN")
        manifest: dict[str, Any] = {
            "version": VERSION,
            "selection_date_utc": day.isoformat(),
            "selection_policy": "deterministic-daily-sha256-sample",
            "evidence_model": EVIDENCE_MODEL,
            "portfolio_registry": {"version": registry.VERSION, "digest": registry.registry_digest()},
            "freshness_basis": "UTC whole-day age from workflow evidence timestamp",
            "live_policy": "signals bind to current main revision; mismatched workflow head is STALE",
            "slots": [],
        }
        for slot, system in enumerate(selected, start=1):
            subject, records = collect_evidence(system, day, token, args.offline)
            for theme in ("light", "dark"):
                (args.output_dir / f"spotlight-{slot}-{theme}.svg").write_text(render_card(system, slot, day, subject, records, theme), encoding="utf-8")
            manifest["slots"].append({
                "slot": slot, "repository": f"{OWNER}/{system['repo']}", "title": system["title"],
                "glyph": system["glyph"], "topology": system["topology"], "subject_revision": subject,
                "evidence_contract": [
                    {"label": spec["label"], "workflow": spec["workflow"], "scope": evidence_scope(spec)}
                    for spec in system["evidence"]
                ],
                "signals": records,
            })
        (args.output_dir / "spotlight-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return 0
    except (OSError, ValueError, AssertionError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
