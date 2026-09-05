#!/usr/bin/env python3
"""Generate Portfolio Evidence Ledger v2 with orthogonal evidence dimensions.

Each evidence record keeps three independent facts:
- result: what the named workflow/job scope concluded;
- binding: whether that run head is the current main subject;
- freshness: whether a timestamp is available and how old it is.

A different-subject run therefore never overwrites a PASSING/FAILING execution result
with a synthetic "STALE" result. The ledger is the single live evidence collection
surface consumed by the Engineering Spotlight projection.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import urllib.error
from pathlib import Path
from typing import Any

import engineering_spotlight_v2 as evidence

OWNER = "portyu9"
VERSION = "portfolio-evidence-ledger-v2"
KIND = "portfolio-evidence-ledger"
OUTPUT = "portfolio-evidence-ledger.json"
EVIDENCE_SEMANTICS = "execution-result-subject-binding-freshness-v1"
SHA40_ZERO = "0" * 40

PERMANENT = (
    {
        "repo": "ai-qa-automation",
        "title": "AI QA CONTROL PLANE",
        "evidence": ({"label": "CI", "workflow": "ci.yml"},),
    },
    {
        "repo": "qa-automation-ai-agent-evals",
        "title": "AGENT EVALUATION + TEVV",
        "evidence": evidence.AGENT_EVIDENCE,
    },
    {
        "repo": "qa-automation-graphql",
        "title": "GRAPHQL QE",
        "evidence": evidence.DEFAULT_EVIDENCE,
    },
    {
        "repo": "qa-automation-visual-and-accessibility-playwright-axe",
        "title": "VISUAL + ACCESSIBILITY QE",
        "evidence": evidence.DEFAULT_EVIDENCE,
    },
)

PERMANENT_REPOS = {str(system["repo"]) for system in PERMANENT}
ROTATING = tuple(system for system in evidence.POOL if str(system["repo"]) not in PERMANENT_REPOS)
SYSTEMS = PERMANENT + tuple(
    {"repo": system["repo"], "title": system["title"], "evidence": system["evidence"]}
    for system in ROTATING
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--date", help="UTC date as YYYY-MM-DD; defaults to current UTC date")
    parser.add_argument("--offline", action="store_true", help="Generate deterministic synthetic evidence without GitHub API calls")
    return parser.parse_args()


def utc_date(raw: str | None) -> dt.date:
    return dt.date.fromisoformat(raw) if raw else dt.datetime.now(dt.timezone.utc).date()


def canonical_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def classify(repo: str) -> str:
    return "permanent" if repo in PERMANENT_REPOS else "rotating"


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
    system: dict[str, Any],
    day: dt.date,
    token: str | None,
    offline: bool,
) -> tuple[str, list[dict[str, Any]]]:
    repo = str(system["repo"])
    specs = list(system["evidence"])
    if offline:
        subject = hashlib.sha256(f"{VERSION}:{repo}:subject:{day.isoformat()}".encode()).hexdigest()[:40]
        return subject, [offline_signal(repo, spec, day, index) for index, spec in enumerate(specs, 1)]

    try:
        subject = evidence.main_revision(repo, token)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
        subject = SHA40_ZERO

    run_cache: dict[str, dict[str, Any]] = {}
    jobs_cache: dict[int, list[dict[str, Any]]] = {}
    records: list[dict[str, Any]] = []

    for index, spec in enumerate(specs, 1):
        workflow = str(spec["workflow"])
        try:
            if workflow not in run_cache:
                run_cache[workflow] = evidence.latest_workflow_run(repo, workflow, token)
            run = run_cache[workflow]
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
            run = {}

        if not run:
            records.append(
                {
                    "label": spec["label"],
                    "workflow": workflow,
                    "scope": evidence.evidence_scope(spec),
                    "result": "UNAVAILABLE",
                    "binding": "UNAVAILABLE",
                    "freshness": "UNAVAILABLE",
                    "run_id": 0,
                    "run_number": 0,
                    "run_url": "",
                    "head_sha": SHA40_ZERO,
                    "completed_at_utc": "",
                    "age_days": 0,
                    "offline": False,
                    "ordinal": index,
                }
            )
            continue

        run_id = int(run.get("id") or 0)
        raw_head = str(run.get("head_sha") or "")
        head_sha = raw_head if len(raw_head) == 40 and all(ch in "0123456789abcdef" for ch in raw_head) else SHA40_ZERO
        status = str(run.get("status") or "")
        completed = str(run.get("updated_at") or run.get("run_started_at") or run.get("created_at") or "")
        result = "RUNNING" if status != "completed" else evidence.conclusion_signal(str(run.get("conclusion") or ""))

        # Scope-specific job/step evidence refines the execution result independently
        # of subject binding. A different run head must never erase the observed result.
        if result == "PASSING" and (spec.get("jobs") or spec.get("job_prefixes")):
            try:
                if run_id not in jobs_cache:
                    jobs_cache[run_id] = evidence.workflow_jobs(repo, run_id, token)
                result = evidence.aggregate_jobs(spec, jobs_cache[run_id])
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, ValueError):
                result = "UNAVAILABLE"

        age = evidence.evidence_age_days(day, completed) if completed else 0
        records.append(
            {
                "label": spec["label"],
                "workflow": workflow,
                "scope": evidence.evidence_scope(spec),
                "result": result,
                "binding": binding_state(subject, head_sha, True),
                "freshness": freshness_state(completed, age, False),
                "run_id": run_id,
                "run_number": int(run.get("run_number") or 0),
                "run_url": str(run.get("html_url") or ""),
                "head_sha": head_sha,
                "completed_at_utc": completed,
                "age_days": age,
                "offline": False,
                "ordinal": index,
            }
        )

    return subject, records


def collect_system(system: dict[str, Any], day: dt.date, token: str | None, offline: bool) -> dict[str, Any]:
    subject, signals = collect_evidence_dimensions(system, day, token, offline)
    contract = [
        {
            "label": spec["label"],
            "workflow": spec["workflow"],
            "scope": evidence.evidence_scope(spec),
        }
        for spec in system["evidence"]
    ]
    ages = [int(signal["age_days"]) for signal in signals if signal.get("freshness") not in {"UNAVAILABLE"}]
    return {
        "repository": f"{OWNER}/{system['repo']}",
        "title": system["title"],
        "classification": classify(str(system["repo"])),
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
    if len(SYSTEMS) != 13 or len({str(system["repo"]) for system in SYSTEMS}) != 13:
        raise ValueError("portfolio ledger must contain exactly 13 distinct reviewed systems")
    if len(PERMANENT) != 4 or len(ROTATING) != 9:
        raise ValueError("portfolio classification must remain four permanent plus nine rotating systems")

    systems = [collect_system(system, day, token, offline) for system in SYSTEMS]
    core: dict[str, Any] = {
        "version": VERSION,
        "kind": KIND,
        "owner": OWNER,
        "as_of_date_utc": day.isoformat(),
        "evidence_semantics": EVIDENCE_SEMANTICS,
        "subject_policy": "current-main-revision-per-system",
        "freshness_basis": "UTC whole-day age from workflow evidence timestamp",
        "classification_policy": "four permanent profile systems plus nine rotating Spotlight systems",
        "system_count": len(systems),
        "result_summary": summarize(systems, "result"),
        "binding_summary": summarize(systems, "binding"),
        "freshness_summary": summarize(systems, "freshness"),
        "systems": systems,
    }
    digest = canonical_digest(core)
    return {
        **core,
        "evidence_id": f"PL2-{digest[:16].upper()}",
        "evidence_digest": f"sha256:{digest}",
    }


def main() -> int:
    try:
        args = parse_args()
        day = utc_date(args.date)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        ledger = build_ledger(day, os.environ.get("GITHUB_TOKEN"), args.offline)
        path = args.output_dir / OUTPUT
        path.write_text(json.dumps(ledger, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(
            f"Portfolio evidence ledger v2 generated: {ledger['evidence_id']} · {ledger['system_count']} systems · "
            "result/binding/freshness separated"
        )
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
