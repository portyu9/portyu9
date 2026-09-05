#!/usr/bin/env python3
"""Generate deterministic daily Engineering Evidence Spotlight v2 cards.

v2 replaces the former fixed CI+SECURITY assumption with an explicit evidence
contract per repository. Every rendered signal is bound to the current main
revision, a named workflow/job scope, exact run provenance, and UTC freshness.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import html
import json
import os
import random
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

OWNER = "portyu9"
VERSION = "engineering-spotlight-v2"
EVIDENCE_MODEL = "per-system-evidence-contract-v2"
SHA40_ZERO = "0" * 40

DEFAULT_EVIDENCE = (
    {"label": "CI", "workflow": "ci.yml"},
    {"label": "SECURITY", "workflow": "security.yml"},
)

AGENT_EVIDENCE = (
    {
        "label": "QUALITY+SEC",
        "workflow": "ci.yml",
        "job_prefixes": ("Quality / Python ",),
        "required_steps": ("Tests", "Bandit", "Dependency audit"),
    },
    {
        "label": "AGENT LABS",
        "workflow": "ci.yml",
        "jobs": (
            "OpenAI adapter / deterministic SDK",
            "MCP fault lab / deterministic protocol",
            "MCP remote auth / loopback HTTP",
            "MCP OAuth flow / separated AS-RS",
            "Package integrity",
        ),
    },
)

POOL = (
    {"repo":"qa-automation-dotnet-selenium","title":".NET + SELENIUM QE","domain":"WEB / UI · SELENIUM + XUNIT","signature":"Browser lifecycle · owned fixtures · bounded evidence","accent":"#43B02A","accent2":"#28D7FF","accent3":"#8C7CFF","glyph":"browser-frame","topology":"session-rails","evidence":DEFAULT_EVIDENCE},
    {"repo":"qa-automation-api-postman-newman","title":"POSTMAN + NEWMAN API QE","domain":"API · POSTMAN + NEWMAN","signature":"Collection contracts · target ownership · execution evidence","accent":"#FF6C37","accent2":"#FF2BD6","accent3":"#28D7FF","glyph":"request-arrow","topology":"request-route","evidence":DEFAULT_EVIDENCE},
    {"repo":"qa-automation-mobile-appium","title":"APPIUM MOBILE QE","domain":"MOBILE · APPIUM + WEBDRIVERIO","signature":"Capability policy · session lifecycle · device evidence","accent":"#8A5CF6","accent2":"#FF2BD6","accent3":"#28D7FF","glyph":"device-frame","topology":"device-bus","evidence":DEFAULT_EVIDENCE},
    {"repo":"qa-automation-ui-cypress","title":"CYPRESS UI QE","domain":"WEB / UI · CYPRESS","signature":"Retryability · isolation · deterministic target ownership","accent":"#00BFA6","accent2":"#28D7FF","accent3":"#8C7CFF","glyph":"retry-loop","topology":"retry-circuit","evidence":DEFAULT_EVIDENCE},
    {"repo":"qa-automation-python-pytest","title":"PYTHON + PYTEST QE","domain":"LAYERED QE · PYTEST","signature":"Failure attribution · persistence · browser · security","accent":"#0A9EDC","accent2":"#28D7FF","accent3":"#8C7CFF","glyph":"bracket-check","topology":"layered-ladder","evidence":DEFAULT_EVIDENCE},
    {"repo":"qa-automation-node-supertest","title":"SUPERTEST API QE","domain":"API / CONTRACT · SUPERTEST + PACT","signature":"Component · transport · contract · listener boundaries","accent":"#00A6C7","accent2":"#28D7FF","accent3":"#FF2BD6","glyph":"endpoint-link","topology":"contract-bridge","evidence":DEFAULT_EVIDENCE},
    {"repo":"qa-automation-java-restassured","title":"REST ASSURED QE","domain":"API / PERSISTENCE · REST ASSURED","signature":"Protocol · schema · PostgreSQL · attributable evidence","accent":"#ED8B00","accent2":"#FF6C37","accent3":"#8C7CFF","glyph":"shield-route","topology":"protocol-chain","evidence":DEFAULT_EVIDENCE},
    {"repo":"qa-automation-node-playwright","title":"PLAYWRIGHT QE","domain":"E2E / BROWSER · PLAYWRIGHT","signature":"Context isolation · traces · attributable browser evidence","accent":"#2EAD33","accent2":"#28D7FF","accent3":"#8C7CFF","glyph":"trace-frame","topology":"trace-fan","evidence":DEFAULT_EVIDENCE},
    {"repo":"qa-automation-load-k6","title":"K6 PERFORMANCE QE","domain":"PERFORMANCE · K6","signature":"Explicit workloads · target authorization · zero-traffic safety","accent":"#7D64FF","accent2":"#FF2BD6","accent3":"#28D7FF","glyph":"gauge-needle","topology":"load-wave","evidence":DEFAULT_EVIDENCE},
    {"repo":"qa-automation-ai-agent-evals","title":"AGENT EVALUATION + TEVV","domain":"AGENTIC QA · TEVV / ASSURANCE","signature":"Evidence-bound trials · authority checks · replayable agent assurance","accent":"#FF4D4D","accent2":"#FF3131","accent3":"#28D7FF","glyph":"evidence-hex","topology":"assurance-lattice","evidence":AGENT_EVIDENCE},
)


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


def request_headers(token: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "portyu9-profile-spotlight-v2",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def fetch_json(url: str, token: str | None) -> dict[str, Any]:
    with urllib.request.urlopen(
        urllib.request.Request(url, headers=request_headers(token)), timeout=12
    ) as response:
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
    endpoint = (
        f"https://api.github.com/repos/{OWNER}/{repo}/actions/workflows/{encoded}/runs"
        "?branch=main&event=push&per_page=1"
    )
    payload = fetch_json(endpoint, token)
    runs = payload.get("workflow_runs") or []
    return runs[0] if runs and isinstance(runs[0], dict) else {}


def workflow_jobs(repo: str, run_id: int, token: str | None) -> list[dict[str, Any]]:
    payload = fetch_json(
        f"https://api.github.com/repos/{OWNER}/{repo}/actions/runs/{run_id}/jobs?per_page=100",
        token,
    )
    return [job for job in (payload.get("jobs") or []) if isinstance(job, dict)]


def conclusion_signal(conclusion: str) -> str:
    value = conclusion.lower().strip()
    if value == "success":
        return "PASSING"
    if value in {"failure", "timed_out", "startup_failure"}:
        return "FAILING"
    if value in {"cancelled", "skipped", "neutral", "action_required", "stale"}:
        return value.replace("_", " ").upper()
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
        matched = [
            job for job in jobs
            if any(str(job.get("name") or "").startswith(prefix) for prefix in prefixes)
        ]
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
        return "jobs:" + "|".join(spec["jobs"])
    if spec.get("job_prefixes"):
        scope = "job-prefix:" + "|".join(spec["job_prefixes"])
        if spec.get("required_steps"):
            scope += ";steps:" + "|".join(spec["required_steps"])
        return scope
    return "workflow"


def evidence_age_days(day: dt.date, timestamp: str) -> int:
    if not timestamp:
        return 0
    parsed = dt.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    return max(0, (day - parsed.date()).days)


def offline_evidence(repo: str, spec: dict[str, Any], day: dt.date, index: int) -> dict[str, Any]:
    seed = hashlib.sha256(f"{VERSION}:{repo}:{spec['label']}:{day.isoformat()}".encode()).hexdigest()
    run_id = int(seed[40:52], 16)
    run_number = 100 + (int(seed[52:58], 16) % 900)
    return {
        "label": spec["label"],
        "workflow": spec["workflow"],
        "scope": evidence_scope(spec),
        "signal": "UNKNOWN",
        "run_id": run_id,
        "run_number": run_number,
        "run_url": f"https://github.com/{OWNER}/{repo}/actions/runs/{run_id}",
        "head_sha": seed[:40],
        "completed_at_utc": f"{day.isoformat()}T00:00:00Z",
        "age_days": 0,
        "offline": True,
        "ordinal": index,
    }


def collect_evidence(system: dict[str, Any], day: dt.date, token: str | None, offline: bool) -> tuple[str, list[dict[str, Any]]]:
    repo = str(system["repo"])
    specs = list(system["evidence"])
    if offline:
        subject = hashlib.sha256(f"{VERSION}:{repo}:subject:{day.isoformat()}".encode()).hexdigest()[:40]
        return subject, [offline_evidence(repo, spec, day, i) for i, spec in enumerate(specs, 1)]

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
            "label": spec["label"],
            "workflow": workflow,
            "scope": evidence_scope(spec),
            "signal": signal,
            "run_id": run_id,
            "run_number": int(run.get("run_number") or 0),
            "run_url": str(run.get("html_url") or ""),
            "head_sha": head_sha if len(head_sha) == 40 else SHA40_ZERO,
            "completed_at_utc": completed,
            "age_days": evidence_age_days(day, completed),
            "offline": False,
            "ordinal": index,
        })

    return subject, results


def palette(theme: str) -> dict[str, str]:
    if theme == "dark":
        return {"surface":"#0D1117","stroke":"#30363D","ink":"#F0F6FC","muted":"#8B949E","chip":"#161B22","chiptext":"#C9D1D9","node":"#0D1117"}
    return {"surface":"#FFFFFF","stroke":"#D0D7DE","ink":"#1F2328","muted":"#57606A","chip":"#F6F8FA","chiptext":"#3D444D","node":"#FFFFFF"}


def signal_color(signal: str) -> str:
    if signal == "PASSING": return "#1A7F37"
    if signal == "FAILING": return "#CF222E"
    if signal == "RUNNING": return "#9A6700"
    if signal == "STALE": return "#BF8700"
    return "#57606A"


def fit_font(text: str, default: int = 24) -> int:
    if len(text) > 25: return default - 4
    if len(text) > 21: return default - 2
    return default


def evidence_pill(label: str, signal: str, x: float, theme: str) -> tuple[str, float]:
    p = palette(theme)
    rendered = f"{label} · {signal}"
    width = max(118.0, min(218.0, 34.0 + len(rendered) * 6.4))
    border = signal_color(signal)
    text_size = 9.4 if len(rendered) <= 21 else 8.7
    markup = (
        f'<rect x="{x:.1f}" y="145" width="{width:.1f}" height="28" rx="8" fill="{p["chip"]}" stroke="{border}" stroke-opacity=".75" stroke-width="1.15"/>'
        f'<circle cx="{x+15:.1f}" cy="159" r="4.0" fill="{border}"/>'
        f'<text x="{x+27:.1f}" y="163" fill="{p["chiptext"]}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="{text_size}" font-weight="800">{html.escape(rendered)}</text>'
    )
    return markup, width


def glyph_markup(glyph: str, accent: str) -> str:
    common = f'fill="none" stroke="{accent}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"'
    glyphs = {
        "browser-frame": f'<g {common}><path d="M38 47h16v14H38zM38 51h16"/><circle cx="41" cy="49" r=".7" fill="{accent}" stroke="none"/></g>',
        "request-arrow": f'<g {common}><path d="M39 55h14M49 50l5 5-5 5"/><circle cx="39" cy="55" r="2.5"/></g>',
        "device-frame": f'<g {common}><rect x="39" y="45" width="14" height="20" rx="2"/><path d="M43 48h6M44 61h4"/></g>',
        "retry-loop": f'<g {common}><path d="M54 50a9 9 0 1 0 1 10M54 50v6h-6"/></g>',
        "bracket-check": f'<g {common}><path d="M43 48l-6 7 6 7M55 48l6 7-6 7M45 56l4 4 8-10"/></g>',
        "endpoint-link": f'<g {common}><circle cx="40" cy="55" r="3"/><circle cx="56" cy="49" r="3"/><circle cx="57" cy="62" r="3"/><path d="M43 54l10-4M43 56l11 5"/></g>',
        "shield-route": f'<g {common}><path d="M47 45l8 3v7c0 6-4 9-8 11-4-2-8-5-8-11v-7z"/><path d="M42 56h5l4-4"/></g>',
        "trace-frame": f'<g {common}><path d="M38 48v-4h6M56 44h6v6M62 60v5h-6M44 65h-6v-5"/><path d="M43 60l14-12"/></g>',
        "gauge-needle": f'<g {common}><path d="M38 61a10 10 0 0 1 20 0"/><path d="M48 59l6-7"/><path d="M41 61h14"/></g>',
        "evidence-hex": f'<g {common}><path d="M48 45l9 5v10l-9 5-9-5V50z"/><path d="M43 55l4 4 7-8"/></g>',
    }
    return glyphs[glyph]


def topology_markup(name: str, node: str, a: str, b: str, c: str) -> str:
    digest = hashlib.sha256(name.encode()).digest()
    points = [(462 + digest[i] % 138, 22 + digest[i + 5] % 82) for i in range(5)]
    colors = (a, b, c, a, b)
    paths = (
        f'<path d="M{points[0][0]} {points[0][1]}L{points[1][0]} {points[1][1]}L{points[2][0]} {points[2][1]}" fill="none" stroke="{a}" stroke-opacity=".11" stroke-linecap="round" stroke-linejoin="round"/>'
        f'<path d="M{points[1][0]} {points[1][1]}L{points[3][0]} {points[3][1]}L{points[4][0]} {points[4][1]}" fill="none" stroke="{b}" stroke-opacity=".11" stroke-linecap="round" stroke-linejoin="round"/>'
        f'<path d="M{points[0][0]} {points[0][1]}L{points[3][0]} {points[3][1]}" fill="none" stroke="{c}" stroke-opacity=".08" stroke-linecap="round"/>'
    )
    circles = "".join(
        f'<circle cx="{x}" cy="{y}" r="3.4" fill="{node}" stroke="{color}" stroke-width="1.5"/>'
        for (x, y), color in zip(points, colors)
    )
    return paths + circles


def render_card(system: dict[str, Any], slot: int, day: dt.date, subject: str, evidence: list[dict[str, Any]], theme: str) -> str:
    p = palette(theme)
    accent, accent2, accent3 = system["accent"], system["accent2"], system["accent3"]
    title = html.escape(str(system["title"]))
    domain = html.escape(str(system["domain"]))
    signature = html.escape(str(system["signature"]))
    repo = html.escape(str(system["repo"]))
    first, first_w = evidence_pill(str(evidence[0]["label"]), str(evidence[0]["signal"]), 40, theme)
    second, _ = evidence_pill(str(evidence[1]["label"]), str(evidence[1]["signal"]), 52 + first_w, theme)
    max_age = max(int(item["age_days"]) for item in evidence)
    run_attr = ";".join(f"{item['label']}:{item['run_id']}" for item in evidence)
    workflow_attr = ";".join(f"{item['label']}:{item['workflow']}" for item in evidence)
    evidence_desc = "; ".join(
        f"{item['label']} via {item['workflow']} run {item['run_id']} is {item['signal']}"
        for item in evidence
    )
    glyph = glyph_markup(str(system["glyph"]), str(accent))
    topology = topology_markup(str(system["topology"]), p["node"], str(accent), str(accent2), str(accent3))
    title_size = fit_font(str(system["title"]))
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="620" height="198" viewBox="0 0 620 198" role="img" aria-labelledby="title desc" data-spotlight="{VERSION}" data-layout="evidence-v2" data-slot="{slot}" data-date="{day.isoformat()}" data-repository="{OWNER}/{repo}" data-subject-revision="{subject}" data-evidence-age-days="{max_age}" data-evidence-runs="{html.escape(run_attr)}" data-evidence-workflows="{html.escape(workflow_attr)}" data-glyph="{system["glyph"]}" data-topology="{system["topology"]}">
  <title id="title">{title}</title>
  <desc id="desc">Daily deterministic Evidence Spotlight for {OWNER}/{repo} at main revision {subject}. {signature}. {html.escape(evidence_desc)}. Freshness is UTC whole-day age from the named workflow evidence timestamp.</desc>
  <defs>
    <linearGradient id="edge" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{accent}"/><stop offset=".54" stop-color="{accent2}"/><stop offset="1" stop-color="{accent3}"/></linearGradient>
    <linearGradient id="wash" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="{accent}" stop-opacity=".055"/><stop offset=".54" stop-color="{accent2}" stop-opacity=".026"/><stop offset="1" stop-color="{accent3}" stop-opacity=".045"/></linearGradient>
  </defs>
  <rect x="1" y="1" width="618" height="196" rx="15" fill="{p['surface']}" stroke="{p['stroke']}"/><rect x="2" y="2" width="616" height="194" rx="14" fill="url(#wash)"/>
  {topology}
  <rect x="20" y="18" width="4" height="162" rx="2" fill="url(#edge)"/>
  <text x="40" y="28" fill="{p['muted']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="10.5" font-weight="700" letter-spacing="1.15">EVIDENCE SPOTLIGHT · {slot:02d}</text>
  {glyph}
  <text x="68" y="62" fill="{accent}" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="{title_size}" font-weight="800">{title}</text>
  <text x="40" y="87" fill="{p['ink']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="10.5" font-weight="700">{domain}</text>
  <text x="40" y="109" fill="{p['muted']}" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="12.2" font-weight="550">{signature}</text>
  <text x="40" y="131" fill="{p['muted']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="8.8" font-weight="700">SUBJECT · {subject} · MAIN</text>
  <text x="590" y="131" text-anchor="end" fill="{p['muted']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="8.8" font-weight="700">FRESHNESS · {max_age}d UTC</text>
  {first}{second}
  <text x="40" y="189" fill="{p['muted']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="8.2">RUNS · {html.escape(" / ".join(f"{item['workflow']}#{item['run_id']}" for item in evidence))}</text>
  <text x="590" y="189" text-anchor="end" fill="{p['muted']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="8.2">repo · {repo}</text>
</svg>
"""


def validate_pool() -> None:
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
        if any(not str(item.get("workflow") or "").endswith((".yml", ".yaml")) for item in evidence):
            raise ValueError(f"{system['repo']}: evidence workflows must be explicit YAML filenames")

    agent = next(system for system in POOL if system["repo"] == "qa-automation-ai-agent-evals")
    labels = tuple(item["label"] for item in agent["evidence"])
    if labels != ("QUALITY+SEC", "AGENT LABS"):
        raise ValueError("Agent Evaluation evidence contract changed")
    if any(item["workflow"] != "ci.yml" for item in agent["evidence"]):
        raise ValueError("Agent Evaluation evidence must remain scoped to its single CI workflow")
    if tuple(agent["evidence"][0].get("required_steps") or ()) != ("Tests", "Bandit", "Dependency audit"):
        raise ValueError("Agent Evaluation quality/security step contract changed")
    if len(tuple(agent["evidence"][1].get("jobs") or ())) != 5:
        raise ValueError("Agent Evaluation lab job contract changed")


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
            "freshness_basis": "UTC whole-day age from workflow evidence timestamp",
            "live_policy": "signals bind to current main revision; mismatched workflow head is STALE",
            "slots": [],
        }
        for slot, system in enumerate(selected, start=1):
            subject, evidence = collect_evidence(system, day, token, args.offline)
            for theme in ("light", "dark"):
                (args.output_dir / f"spotlight-{slot}-{theme}.svg").write_text(
                    render_card(system, slot, day, subject, evidence, theme),
                    encoding="utf-8",
                )
            manifest["slots"].append({
                "slot": slot,
                "repository": f"{OWNER}/{system['repo']}",
                "title": system["title"],
                "glyph": system["glyph"],
                "topology": system["topology"],
                "subject_revision": subject,
                "evidence_contract": [
                    {"label": spec["label"], "workflow": spec["workflow"], "scope": evidence_scope(spec)}
                    for spec in system["evidence"]
                ],
                "signals": evidence,
            })
        (args.output_dir / "spotlight-manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return 0
    except (OSError, ValueError, AssertionError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
