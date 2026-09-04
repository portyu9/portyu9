#!/usr/bin/env python3
'''Generate two deterministic daily engineering Evidence Spotlight cards.

Selection changes once per UTC date. Workflow conclusions are refreshed whenever the
profile-stats workflow runs, so selection remains stable during the day while evidence
signals can change without rewriting README.md.
'''
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

OWNER = "portyu9"
VERSION = "engineering-spotlight-v1"
POOL = (
    {"repo":"qa-automation-dotnet-selenium","title":".NET + SELENIUM QE","domain":"WEB / UI · SELENIUM + XUNIT","signature":"Browser lifecycle · owned fixtures · bounded evidence","accent":"#43B02A","accent2":"#28D7FF","accent3":"#8C7CFF"},
    {"repo":"qa-automation-api-postman-newman","title":"POSTMAN + NEWMAN API QE","domain":"API · POSTMAN + NEWMAN","signature":"Collection contracts · target ownership · execution evidence","accent":"#FF6C37","accent2":"#FF2BD6","accent3":"#28D7FF"},
    {"repo":"qa-automation-mobile-appium","title":"APPIUM MOBILE QE","domain":"MOBILE · APPIUM + WEBDRIVERIO","signature":"Capability policy · session lifecycle · device evidence","accent":"#8A5CF6","accent2":"#FF2BD6","accent3":"#28D7FF"},
    {"repo":"qa-automation-ui-cypress","title":"CYPRESS UI QE","domain":"WEB / UI · CYPRESS","signature":"Retryability · isolation · deterministic target ownership","accent":"#00BFA6","accent2":"#28D7FF","accent3":"#8C7CFF"},
    {"repo":"qa-automation-python-pytest","title":"PYTHON + PYTEST QE","domain":"LAYERED QE · PYTEST","signature":"Failure attribution · persistence · browser · security","accent":"#0A9EDC","accent2":"#28D7FF","accent3":"#8C7CFF"},
    {"repo":"qa-automation-node-supertest","title":"SUPERTEST API QE","domain":"API / CONTRACT · SUPERTEST + PACT","signature":"Component · transport · contract · listener boundaries","accent":"#00A6C7","accent2":"#28D7FF","accent3":"#FF2BD6"},
    {"repo":"qa-automation-java-restassured","title":"REST ASSURED QE","domain":"API / PERSISTENCE · REST ASSURED","signature":"Protocol · schema · PostgreSQL · attributable evidence","accent":"#ED8B00","accent2":"#FF6C37","accent3":"#8C7CFF"},
    {"repo":"qa-automation-node-playwright","title":"PLAYWRIGHT QE","domain":"E2E / BROWSER · PLAYWRIGHT","signature":"Context isolation · traces · attributable browser evidence","accent":"#2EAD33","accent2":"#28D7FF","accent3":"#8C7CFF"},
    {"repo":"qa-automation-load-k6","title":"K6 PERFORMANCE QE","domain":"PERFORMANCE · K6","signature":"Explicit workloads · target authorization · zero-traffic safety","accent":"#7D64FF","accent2":"#FF2BD6","accent3":"#28D7FF"},
)
WORKFLOWS = (("CI", "ci.yml"), ("SECURITY", "security.yml"))

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--date", help="UTC date as YYYY-MM-DD; defaults to current UTC date")
    parser.add_argument("--offline", action="store_true", help="Render deterministic UNKNOWN status without GitHub API calls")
    return parser.parse_args()

def utc_date(raw: str | None) -> dt.date:
    return dt.date.fromisoformat(raw) if raw else dt.datetime.now(dt.timezone.utc).date()

def select_systems(day: dt.date) -> list[dict[str, str]]:
    seed = int(hashlib.sha256(f"{VERSION}:{day.isoformat()}".encode()).hexdigest(), 16)
    return random.Random(seed).sample(list(POOL), 2)

def workflow_signal(repo: str, workflow: str, token: str | None, offline: bool) -> str:
    if offline:
        return "UNKNOWN"
    endpoint = f"https://api.github.com/repos/{OWNER}/{repo}/actions/workflows/{urllib.parse.quote(workflow, safe='')}/runs?branch=main&per_page=1"
    headers = {"Accept":"application/vnd.github+json","User-Agent":"portyu9-profile-spotlight","X-GitHub-Api-Version":"2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        with urllib.request.urlopen(urllib.request.Request(endpoint, headers=headers), timeout=12) as response:
            payload = json.load(response)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return "UNAVAILABLE"
    runs = payload.get("workflow_runs") or []
    if not runs:
        return "NO SIGNAL"
    run = runs[0]
    if run.get("status") != "completed":
        return "RUNNING"
    conclusion = (run.get("conclusion") or "").lower()
    if conclusion == "success":
        return "PASSING"
    if conclusion in {"failure", "timed_out", "startup_failure"}:
        return "FAILING"
    if conclusion in {"cancelled", "skipped", "neutral", "action_required", "stale"}:
        return conclusion.replace("_", " ").upper()
    return "UNKNOWN"

def palette(theme: str) -> dict[str, str]:
    if theme == "dark":
        return {"surface":"#0D1117","stroke":"#30363D","ink":"#F0F6FC","muted":"#8B949E","chip":"#161B22","chiptext":"#C9D1D9","node":"#0D1117"}
    return {"surface":"#FFFFFF","stroke":"#D0D7DE","ink":"#1F2328","muted":"#57606A","chip":"#F6F8FA","chiptext":"#3D444D","node":"#FFFFFF"}

def signal_color(signal: str) -> str:
    if signal == "PASSING": return "#1A7F37"
    if signal == "FAILING": return "#CF222E"
    if signal == "RUNNING": return "#9A6700"
    return "#57606A"

def fit_font(text: str, default: int = 24) -> int:
    if len(text) > 25: return default - 4
    if len(text) > 21: return default - 2
    return default

def evidence_pill(label: str, signal: str, x: float, theme: str) -> tuple[str, float]:
    p = palette(theme)
    rendered = f"{label} · {signal}"
    width = max(118.0, min(208.0, 34.0 + len(rendered) * 6.6))
    border = signal_color(signal)
    text_size = 9.6 if len(rendered) <= 20 else 9.0
    cy = 145
    markup = (
        f'<rect x="{x:.1f}" y="131" width="{width:.1f}" height="28" rx="8" fill="{p["chip"]}" stroke="{border}" stroke-width="1.25"/>'
        f'<circle cx="{x+15:.1f}" cy="{cy}" r="4.2" fill="{border}"/>'
        f'<text x="{x+27:.1f}" y="149" fill="{p["chiptext"]}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="{text_size}" font-weight="800">{html.escape(rendered)}</text>'
    )
    return markup, width

def render_card(system: dict[str, str], slot: int, day: dt.date, statuses: dict[str, str], theme: str) -> str:
    p = palette(theme)
    accent, accent2, accent3 = system["accent"], system["accent2"], system["accent3"]
    title = html.escape(system["title"])
    domain = html.escape(system["domain"])
    signature = html.escape(system["signature"])
    repo = html.escape(system["repo"])
    first, first_w = evidence_pill("CI", statuses["CI"], 40, theme)
    second, _ = evidence_pill("SECURITY", statuses["SECURITY"], 52 + first_w, theme)
    title_size = fit_font(system["title"])
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="620" height="170" viewBox="0 0 620 170" role="img" aria-labelledby="title desc" data-spotlight="{VERSION}" data-layout="rich-v2" data-slot="{slot}" data-date="{day.isoformat()}" data-repository="{OWNER}/{repo}">
  <title id="title">{title}</title>
  <desc id="desc">Daily deterministic Evidence Spotlight for {OWNER}/{repo}. {signature}. Workflow signals are scoped to the named main-branch workflows.</desc>
  <defs>
    <linearGradient id="edge" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{accent}"/><stop offset=".54" stop-color="{accent2}"/><stop offset="1" stop-color="{accent3}"/></linearGradient>
    <linearGradient id="wash" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="{accent}" stop-opacity=".055"/><stop offset=".54" stop-color="{accent2}" stop-opacity=".026"/><stop offset="1" stop-color="{accent3}" stop-opacity=".045"/></linearGradient>
  </defs>
  <rect x="1" y="1" width="618" height="168" rx="15" fill="{p['surface']}" stroke="{p['stroke']}"/><rect x="2" y="2" width="616" height="166" rx="14" fill="url(#wash)"/>
  <path d="M474 18h42l18 18h42l18-17h12" fill="none" stroke="{accent2}" stroke-opacity=".12" stroke-linecap="round" stroke-linejoin="round"/><path d="M486 158h38l18-17h42l18 16h4" fill="none" stroke="{accent3}" stroke-opacity=".10" stroke-linecap="round" stroke-linejoin="round"/><path d="M530 18c16 18 20 36 10 53s-2 34 17 49" fill="none" stroke="{accent}" stroke-opacity=".08" stroke-linecap="round"/>
  <circle cx="534" cy="36" r="3.4" fill="{p['node']}" stroke="{accent2}" stroke-width="1.5"/><circle cx="594" cy="19" r="3.4" fill="{p['node']}" stroke="{accent3}" stroke-width="1.5"/><circle cx="542" cy="141" r="3.4" fill="{p['node']}" stroke="{accent}" stroke-width="1.5"/><circle cx="602" cy="157" r="3.4" fill="{p['node']}" stroke="{accent2}" stroke-width="1.5"/>
  <rect x="20" y="18" width="4" height="134" rx="2" fill="url(#edge)"/>
  <text x="40" y="28" fill="{p['muted']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="10.5" font-weight="700" letter-spacing="1.15">ROTATING SYSTEM · {slot:02d}</text>
  <g fill="none" stroke="{accent}" stroke-width="2"><path d="M46 46l8 8-8 8-8-8z"/><path d="M46 50l4 4-4 4-4-4z"/></g>
  <text x="62" y="62" fill="{accent}" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="{title_size}" font-weight="800">{title}</text>
  <text x="40" y="87" fill="{p['ink']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="10.5" font-weight="700">{domain}</text>
  <text x="40" y="110" fill="{p['muted']}" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="12.3" font-weight="550">{signature}</text>
  {first}{second}
  <text x="596" y="164" text-anchor="end" fill="{p['muted']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="8.6">repo · {repo}</text>
</svg>\n'''

def main() -> int:
    args = parse_args()
    day = utc_date(args.date)
    selected = select_systems(day)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    token = os.environ.get("GITHUB_TOKEN")
    manifest = {"version":VERSION,"selection_date_utc":day.isoformat(),"selection_policy":"deterministic-daily-sha256-sample","status_scope":"latest named workflow run on main","slots":[]}
    for slot, system in enumerate(selected, start=1):
        statuses = {label: workflow_signal(system["repo"], workflow, token, args.offline) for label, workflow in WORKFLOWS}
        for theme in ("light", "dark"):
            (args.output_dir / f"spotlight-{slot}-{theme}.svg").write_text(render_card(system, slot, day, statuses, theme), encoding="utf-8")
        manifest["slots"].append({"slot":slot,"repository":f"{OWNER}/{system['repo']}","title":system["title"],"statuses":statuses})
    (args.output_dir / "spotlight-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
