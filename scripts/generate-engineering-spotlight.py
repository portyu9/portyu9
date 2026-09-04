#!/usr/bin/env python3
"""Generate two deterministic daily engineering Evidence Spotlight cards.

Selection changes once per UTC date. Workflow conclusions are refreshed whenever the
profile-stats workflow runs, so selection remains stable during the day while evidence
signals can change without rewriting README.md.
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

OWNER = "portyu9"
VERSION = "engineering-spotlight-v1"
POOL = (
    {"repo":"qa-automation-dotnet-selenium","title":".NET + SELENIUM QE","domain":"WEB / UI · SELENIUM + XUNIT","signature":"Explicit browser lifecycle · owned fixture · bounded failure evidence","accent":"#43B02A"},
    {"repo":"qa-automation-api-postman-newman","title":"POSTMAN + NEWMAN API QE","domain":"API · POSTMAN + NEWMAN","signature":"Collection semantics · deterministic target ownership · execution ledger","accent":"#FF6C37"},
    {"repo":"qa-automation-mobile-appium","title":"APPIUM MOBILE QE","domain":"MOBILE · APPIUM + WEBDRIVERIO","signature":"Capability policy · session lifecycle · device-evidence boundaries","accent":"#8A5CF6"},
    {"repo":"qa-automation-ui-cypress","title":"CYPRESS UI QE","domain":"WEB / UI · CYPRESS","signature":"Native retryability · test isolation · deterministic target ownership","accent":"#00BFA6"},
    {"repo":"qa-automation-python-pytest","title":"PYTHON + PYTEST QE","domain":"LAYERED QE · PYTEST","signature":"Failure attribution · persistence + browser + security boundaries","accent":"#0A9EDC"},
    {"repo":"qa-automation-node-supertest","title":"SUPERTEST API QE","domain":"API / CONTRACT · SUPERTEST + PACT","signature":"Component · transport · contract · listener boundaries","accent":"#00A6C7"},
    {"repo":"qa-automation-java-restassured","title":"REST ASSURED QE","domain":"API / PERSISTENCE · REST ASSURED","signature":"Protocol · schema · PostgreSQL · attributable evidence","accent":"#ED8B00"},
    {"repo":"qa-automation-node-playwright","title":"PLAYWRIGHT QE","domain":"E2E / BROWSER · PLAYWRIGHT","signature":"Native runner · context isolation · traceable browser evidence","accent":"#2EAD33"},
    {"repo":"qa-automation-load-k6","title":"K6 PERFORMANCE QE","domain":"PERFORMANCE · K6","signature":"Explicit workloads · target authorization · zero-traffic safety","accent":"#7D64FF"},
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
    return ({"surface":"#0D1117","stroke":"#30363D","ink":"#F0F6FC","muted":"#8B949E"}
            if theme == "dark" else
            {"surface":"#FFFFFF","stroke":"#D0D7DE","ink":"#1F2328","muted":"#57606A"})


def status_style(signal: str) -> tuple[str, str]:
    if signal == "PASSING": return "#1A7F37", "#FFFFFF"
    if signal == "FAILING": return "#CF222E", "#FFFFFF"
    if signal == "RUNNING": return "#9A6700", "#FFFFFF"
    return "#57606A", "#FFFFFF"


def fit_font(text: str, default: int = 24) -> int:
    if len(text) > 23: return default - 3
    if len(text) > 19: return default - 1
    return default


def render_card(system: dict[str, str], slot: int, day: dt.date, statuses: dict[str, str], theme: str) -> str:
    p = palette(theme)
    accent = system["accent"]
    title = html.escape(system["title"])
    domain = html.escape(system["domain"])
    signature = html.escape(system["signature"])
    repo = html.escape(system["repo"])
    pills = []
    x = 40
    for label, _workflow in WORKFLOWS:
        signal = statuses[label]
        fill, text = status_style(signal)
        width = max(96, 58 + len(signal) * 7)
        pills.append(f'<rect x="{x}" y="116" width="{width}" height="24" rx="7" fill="{fill}"/><text x="{x + width/2:.1f}" y="132" text-anchor="middle" fill="{text}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="10" font-weight="800">{label} · {html.escape(signal)}</text>')
        x += width + 10
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="620" height="150" viewBox="0 0 620 150" role="img" aria-labelledby="title desc" data-spotlight="{VERSION}" data-slot="{slot}" data-date="{day.isoformat()}" data-repository="{OWNER}/{repo}">
  <title id="title">{title}</title>
  <desc id="desc">Daily deterministic Evidence Spotlight for {OWNER}/{repo}. {signature}. Workflow signals are scoped to the named main-branch workflows.</desc>
  <rect x="1" y="1" width="618" height="148" rx="15" fill="{p['surface']}" stroke="{p['stroke']}"/>
  <rect x="20" y="18" width="4" height="114" rx="2" fill="{accent}"/>
  <path d="M486 18h44l16 16h42" fill="none" stroke="{accent}" stroke-opacity=".14" stroke-linecap="round"/>
  <path d="M500 136h36l16-18h54" fill="none" stroke="{accent}" stroke-opacity=".10" stroke-linecap="round"/>
  <circle cx="546" cy="34" r="3.4" fill="{p['surface']}" stroke="{accent}" stroke-width="1.5"/>
  <circle cx="552" cy="118" r="3.4" fill="{p['surface']}" stroke="{accent}" stroke-width="1.5"/>
  <text x="40" y="27" fill="{p['muted']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="10.5" font-weight="700" letter-spacing="1.15">DAILY EVIDENCE SPOTLIGHT · {slot:02d}</text>
  <text x="40" y="58" fill="{accent}" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="{fit_font(system['title'])}" font-weight="800">{title}</text>
  <text x="40" y="82" fill="{p['ink']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="10.5" font-weight="700">{domain}</text>
  <text x="40" y="102" fill="{p['muted']}" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="12.5" font-weight="550">{signature}</text>
  {''.join(pills)}
  <text x="596" y="136" text-anchor="end" fill="{p['muted']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="8.8">{repo}</text>
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
