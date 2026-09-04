#!/usr/bin/env python3
"""Generate two deterministic daily engineering Evidence Spotlight cards.

Selection changes once per UTC date. Workflow conclusions are refreshed whenever the
profile-stats workflow runs, so selection remains stable during the day while evidence
signals can change without rewriting README.md.

Each portfolio system owns a stable glyph and topology motif. The two visible cards
therefore rotate by repository while retaining distinct authored visual identities.
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
    {"repo":"qa-automation-dotnet-selenium","title":".NET + SELENIUM QE","domain":"WEB / UI · SELENIUM + XUNIT","signature":"Browser lifecycle · owned fixtures · bounded evidence","accent":"#43B02A","accent2":"#28D7FF","accent3":"#8C7CFF","glyph":"browser-frame","topology":"session-rails"},
    {"repo":"qa-automation-api-postman-newman","title":"POSTMAN + NEWMAN API QE","domain":"API · POSTMAN + NEWMAN","signature":"Collection contracts · target ownership · execution evidence","accent":"#FF6C37","accent2":"#FF2BD6","accent3":"#28D7FF","glyph":"request-arrow","topology":"request-route"},
    {"repo":"qa-automation-mobile-appium","title":"APPIUM MOBILE QE","domain":"MOBILE · APPIUM + WEBDRIVERIO","signature":"Capability policy · session lifecycle · device evidence","accent":"#8A5CF6","accent2":"#FF2BD6","accent3":"#28D7FF","glyph":"device-frame","topology":"device-bus"},
    {"repo":"qa-automation-ui-cypress","title":"CYPRESS UI QE","domain":"WEB / UI · CYPRESS","signature":"Retryability · isolation · deterministic target ownership","accent":"#00BFA6","accent2":"#28D7FF","accent3":"#8C7CFF","glyph":"retry-loop","topology":"retry-circuit"},
    {"repo":"qa-automation-python-pytest","title":"PYTHON + PYTEST QE","domain":"LAYERED QE · PYTEST","signature":"Failure attribution · persistence · browser · security","accent":"#0A9EDC","accent2":"#28D7FF","accent3":"#8C7CFF","glyph":"bracket-check","topology":"layered-ladder"},
    {"repo":"qa-automation-node-supertest","title":"SUPERTEST API QE","domain":"API / CONTRACT · SUPERTEST + PACT","signature":"Component · transport · contract · listener boundaries","accent":"#00A6C7","accent2":"#28D7FF","accent3":"#FF2BD6","glyph":"endpoint-link","topology":"contract-bridge"},
    {"repo":"qa-automation-java-restassured","title":"REST ASSURED QE","domain":"API / PERSISTENCE · REST ASSURED","signature":"Protocol · schema · PostgreSQL · attributable evidence","accent":"#ED8B00","accent2":"#FF6C37","accent3":"#8C7CFF","glyph":"shield-route","topology":"protocol-chain"},
    {"repo":"qa-automation-node-playwright","title":"PLAYWRIGHT QE","domain":"E2E / BROWSER · PLAYWRIGHT","signature":"Context isolation · traces · attributable browser evidence","accent":"#2EAD33","accent2":"#28D7FF","accent3":"#8C7CFF","glyph":"trace-frame","topology":"trace-fan"},
    {"repo":"qa-automation-load-k6","title":"K6 PERFORMANCE QE","domain":"PERFORMANCE · K6","signature":"Explicit workloads · target authorization · zero-traffic safety","accent":"#7D64FF","accent2":"#FF2BD6","accent3":"#28D7FF","glyph":"gauge-needle","topology":"load-wave"},
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
        f'<rect x="{x:.1f}" y="131" width="{width:.1f}" height="28" rx="8" fill="{p["chip"]}" stroke="{border}" stroke-opacity=".72" stroke-width="1.15"/>'
        f'<circle cx="{x+15:.1f}" cy="{cy}" r="4.0" fill="{border}"/>'
        f'<text x="{x+27:.1f}" y="149" fill="{p["chiptext"]}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="{text_size}" font-weight="800">{html.escape(rendered)}</text>'
    )
    return markup, width

def glyph_markup(glyph: str, accent: str) -> str:
    common=f'fill="none" stroke="{accent}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"'
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
    }
    return glyphs[glyph]

def topology_markup(name: str, node: str, a: str, b: str, c: str) -> str:
    styles = {
        "session-rails": (f'<path d="M468 22h34l16 16h28l16-12h42" fill="none" stroke="{b}" stroke-opacity=".12" stroke-linecap="round"/><path d="M478 154h38l16-18h34l16 16h24" fill="none" stroke="{a}" stroke-opacity=".10" stroke-linecap="round"/><path d="M536 38v28l18 16v30" fill="none" stroke="{c}" stroke-opacity=".09"/>',[(518,38,b),(562,26,c),(532,136,a),(582,152,b)]),
        "request-route": (f'<path d="M456 28h52l16 16h26l18 18h38" fill="none" stroke="{a}" stroke-opacity=".12"/><path d="M482 148h28l18-20h42l18-18h18" fill="none" stroke="{b}" stroke-opacity=".11"/><path d="M544 44l22 22-12 22 18 20" fill="none" stroke="{c}" stroke-opacity=".08"/>',[(508,28,a),(550,44,b),(528,128,c),(588,110,a)]),
        "device-bus": (f'<path d="M490 20v28l16 14v42l-16 16v30" fill="none" stroke="{a}" stroke-opacity=".11"/><path d="M490 62h36l14-14h42l14 14h10" fill="none" stroke="{b}" stroke-opacity=".12"/><path d="M506 104h38l18 20h44" fill="none" stroke="{c}" stroke-opacity=".10"/>',[(490,48,a),(540,48,b),(506,104,c),(562,124,a)]),
        "retry-circuit": (f'<path d="M474 34h52c26 0 34 34 10 46-18 9-18 31 0 40 21 10 18 36-6 36h-54" fill="none" stroke="{a}" stroke-opacity=".10"/><path d="M526 34h36l16 16h28" fill="none" stroke="{b}" stroke-opacity=".12"/><path d="M530 156h34l16-16h26" fill="none" stroke="{c}" stroke-opacity=".11"/>',[(526,34,b),(578,50,c),(530,120,a),(580,140,b)]),
        "layered-ladder": (f'<path d="M470 26h54l14 14h54" fill="none" stroke="{b}" stroke-opacity=".12"/><path d="M486 70h42l16 14h62" fill="none" stroke="{a}" stroke-opacity=".09"/><path d="M476 126h48l16-14h42l16 14" fill="none" stroke="{c}" stroke-opacity=".10"/><path d="M508 40v30M528 84v28M540 112v28" fill="none" stroke="{b}" stroke-opacity=".07"/>',[(524,26,b),(544,84,a),(524,126,c),(598,126,b)]),
        "contract-bridge": (f'<path d="M458 44h42l18 18h26l18-18h44" fill="none" stroke="{a}" stroke-opacity=".12"/><path d="M470 140h36l20-18h30l18 18h32" fill="none" stroke="{c}" stroke-opacity=".11"/><path d="M518 62v60M562 44v96" fill="none" stroke="{b}" stroke-opacity=".07"/>',[(500,44,a),(544,62,b),(526,122,c),(574,140,a)]),
        "protocol-chain": (f'<path d="M458 30h30l14 14h28l14 14h28l14 14h10" fill="none" stroke="{a}" stroke-opacity=".12"/><path d="M474 146h30l14-14h30l14-14h44" fill="none" stroke="{b}" stroke-opacity=".11"/><path d="M530 58c12 12 12 28 0 40s-12 28 0 40" fill="none" stroke="{c}" stroke-opacity=".08"/>',[(502,44,a),(544,58,b),(518,132,c),(586,72,a)]),
        "trace-fan": (f'<path d="M470 86h38l24-52h38l20-14" fill="none" stroke="{a}" stroke-opacity=".11"/><path d="M508 86h48l30-30h20" fill="none" stroke="{b}" stroke-opacity=".12"/><path d="M508 86h44l32 42h22" fill="none" stroke="{c}" stroke-opacity=".10"/><path d="M508 86h28l18 64h40" fill="none" stroke="{a}" stroke-opacity=".08"/>',[(508,86,a),(532,34,b),(586,56,c),(584,128,a)]),
        "load-wave": (f'<path d="M458 74c18-28 36-28 54 0s36 28 54 0 28-28 40-8" fill="none" stroke="{a}" stroke-opacity=".11"/><path d="M458 116c18-22 36-22 54 0s36 22 54 0 28-22 40-8" fill="none" stroke="{b}" stroke-opacity=".10"/><path d="M500 32h44l14 14h48" fill="none" stroke="{c}" stroke-opacity=".12"/>',[(500,74,a),(548,102,b),(558,46,c),(594,108,a)]),
    }
    paths, nodes = styles[name]
    circles = ''.join(f'<circle cx="{x}" cy="{y}" r="3.4" fill="{node}" stroke="{color}" stroke-width="1.5"/>' for x,y,color in nodes)
    return paths + circles

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
    glyph = glyph_markup(system["glyph"], accent)
    topology = topology_markup(system["topology"], p["node"], accent, accent2, accent3)
    return f'''<svg xmlns="http://www.w3.org/2000/svg" width="620" height="170" viewBox="0 0 620 170" role="img" aria-labelledby="title desc" data-spotlight="{VERSION}" data-layout="rich-v2" data-slot="{slot}" data-date="{day.isoformat()}" data-repository="{OWNER}/{repo}" data-glyph="{system["glyph"]}" data-topology="{system["topology"]}">
  <title id="title">{title}</title>
  <desc id="desc">Daily deterministic Evidence Spotlight for {OWNER}/{repo}. {signature}. Workflow signals are scoped to the named main-branch workflows.</desc>
  <defs><linearGradient id="edge" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="{accent}"/><stop offset=".54" stop-color="{accent2}"/><stop offset="1" stop-color="{accent3}"/></linearGradient><linearGradient id="wash" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="{accent}" stop-opacity=".055"/><stop offset=".54" stop-color="{accent2}" stop-opacity=".026"/><stop offset="1" stop-color="{accent3}" stop-opacity=".045"/></linearGradient></defs>
  <rect x="1" y="1" width="618" height="168" rx="15" fill="{p['surface']}" stroke="{p['stroke']}"/><rect x="2" y="2" width="616" height="166" rx="14" fill="url(#wash)"/>
  {topology}
  <rect x="20" y="18" width="4" height="134" rx="2" fill="url(#edge)"/>
  <text x="40" y="28" fill="{p['muted']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="10.5" font-weight="700" letter-spacing="1.15">ROTATING SYSTEM · {slot:02d}</text>
  {glyph}
  <text x="68" y="62" fill="{accent}" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="{title_size}" font-weight="800">{title}</text>
  <text x="40" y="87" fill="{p['ink']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="10.5" font-weight="700">{domain}</text>
  <text x="40" y="110" fill="{p['muted']}" font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" font-size="12.3" font-weight="550">{signature}</text>
  {first}{second}
  <text x="590" y="161" text-anchor="end" fill="{p['muted']}" font-family="ui-monospace,SFMono-Regular,Consolas,monospace" font-size="9.2">repo · {repo}</text>
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
        manifest["slots"].append({"slot":slot,"repository":f"{OWNER}/{system['repo']}","title":system["title"],"glyph":system["glyph"],"topology":system["topology"],"statuses":statuses})
    (args.output_dir / "spotlight-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
