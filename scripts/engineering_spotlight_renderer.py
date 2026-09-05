#!/usr/bin/env python3
"""Pure, network-free Engineering Spotlight SVG renderer."""
from __future__ import annotations

import datetime as dt
import hashlib
import html
from typing import Any


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
    if glyph not in glyphs:
        raise ValueError(f"unsupported Spotlight glyph: {glyph}")
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


def render_card(
    system: dict[str, Any],
    slot: int,
    day: dt.date,
    subject: str,
    evidence: list[dict[str, Any]],
    theme: str,
    *,
    version: str,
    owner: str,
) -> str:
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
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="620" height="198" viewBox="0 0 620 198" role="img" aria-labelledby="title desc" data-spotlight="{version}" data-layout="evidence-v2" data-slot="{slot}" data-date="{day.isoformat()}" data-repository="{owner}/{repo}" data-subject-revision="{subject}" data-evidence-age-days="{max_age}" data-evidence-runs="{html.escape(run_attr)}" data-evidence-workflows="{html.escape(workflow_attr)}" data-glyph="{system["glyph"]}" data-topology="{system["topology"]}">
  <title id="title">{title}</title>
  <desc id="desc">Daily deterministic Evidence Spotlight for {owner}/{repo} at main revision {subject}. {signature}. {html.escape(evidence_desc)}. Freshness is UTC whole-day age from the named workflow evidence timestamp.</desc>
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
