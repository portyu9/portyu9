#!/usr/bin/env python3
"""Inject the Signal Field v2.3 evidence-topology background.

The background is an inline, deterministic SVG composition inspired by the visual depth
of the profile hero while deliberately using a different language: sparse topology arcs,
circuit traces, micro-nodes, scan-grid geometry, and asymmetric neon field glows.

It runs after v2.2 so the data/semantics layer remains independent from decoration.
Unexpected upstream structure fails closed instead of publishing a partially styled card.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

BACKGROUND_ID = "signal-field-v2.3"
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)

SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
BASE_RECT = re.compile(r'<rect width="(\d+)" height="(\d+)" fill="([^"]+)"/>', re.I)

THEME = {
    "dark": {
        "pink": "#FF2BD6",
        "purple": "#A020F0",
        "violet": "#7A5CFF",
        "cyan": "#00AEEF",
        "grid": "#59657A",
        "line_opacity": "0.105",
        "grid_opacity": "0.075",
        "glow_opacity": "0.125",
        "node_opacity": "0.19",
    },
    "light": {
        "pink": "#D91BB7",
        "purple": "#7C17C8",
        "violet": "#6548D8",
        "cyan": "#008BC0",
        "grid": "#9AA5B8",
        "line_opacity": "0.070",
        "grid_opacity": "0.050",
        "glow_opacity": "0.085",
        "node_opacity": "0.13",
    },
}


def attrs_of(element: str) -> dict[str, str]:
    return dict(ATTR.findall(element))


def scheme_for(filename: str) -> str:
    if filename.endswith("-dark.svg"):
        return "dark"
    if filename.endswith("-light.svg"):
        return "light"
    raise ValueError(f"unsupported Signal Field filename: {filename}")


def layout_for(filename: str) -> str:
    if "-compact-" in filename:
        return "compact"
    if "-wide-" in filename:
        return "wide"
    raise ValueError(f"unsupported Signal Field layout: {filename}")


def add_root_provenance(text: str) -> str:
    match = SVG_OPEN.search(text)
    if not match:
        raise ValueError("SVG root element is missing")
    root = match.group(0)
    attrs = attrs_of(root)
    if attrs.get("data-enhancement") != "signal-field-v2.2":
        raise ValueError("Signal Field v2.2 evidence provenance is missing")
    if "data-background" in attrs:
        raise ValueError("Signal Field unexpectedly already contains background provenance")
    replacement = root[:-1] + f' data-background="{BACKGROUND_ID}">'
    return text[:match.start()] + replacement + text[match.end():]


def defs(layout: str, scheme: str) -> str:
    t = THEME[scheme]
    prefix = f"sf-{layout}-{scheme}"
    return (
        "<defs>"
        f'<linearGradient id="{prefix}-trace" x1="0" y1="0" x2="1" y2="1">'
        f'<stop offset="0" stop-color="{t["pink"]}"/>'
        f'<stop offset="0.48" stop-color="{t["violet"]}"/>'
        f'<stop offset="1" stop-color="{t["cyan"]}"/>'
        "</linearGradient>"
        f'<radialGradient id="{prefix}-glow-a" cx="0.08" cy="0.12" r="0.68">'
        f'<stop offset="0" stop-color="{t["pink"]}" stop-opacity="0.55"/>'
        f'<stop offset="0.46" stop-color="{t["purple"]}" stop-opacity="0.18"/>'
        f'<stop offset="1" stop-color="{t["purple"]}" stop-opacity="0"/>'
        "</radialGradient>"
        f'<radialGradient id="{prefix}-glow-b" cx="0.88" cy="0.78" r="0.74">'
        f'<stop offset="0" stop-color="{t["cyan"]}" stop-opacity="0.48"/>'
        f'<stop offset="0.50" stop-color="{t["violet"]}" stop-opacity="0.14"/>'
        f'<stop offset="1" stop-color="{t["violet"]}" stop-opacity="0"/>'
        "</radialGradient>"
        f'<pattern id="{prefix}-microgrid" width="24" height="24" patternUnits="userSpaceOnUse">'
        f'<path d="M24 0H0V24" fill="none" stroke="{t["grid"]}" stroke-width="0.65" opacity="{t["grid_opacity"]}"/>'
        "</pattern>"
        "</defs>"
    )


def node(x: float, y: float, color: str, opacity: str, radius: float = 2.2) -> str:
    return (
        f'<circle cx="{x:g}" cy="{y:g}" r="{radius:g}" fill="{color}" opacity="{opacity}"/>'
        f'<circle cx="{x:g}" cy="{y:g}" r="{radius + 4:g}" fill="none" stroke="{color}" '
        f'stroke-width="0.7" opacity="0.055"/>'
    )


def topology_group(width: int, height: int, layout: str, scheme: str) -> str:
    t = THEME[scheme]
    prefix = f"sf-{layout}-{scheme}"
    line = t["line_opacity"]
    glow = t["glow_opacity"]
    node_opacity = t["node_opacity"]

    # Normalized anchor points keep the composition coherent across compact and wide cards.
    x1, y1 = width * 0.05, height * 0.14
    x2, y2 = width * 0.95, height * 0.25
    x3, y3 = width * 0.88, height * 0.78
    x4, y4 = width * 0.12, height * 0.86

    if layout == "compact":
        arc1 = f"M{-0.12*width:g},{0.30*height:g} C{0.16*width:g},{0.12*height:g} {0.34*width:g},{0.12*height:g} {0.52*width:g},{0.25*height:g}"
        arc2 = f"M{0.54*width:g},{0.86*height:g} C{0.72*width:g},{0.70*height:g} {0.92*width:g},{0.74*height:g} {1.10*width:g},{0.57*height:g}"
        trace1 = f"M{0.03*width:g},{0.67*height:g} H{0.17*width:g} L{0.23*width:g},{0.61*height:g} H{0.35*width:g}"
        trace2 = f"M{0.68*width:g},{0.19*height:g} H{0.79*width:g} L{0.84*width:g},{0.24*height:g} H{0.98*width:g}"
        nodes = ((x1, y1, t["pink"]), (x2, y2, t["violet"]), (x3, y3, t["cyan"]), (x4, y4, t["purple"]))
    else:
        arc1 = f"M{-0.08*width:g},{0.34*height:g} C{0.18*width:g},{0.10*height:g} {0.38*width:g},{0.13*height:g} {0.58*width:g},{0.29*height:g}"
        arc2 = f"M{0.42*width:g},{0.90*height:g} C{0.66*width:g},{0.64*height:g} {0.88*width:g},{0.72*height:g} {1.08*width:g},{0.51*height:g}"
        trace1 = f"M{0.02*width:g},{0.73*height:g} H{0.15*width:g} L{0.20*width:g},{0.66*height:g} H{0.34*width:g} L{0.39*width:g},{0.61*height:g}"
        trace2 = f"M{0.66*width:g},{0.16*height:g} H{0.76*width:g} L{0.80*width:g},{0.22*height:g} H{0.91*width:g} L{0.95*width:g},{0.18*height:g}"
        nodes = (
            (x1, y1, t["pink"]), (width*0.22, height*0.20, t["violet"]),
            (x2, y2, t["purple"]), (x3, y3, t["cyan"]),
            (width*0.66, height*0.83, t["violet"]), (x4, y4, t["pink"]),
        )

    node_markup = "".join(node(x, y, color, node_opacity) for x, y, color in nodes)
    return (
        f'<g data-background-layer="evidence-topology" pointer-events="none">'
        f'<rect width="{width}" height="{height}" fill="url(#{prefix}-microgrid)" opacity="0.80"/>'
        f'<ellipse cx="{0.05*width:g}" cy="{0.14*height:g}" rx="{0.42*width:g}" ry="{0.34*height:g}" '
        f'fill="url(#{prefix}-glow-a)" opacity="{glow}"/>'
        f'<ellipse cx="{0.92*width:g}" cy="{0.78*height:g}" rx="{0.46*width:g}" ry="{0.40*height:g}" '
        f'fill="url(#{prefix}-glow-b)" opacity="{glow}"/>'
        f'<path d="{arc1}" fill="none" stroke="url(#{prefix}-trace)" stroke-width="1.2" opacity="{line}"/>'
        f'<path d="{arc2}" fill="none" stroke="url(#{prefix}-trace)" stroke-width="1.0" opacity="{line}"/>'
        f'<path d="{trace1}" fill="none" stroke="{t["cyan"]}" stroke-width="0.9" opacity="{line}"/>'
        f'<path d="{trace2}" fill="none" stroke="{t["pink"]}" stroke-width="0.9" opacity="{line}"/>'
        f'<path d="M{0.10*width:g},{0.46*height:g} C{0.26*width:g},{0.38*height:g} {0.40*width:g},{0.51*height:g} {0.54*width:g},{0.44*height:g} '
        f'S{0.79*width:g},{0.36*height:g} {0.92*width:g},{0.47*height:g}" fill="none" stroke="{t["violet"]}" '
        f'stroke-width="0.7" stroke-dasharray="3 7" opacity="{float(line)*0.75:.4f}"/>'
        f'{node_markup}'
        f'</g>'
    )


def inject_background(text: str, layout: str, scheme: str) -> str:
    base = BASE_RECT.search(text)
    if not base:
        raise ValueError("Signal Field base surface rectangle is missing")
    width, height = int(base.group(1)), int(base.group(2))
    if layout == "compact" and width != 320:
        raise ValueError(f"unexpected compact SVG width: {width}")
    if layout == "wide" and width != 640:
        raise ValueError(f"unexpected wide SVG width: {width}")
    if height not in (425, 500, 528):
        raise ValueError(f"unexpected Signal Field height: {height}")

    insertion = defs(layout, scheme) + topology_group(width, height, layout, scheme)
    return text[:base.end()] + insertion + text[base.end():]


def validate(text: str, layout: str, scheme: str) -> None:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root element is missing after background injection")
    attrs = attrs_of(root.group(0))
    if attrs.get("data-background") != BACKGROUND_ID:
        raise ValueError("background provenance is missing")
    if text.count('data-background-layer="evidence-topology"') != 1:
        raise ValueError("expected exactly one evidence-topology background layer")
    if text.count("<defs>") != 1:
        raise ValueError("background defs count is invalid")
    prefix = f"sf-{layout}-{scheme}"
    for marker in (f'{prefix}-trace', f'{prefix}-glow-a', f'{prefix}-glow-b', f'{prefix}-microgrid'):
        if marker not in text:
            raise ValueError(f"background definition missing: {marker}")
    if 'pointer-events="none"' not in text:
        raise ValueError("background must never become interactive")


def enhance_svg(text: str, layout: str, scheme: str) -> str:
    enhanced = add_root_provenance(text)
    enhanced = inject_background(enhanced, layout, scheme)
    validate(enhanced, layout, scheme)
    return enhanced


def enhance_directory(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        layout = layout_for(filename)
        scheme = scheme_for(filename)
        enhanced = enhance_svg(path.read_text(encoding="utf-8"), layout, scheme)
        path.write_text(enhanced, encoding="utf-8")
        print(f"background {filename} -> {BACKGROUND_ID}")


def fixture(layout: str, scheme: str) -> str:
    width = 320 if layout == "compact" else 640
    height = 500 if layout == "compact" else 425
    base = "#0B1020" if scheme == "dark" else "#F8FAFF"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'data-enhancement="signal-field-v2.2"><rect width="{width}" height="{height}" fill="{base}"/>'
        f'<text x="20" y="30">fixture</text></svg>'
    )


def self_test() -> None:
    for layout in ("wide", "compact"):
        for scheme in ("light", "dark"):
            enhanced = enhance_svg(fixture(layout, scheme), layout, scheme)
            assert f'data-background="{BACKGROUND_ID}"' in enhanced
            assert enhanced.count('data-background-layer="evidence-topology"') == 1
            assert 'pointer-events="none"' in enhanced
    print(f"Signal Field background self-test passed: {BACKGROUND_ID}")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError("usage: background-signal-field-v2.py <generated-directory> | --self-test")
        enhance_directory(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
