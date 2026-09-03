#!/usr/bin/env python3
"""Inject the Signal Field v2.4 dimensional portal layer.

This layer runs after the v2.3 evidence-topology background. It adds a faint,
self-contained vector portal with perspective ellipses, depth glows, orbital arcs,
and sparse energy particles. The portal is decorative only and deliberately stays
behind all metrics/calendar content.

Unexpected v2.3 structure fails closed rather than publishing a partial artifact.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

PORTAL_ID = "signal-field-v2.4"
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)

SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
DEFS_CLOSE = re.compile(r"</defs>", re.I)
BORDER_RECT = re.compile(
    r'<rect x="0\.5" y="0\.5" width="(\d+)" height="(\d+)" fill="none" stroke="([^"]+)"/>',
    re.I,
)

THEME = {
    "dark": {
        "pink": "#FF2BD6",
        "purple": "#A020F0",
        "violet": "#7A5CFF",
        "cyan": "#00AEEF",
        "white": "#F8FAFC",
        "core": "#10162A",
        "halo_opacity": "0.17",
        "ring_opacity": "0.24",
        "inner_opacity": "0.18",
        "particle_opacity": "0.28",
    },
    "light": {
        "pink": "#D91BB7",
        "purple": "#7C17C8",
        "violet": "#6548D8",
        "cyan": "#008BC0",
        "white": "#FFFFFF",
        "core": "#E9EEFF",
        "halo_opacity": "0.085",
        "ring_opacity": "0.14",
        "inner_opacity": "0.105",
        "particle_opacity": "0.16",
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
    if attrs.get("data-background") != "signal-field-v2.3":
        raise ValueError("Signal Field v2.3 background provenance is missing")
    if "data-portal" in attrs:
        raise ValueError("Signal Field unexpectedly already contains portal provenance")
    replacement = root[:-1] + f' data-portal="{PORTAL_ID}">'
    return text[:match.start()] + replacement + text[match.end():]


def portal_defs(layout: str, scheme: str) -> str:
    t = THEME[scheme]
    prefix = f"sfp-{layout}-{scheme}"
    blur = "7" if layout == "wide" else "5"
    return (
        f'<linearGradient id="{prefix}-ring" x1="0" y1="0" x2="1" y2="0">'
        f'<stop offset="0" stop-color="{t["pink"]}"/>'
        f'<stop offset="0.34" stop-color="{t["purple"]}"/>'
        f'<stop offset="0.68" stop-color="{t["violet"]}"/>'
        f'<stop offset="1" stop-color="{t["cyan"]}"/>'
        '</linearGradient>'
        f'<radialGradient id="{prefix}-core" cx="0.50" cy="0.48" r="0.58">'
        f'<stop offset="0" stop-color="{t["core"]}" stop-opacity="0.78"/>'
        f'<stop offset="0.38" stop-color="{t["violet"]}" stop-opacity="0.17"/>'
        f'<stop offset="0.72" stop-color="{t["purple"]}" stop-opacity="0.06"/>'
        f'<stop offset="1" stop-color="{t["cyan"]}" stop-opacity="0"/>'
        '</radialGradient>'
        f'<radialGradient id="{prefix}-halo" cx="0.50" cy="0.50" r="0.50">'
        f'<stop offset="0" stop-color="{t["white"]}" stop-opacity="0.18"/>'
        f'<stop offset="0.20" stop-color="{t["cyan"]}" stop-opacity="0.30"/>'
        f'<stop offset="0.52" stop-color="{t["violet"]}" stop-opacity="0.16"/>'
        f'<stop offset="0.78" stop-color="{t["pink"]}" stop-opacity="0.07"/>'
        f'<stop offset="1" stop-color="{t["pink"]}" stop-opacity="0"/>'
        '</radialGradient>'
        f'<filter id="{prefix}-blur" x="-55%" y="-120%" width="210%" height="340%">'
        f'<feGaussianBlur stdDeviation="{blur}"/>'
        '</filter>'
    )


def particle(x: float, y: float, radius: float, color: str, opacity: str) -> str:
    return (
        f'<circle cx="{x:g}" cy="{y:g}" r="{radius:g}" fill="{color}" opacity="{opacity}"/>'
        f'<circle cx="{x:g}" cy="{y:g}" r="{radius + 2.6:g}" fill="none" stroke="{color}" '
        f'stroke-width="0.55" opacity="0.055"/>'
    )


def portal_group(width: int, height: int, layout: str, scheme: str) -> str:
    t = THEME[scheme]
    prefix = f"sfp-{layout}-{scheme}"

    if layout == "wide":
        cx, cy = width * 0.50, height * 0.475
        rx, ry = width * 0.205, height * 0.092
        rotation = -7
        halo_rx, halo_ry = rx * 1.30, ry * 2.15
        particle_specs = (
            (cx-rx*1.04, cy-ry*0.42, 1.7, t["pink"]),
            (cx+rx*1.12, cy+ry*0.24, 1.5, t["cyan"]),
            (cx-rx*0.52, cy+ry*1.35, 1.25, t["violet"]),
            (cx+rx*0.58, cy-ry*1.24, 1.15, t["purple"]),
            (cx+rx*0.02, cy+ry*1.72, 1.0, t["cyan"]),
        )
    else:
        cx, cy = width * 0.50, height * 0.492
        rx, ry = width * 0.30, height * 0.053
        rotation = -8
        halo_rx, halo_ry = rx * 1.18, ry * 2.65
        particle_specs = (
            (cx-rx*1.03, cy-ry*0.55, 1.35, t["pink"]),
            (cx+rx*1.04, cy+ry*0.32, 1.25, t["cyan"]),
            (cx-rx*0.50, cy+ry*1.65, 1.05, t["violet"]),
            (cx+rx*0.55, cy-ry*1.58, 1.0, t["purple"]),
        )

    ring = t["ring_opacity"]
    inner = t["inner_opacity"]
    halo = t["halo_opacity"]
    particles = "".join(
        particle(x, y, radius, color, t["particle_opacity"])
        for x, y, radius, color in particle_specs
    )

    # Receding ellipses shift subtly upward, creating a tunnel rather than a flat target.
    rings = (
        (1.00, 1.00, 1.45, ring, 0.0),
        (0.84, 0.82, 1.15, f"{float(ring)*0.86:.3f}", -ry*0.10),
        (0.68, 0.66, 0.95, f"{float(inner)*0.95:.3f}", -ry*0.20),
        (0.52, 0.50, 0.78, f"{float(inner)*0.78:.3f}", -ry*0.29),
        (0.37, 0.34, 0.65, f"{float(inner)*0.62:.3f}", -ry*0.37),
    )
    ring_markup = "".join(
        f'<ellipse cx="{cx:g}" cy="{cy+dy:g}" rx="{rx*sx:g}" ry="{ry*sy:g}" '
        f'fill="none" stroke="url(#{prefix}-ring)" stroke-width="{stroke:g}" opacity="{opacity}"/>'
        for sx, sy, stroke, opacity, dy in rings
    )

    orbital = (
        f'<ellipse cx="{cx:g}" cy="{cy:g}" rx="{rx*1.12:g}" ry="{ry*1.30:g}" fill="none" '
        f'stroke="{t["cyan"]}" stroke-width="0.7" stroke-dasharray="2 7" opacity="{float(inner)*0.54:.3f}"/>'
        f'<ellipse cx="{cx:g}" cy="{cy:g}" rx="{rx*0.92:g}" ry="{ry*1.64:g}" fill="none" '
        f'stroke="{t["pink"]}" stroke-width="0.55" stroke-dasharray="1 8" opacity="{float(inner)*0.43:.3f}"/>'
    )

    return (
        f'<g data-portal-layer="dimensional-core" pointer-events="none" '
        f'transform="rotate({rotation} {cx:g} {cy:g})">'
        f'<ellipse cx="{cx:g}" cy="{cy:g}" rx="{halo_rx:g}" ry="{halo_ry:g}" '
        f'fill="url(#{prefix}-halo)" opacity="{halo}" filter="url(#{prefix}-blur)"/>'
        f'<ellipse cx="{cx:g}" cy="{cy:g}" rx="{rx*0.82:g}" ry="{ry*2.05:g}" '
        f'fill="url(#{prefix}-core)" opacity="{float(halo)*0.72:.3f}"/>'
        f'{orbital}{ring_markup}{particles}'
        f'<path d="M{cx-rx*0.98:g},{cy+ry*0.58:g} Q{cx:g},{cy+ry*1.32:g} {cx+rx*0.98:g},{cy+ry*0.58:g}" '
        f'fill="none" stroke="{t["cyan"]}" stroke-width="0.75" opacity="{float(inner)*0.52:.3f}"/>'
        f'<path d="M{cx-rx*0.82:g},{cy-ry*0.72:g} Q{cx:g},{cy-ry*1.20:g} {cx+rx*0.82:g},{cy-ry*0.72:g}" '
        f'fill="none" stroke="{t["pink"]}" stroke-width="0.65" opacity="{float(inner)*0.44:.3f}"/>'
        '</g>'
    )


def inject_portal(text: str, layout: str, scheme: str) -> str:
    defs_close = DEFS_CLOSE.search(text)
    if not defs_close:
        raise ValueError("Signal Field v2.3 defs block is missing")
    defs_markup = portal_defs(layout, scheme)
    text = text[:defs_close.start()] + defs_markup + text[defs_close.start():]

    border = BORDER_RECT.search(text)
    if not border:
        raise ValueError("Signal Field border rectangle is missing")
    root = SVG_OPEN.search(text)
    assert root is not None
    root_attrs = attrs_of(root.group(0))
    width = int(root_attrs.get("width", "0"))
    height = int(root_attrs.get("height", "0"))
    if layout == "compact" and width != 320:
        raise ValueError(f"unexpected compact SVG width: {width}")
    if layout == "wide" and width != 640:
        raise ValueError(f"unexpected wide SVG width: {width}")
    if height not in (425, 500, 528):
        raise ValueError(f"unexpected Signal Field height: {height}")

    portal = portal_group(width, height, layout, scheme)
    return text[:border.start()] + portal + text[border.start():]


def validate(text: str, layout: str, scheme: str) -> None:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root element is missing after portal injection")
    attrs = attrs_of(root.group(0))
    if attrs.get("data-portal") != PORTAL_ID:
        raise ValueError("portal provenance is missing")
    if text.count('data-portal-layer="dimensional-core"') != 1:
        raise ValueError("expected exactly one dimensional portal layer")
    if text.count('pointer-events="none"') < 2:
        raise ValueError("portal and topology layers must remain non-interactive")
    prefix = f"sfp-{layout}-{scheme}"
    for marker in (f'{prefix}-ring', f'{prefix}-core', f'{prefix}-halo', f'{prefix}-blur'):
        if marker not in text:
            raise ValueError(f"portal definition missing: {marker}")
    if text.count('filter="url(#') < 1:
        raise ValueError("portal atmospheric glow filter is missing")
    if text.count("<ellipse") < 8:
        raise ValueError("portal depth geometry is unexpectedly sparse")


def enhance_svg(text: str, layout: str, scheme: str) -> str:
    enhanced = add_root_provenance(text)
    enhanced = inject_portal(enhanced, layout, scheme)
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
        print(f"portal {filename} -> {PORTAL_ID}")


def fixture(layout: str, scheme: str) -> str:
    width = 320 if layout == "compact" else 640
    height = 500 if layout == "compact" else 425
    base = "#0B1020" if scheme == "dark" else "#F8FAFF"
    border = "#28324A" if scheme == "dark" else "#D9DFF0"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
        f'data-background="signal-field-v2.3"><rect width="{width}" height="{height}" fill="{base}"/>'
        '<defs><linearGradient id="fixture"><stop offset="0"/></linearGradient></defs>'
        '<g data-background-layer="evidence-topology" pointer-events="none"><path d="M0 0"/></g>'
        f'<rect x="0.5" y="0.5" width="{width-1}" height="{height-1}" fill="none" stroke="{border}"/>'
        '<text x="20" y="30">fixture</text></svg>'
    )


def self_test() -> None:
    for layout in ("wide", "compact"):
        for scheme in ("light", "dark"):
            enhanced = enhance_svg(fixture(layout, scheme), layout, scheme)
            assert f'data-portal="{PORTAL_ID}"' in enhanced
            assert enhanced.count('data-portal-layer="dimensional-core"') == 1
            assert 'pointer-events="none"' in enhanced
            assert f'sfp-{layout}-{scheme}-ring' in enhanced
    print(f"Signal Field portal self-test passed: {PORTAL_ID}")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError("usage: portal-signal-field-v2.py <generated-directory> | --self-test")
        enhance_directory(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
