#!/usr/bin/env python3
"""Add self-contained vector glyphs beside secondary Signal Field metric values.

The glyphs are decorative, aria-hidden inline SVG vectors. They inherit each metric's
existing phosphorescent color and are positioned from the live numeric value so the
icon remains immediately left of the value as digit counts change.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

VERSION = "signal-field-v2.11"
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)
METRICS = ("stars", "pull_requests", "issues")
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')


def attrs_of(tag: str) -> dict[str, str]:
    return dict(ATTR.findall(tag))


def metric_pattern(metric: str) -> re.Pattern[str]:
    return re.compile(
        rf'(?P<tag><text\b(?=[^>]*\bdata-metric-phosphor="{re.escape(metric)}")[^>]*>)'
        r'(?P<value>[\d,]+)</text>',
        re.I,
    )


def approximate_width(value: str, font_size: float) -> float:
    digits = sum(char.isdigit() for char in value)
    commas = value.count(",")
    return digits * font_size * 0.59 + commas * font_size * 0.28


def glyph_markup(metric: str, color: str, cx: float, cy: float, size: float) -> str:
    scale = size / 12.0
    common = (
        f'<g data-metric-glyph="{metric}" data-glyph-rendering="inline-vector" '
        f'aria-hidden="true" pointer-events="none" '
        f'transform="translate({cx:.2f} {cy:.2f}) scale({scale:.4f})">'
    )
    if metric == "stars":
        shape = (
            f'<path data-glyph-vector="star" d="M0 -6 L1.8 -1.9 L6 -1.9 L2.6 0.8 '
            f'L3.9 5 L0 2.5 L-3.9 5 L-2.6 0.8 L-6 -1.9 L-1.8 -1.9 Z" fill="{color}"/>'
        )
    elif metric == "pull_requests":
        shape = (
            f'<g data-glyph-vector="pull-request" fill="{color}" stroke="{color}" stroke-linecap="round">'
            '<circle cx="-4" cy="-4" r="1.7" stroke="none"/>'
            '<circle cx="-4" cy="4" r="1.7" stroke="none"/>'
            '<circle cx="4" cy="-4" r="1.7" stroke="none"/>'
            '<path d="M-4 -2.2V2.2 M-2.3 4H0.4C2.4 4 4 2.4 4 0.4V-2.2" '
            'fill="none" stroke-width="1.35"/>'
            '</g>'
        )
    elif metric == "issues":
        shape = (
            f'<g data-glyph-vector="bug" fill="none" stroke="{color}" stroke-width="1.25" '
            'stroke-linecap="round" stroke-linejoin="round">'
            '<rect x="-3.4" y="-2.2" width="6.8" height="7" rx="2.4"/>'
            '<path d="M-2.1 -2.7C-1.6 -4 1.6 -4 2.1 -2.7 M-5 -0.2H-3.4 M3.4 -0.2H5 '
            'M-5 2.2H-3.4 M3.4 2.2H5 M-4.6 4.8L-3.1 3.7 M4.6 4.8L3.1 3.7"/>'
            '</g>'
        )
    else:
        raise ValueError(f"unsupported metric glyph: {metric}")
    return common + shape + "</g>"


def layout_of(root_tag: str) -> str:
    view_box = attrs_of(root_tag).get("viewBox")
    if view_box == "0 0 640 425":
        return "wide"
    if view_box == "0 0 320 500":
        return "compact"
    raise ValueError(f"unexpected Signal Field viewBox: {view_box!r}")


def add_glyphs(text: str) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing")
    root_tag = root.group(0)
    layout = layout_of(root_tag)

    existing = sum(text.count(f'data-metric-glyph="{metric}"') for metric in METRICS)
    if f'data-metric-glyphs="{VERSION}"' in root_tag:
        if existing != len(METRICS):
            raise ValueError("metric-glyph provenance exists without the complete glyph set")
        return text
    if existing:
        raise ValueError("unexpected pre-existing metric glyph markup")

    for metric in METRICS:
        pattern = metric_pattern(metric)
        matches = list(pattern.finditer(text))
        if len(matches) != 1:
            raise ValueError(f"expected exactly one metric value for {metric}, found {len(matches)}")
        match = matches[0]
        attrs = attrs_of(match.group("tag"))
        try:
            x = float(attrs["x"])
            y = float(attrs["y"])
            font_size = float(attrs["font-size"])
        except (KeyError, ValueError) as exc:
            raise ValueError(f"{metric} metric geometry signature changed") from exc
        color = attrs.get("fill")
        if not color or not re.fullmatch(r"#[0-9A-Fa-f]{6}", color):
            raise ValueError(f"{metric} metric phosphor color is missing")

        value = match.group("value")
        width = approximate_width(value, font_size)
        anchor = attrs.get("text-anchor", "start")
        if anchor == "start":
            left = x
        elif anchor == "middle":
            left = x - width / 2.0
        elif anchor == "end":
            left = x - width
        else:
            raise ValueError(f"unsupported text-anchor for {metric}: {anchor!r}")

        size = 11.5 if layout == "wide" else 9.75
        gap = 4.0 if layout == "wide" else 3.0
        cx = left - gap - size / 2.0
        cy = y - font_size * 0.35
        glyph = glyph_markup(metric, color, cx, cy, size)
        text = text[: match.start()] + glyph + text[match.start() :]

    root = SVG_OPEN.search(text)
    assert root is not None
    if "data-metric-glyphs=" in root.group(0):
        raise ValueError("unexpected pre-existing metric-glyph provenance")
    replacement = root.group(0)[:-1] + f' data-metric-glyphs="{VERSION}">'
    text = text[: root.start()] + replacement + text[root.end() :]

    if text.count(f'data-metric-glyphs="{VERSION}"') != 1:
        raise ValueError("metric-glyph provenance is missing or duplicated")
    for metric in METRICS:
        if text.count(f'data-metric-glyph="{metric}"') != 1:
            raise ValueError(f"metric glyph is missing or duplicated for {metric}")
    return text


def self_test() -> None:
    fixtures = {
        "wide": (
            '<svg viewBox="0 0 640 425" data-metric-labels="signal-field-v2.10">'
            '<text x="284" y="108" fill="#C96BFF" font-size="26" data-metric-phosphor="stars">14</text>'
            '<text x="390" y="108" fill="#8C7CFF" font-size="26" data-metric-phosphor="pull_requests">475</text>'
            '<text x="610" y="108" text-anchor="end" fill="#28D7FF" font-size="26" data-metric-phosphor="issues">33</text>'
            '<text>BUGS FOUND</text></svg>'
        ),
        "compact": (
            '<svg viewBox="0 0 320 500" data-metric-labels="signal-field-v2.10">'
            '<text x="66" y="206" text-anchor="middle" fill="#C96BFF" font-size="22" data-metric-phosphor="stars">14</text>'
            '<text x="160" y="206" text-anchor="middle" fill="#8C7CFF" font-size="22" data-metric-phosphor="pull_requests">475</text>'
            '<text x="254" y="206" text-anchor="middle" fill="#28D7FF" font-size="22" data-metric-phosphor="issues">33</text>'
            '<text>BUGS FOUND</text></svg>'
        ),
    }
    for layout, fixture in fixtures.items():
        transformed = add_glyphs(fixture)
        assert f'data-metric-glyphs="{VERSION}"' in transformed
        assert transformed.count('data-glyph-rendering="inline-vector"') == 3
        assert 'data-glyph-vector="star"' in transformed
        assert 'data-glyph-vector="pull-request"' in transformed
        assert 'data-glyph-vector="bug"' in transformed
        assert 'aria-hidden="true"' in transformed
        assert ">BUGS FOUND</text>" in transformed
        assert add_glyphs(transformed) == transformed
        print(f"{layout} metric glyph fixture passed")

    broken = fixtures["wide"].replace('data-metric-phosphor="stars"', 'data-metric-phosphor="missing"')
    try:
        add_glyphs(broken)
    except ValueError:
        pass
    else:
        raise AssertionError("missing metric value must fail closed")

    print(f"Signal Field metric-glyph self-test passed: {VERSION}")


def apply(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        transformed = add_glyphs(path.read_text(encoding="utf-8"))
        path.write_text(transformed, encoding="utf-8")
        print(f"added vector metric glyphs to {filename}: stars, pull requests, bugs found")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError("usage: glyphs-signal-field-metrics.py <generated-directory> | --self-test")
        apply(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
