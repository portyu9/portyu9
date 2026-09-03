#!/usr/bin/env python3
"""Deterministically polish the already-themed Signal Field v2 SVGs.

This layer intentionally runs after customize-signal-field.py. It owns presentation-only
refinements that should not be coupled to upstream data extraction:
- clearer compact LESS/MORE legend spacing
- attributable compact peak telemetry including the peak date
- brighter weekday labels
- quieter month markers
- a two-tier latest-day state with a cyan outer hairline
- tighter five-week compact-card footer geometry

The transformation fails closed when the expected v2 structure changes.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
import re
import sys

POLISH_ID = "signal-field-v2.1"
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)

THEME_TOKENS = {
    "light": {
        "primary": "#111827",
        "secondary": "#5B6475",
        "hairline": "#D9DFF0",
        "latest": "#00AEEF",
    },
    "dark": {
        "primary": "#F8FAFC",
        "secondary": "#A7B0C4",
        "hairline": "#28324A",
        "latest": "#00AEEF",
    },
}

SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
WEEKDAY_LABEL = re.compile(
    r'<text\b[^>]*\bdata-weekday-label="[0-6]"[^>]*>[^<]+</text>', re.I
)
MONTH_LABEL = re.compile(
    r'<text\b[^>]*\bdata-month-boundary="[A-Z]{3}"[^>]*>[^<]+</text>', re.I
)
LATEST_TILE = re.compile(
    r'<rect\b[^>]*\bdata-latest-day="true"[^>]*/>', re.I
)
ACTIVITY_SUMMARY = re.compile(
    r'<text\b[^>]*\bdata-activity-summary="true"[^>]*>[^<]+</text>', re.I
)
LEGEND_LESS = re.compile(r'<text x="186\.4" y="266"[^>]*>LESS</text>', re.I)
LEGEND_MORE = re.compile(r'<text x="276" y="266"[^>]*>MORE</text>', re.I)
LEGEND_RECT = re.compile(
    r'<rect x="(218|228|238|248|258)" y="259"[^>]*\bdata-legend-level="[0-4]"[^>]*/>',
    re.I,
)


def scheme_for(path: Path) -> str:
    if path.name.endswith("-light.svg"):
        return "light"
    if path.name.endswith("-dark.svg"):
        return "dark"
    raise ValueError(f"unsupported Signal Field filename: {path.name}")


def layout_for(path: Path) -> str:
    if "-wide-" in path.name:
        return "wide"
    if "-compact-" in path.name:
        return "compact"
    raise ValueError(f"unsupported Signal Field layout: {path.name}")


def attrs_of(element: str) -> dict[str, str]:
    return dict(ATTR.findall(element))


def set_attr(element: str, name: str, value: str) -> str:
    pattern = re.compile(rf'\b{re.escape(name)}="[^"]*"')
    replacement = f'{name}="{value}"'
    if pattern.search(element):
        return pattern.sub(replacement, element, count=1)
    close = "/>" if element.endswith("/>") else ">"
    index = element.rfind(close)
    if index < 0:
        raise ValueError(f"cannot add attribute {name!r} to malformed element")
    return element[:index] + f' {replacement}' + element[index:]


def text_content(element: str, value: str) -> str:
    return re.sub(r">[^<]*</text>$", f">{value}</text>", element, count=1)


def polish_weekdays(text: str, scheme: str) -> str:
    primary = THEME_TOKENS[scheme]["primary"]
    matches = WEEKDAY_LABEL.findall(text)
    if len(matches) != 7:
        raise ValueError(f"expected seven weekday labels, found {len(matches)}")

    def transform(match: re.Match[str]) -> str:
        element = set_attr(match.group(0), "fill", primary)
        element = set_attr(element, "opacity", "0.72")
        return element

    return WEEKDAY_LABEL.sub(transform, text)


def polish_month_markers(text: str, scheme: str, layout: str) -> str:
    secondary = THEME_TOKENS[scheme]["secondary"]
    matches = MONTH_LABEL.findall(text)
    if not matches:
        raise ValueError("expected at least one month-boundary label")
    size = "6" if layout == "wide" else "5"

    def transform(match: re.Match[str]) -> str:
        element = set_attr(match.group(0), "fill", secondary)
        element = set_attr(element, "font-size", size)
        element = set_attr(element, "font-weight", "700")
        element = set_attr(element, "opacity", "0.90")
        return element

    return MONTH_LABEL.sub(transform, text)


def polish_latest_day(text: str, scheme: str) -> str:
    matches = LATEST_TILE.findall(text)
    if len(matches) != 1:
        raise ValueError(f"expected one latest-day tile, found {len(matches)}")

    primary = THEME_TOKENS[scheme]["primary"]
    latest = THEME_TOKENS[scheme]["latest"]
    element = matches[0]
    attrs = attrs_of(element)
    for required in ("x", "y", "width", "height", "rx"):
        if required not in attrs:
            raise ValueError(f"latest-day tile is missing {required}")

    inner = set_attr(element, "stroke", primary)
    inner = set_attr(inner, "stroke-width", "1")

    x = float(attrs["x"])
    y = float(attrs["y"])
    width = float(attrs["width"])
    height = float(attrs["height"])
    radius = float(attrs["rx"])
    outer = (
        f'<rect x="{x - 2:g}" y="{y - 2:g}" width="{width + 4:g}" '
        f'height="{height + 4:g}" rx="{radius + 2:g}" fill="none" '
        f'stroke="{latest}" stroke-width="1.5" opacity="0.96" '
        f'data-latest-outline="outer"/>'
    )
    return text.replace(element, inner + outer, 1)


def polish_compact_summary(text: str) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root element is missing")
    root_attrs = attrs_of(root.group(0))
    for required in ("data-active-days", "data-current-streak", "data-peak-count", "data-peak-date"):
        if required not in root_attrs:
            raise ValueError(f"compact SVG is missing {required}")

    matches = ACTIVITY_SUMMARY.findall(text)
    if len(matches) != 1:
        raise ValueError(f"expected one activity summary, found {len(matches)}")
    peak_short = date.fromisoformat(root_attrs["data-peak-date"]).strftime("%b %d").upper()
    value = (
        f'ACTIVE {root_attrs["data-active-days"]}/30 · '
        f'STREAK {root_attrs["data-current-streak"]} · '
        f'PEAK {peak_short} · {root_attrs["data-peak-count"]}'
    )
    element = set_attr(matches[0], "font-size", "6.8")
    element = text_content(element, value)
    return text.replace(matches[0], element, 1)


def polish_compact_legend(text: str) -> str:
    less = LEGEND_LESS.findall(text)
    more = LEGEND_MORE.findall(text)
    rects = LEGEND_RECT.findall(text)
    if len(less) != 1 or len(more) != 1 or len(rects) != 5:
        raise ValueError("compact legend geometry signature changed")

    text = LEGEND_LESS.sub(lambda m: m.group(0).replace('x="186.4"', 'x="196.4"', 1), text, count=1)
    text = LEGEND_MORE.sub(lambda m: m.group(0).replace('x="276"', 'x="286"', 1), text, count=1)

    def shift_rect(match: re.Match[str]) -> str:
        old_x = int(match.group(1))
        return match.group(0).replace(f'x="{old_x}"', f'x="{old_x + 10}"', 1)

    return LEGEND_RECT.sub(shift_rect, text)


def resize_compact_five_week(text: str) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root element is missing")
    rows = attrs_of(root.group(0)).get("data-activity-week-rows")
    if rows == "6":
        return text
    if rows != "5":
        raise ValueError(f"unexpected compact activity week-row count: {rows}")

    required = (
        ('viewBox="0 0 320 528" width="320" height="528"',
         'viewBox="0 0 320 500" width="320" height="500"'),
        ('<rect width="320" height="528"', '<rect width="320" height="500"'),
        ('<rect x="0.5" y="0.5" width="319" height="527"',
         '<rect x="0.5" y="0.5" width="319" height="499"'),
        ('<path d="M22 493h276"', '<path d="M22 465h276"'),
        ('<text x="160" y="512"', '<text x="160" y="486"'),
    )
    for old, new in required:
        if old not in text:
            raise ValueError(f"compact five-week geometry signature changed: {old}")
        text = text.replace(old, new, 1)
    return text


def add_polish_provenance(text: str) -> str:
    match = SVG_OPEN.search(text)
    if not match:
        raise ValueError("SVG root element is missing")
    if "data-polish=" in match.group(0):
        raise ValueError("Signal Field unexpectedly already contains polish provenance")
    attrs = match.group(1)
    replacement = f'<svg{attrs} data-polish="{POLISH_ID}">'
    return text[:match.start()] + replacement + text[match.end():]


def validate_polished(text: str, layout: str, scheme: str) -> None:
    if f'data-polish="{POLISH_ID}"' not in text:
        raise ValueError("polish provenance is missing")
    if text.count('data-latest-outline="outer"') != 1:
        raise ValueError("latest day must have exactly one outer cyan hairline")

    primary = THEME_TOKENS[scheme]["primary"]
    weekday_elements = WEEKDAY_LABEL.findall(text)
    if len(weekday_elements) != 7:
        raise ValueError("weekday-label count changed after polish")
    for element in weekday_elements:
        attrs = attrs_of(element)
        if attrs.get("fill") != primary or attrs.get("opacity") != "0.72":
            raise ValueError("weekday labels must use the brighter v2.1 treatment")

    month_elements = MONTH_LABEL.findall(text)
    if not month_elements:
        raise ValueError("month markers disappeared after polish")
    for element in month_elements:
        attrs = attrs_of(element)
        if attrs.get("font-weight") != "700" or attrs.get("opacity") != "0.90":
            raise ValueError("month-marker hierarchy is not the v2.1 treatment")

    latest = LATEST_TILE.findall(text)
    if len(latest) != 1:
        raise ValueError("latest-day tile disappeared after polish")
    latest_attrs = attrs_of(latest[0])
    if latest_attrs.get("stroke") != primary or latest_attrs.get("stroke-width") != "1":
        raise ValueError("latest-day inner keyline is not the v2.1 treatment")

    if layout == "compact":
        if 'x="186.4" y="266"' in text or 'x="276" y="266"' in text:
            raise ValueError("legacy compact legend positions remain")
        if 'x="196.4" y="266"' not in text or 'x="286" y="266"' not in text:
            raise ValueError("compact legend was not shifted as one unit")
        summary = ACTIVITY_SUMMARY.findall(text)
        if len(summary) != 1 or not re.search(r"PEAK [A-Z]{3} \d{2} · \d+", summary[0]):
            raise ValueError("compact peak telemetry must include peak date and count")

        root = SVG_OPEN.search(text)
        assert root is not None
        rows = attrs_of(root.group(0)).get("data-activity-week-rows")
        if rows == "5" and 'viewBox="0 0 320 500"' not in text:
            raise ValueError("five-week compact card must use the tightened 500px height")
        if rows == "6" and 'viewBox="0 0 320 528"' not in text:
            raise ValueError("six-week compact card must retain its 528px height")


def polish_svg(text: str, layout: str, scheme: str) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root element is missing")
    root_attrs = attrs_of(root.group(0))
    if root_attrs.get("data-theme") != "yunior-portal-neon-v2":
        raise ValueError("Signal Field v2 theme provenance is missing")
    if root_attrs.get("data-activity-layout") != "month-calendar-v2":
        raise ValueError("Signal Field v2 month-calendar provenance is missing")

    polished = polish_weekdays(text, scheme)
    polished = polish_month_markers(polished, scheme, layout)
    polished = polish_latest_day(polished, scheme)
    if layout == "compact":
        polished = polish_compact_summary(polished)
        polished = polish_compact_legend(polished)
        polished = resize_compact_five_week(polished)
    polished = add_polish_provenance(polished)
    validate_polished(polished, layout, scheme)
    return polished


def polish_directory(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        layout = layout_for(path)
        scheme = scheme_for(path)
        polished = polish_svg(path.read_text(encoding="utf-8"), layout, scheme)
        path.write_text(polished, encoding="utf-8")
        print(f"polished {filename} -> {POLISH_ID}")


def fixture(layout: str, scheme: str, week_rows: int = 5) -> str:
    tokens = THEME_TOKENS[scheme]
    geometry = (
        'viewBox="0 0 640 425" width="640" height="425"'
        if layout == "wide"
        else 'viewBox="0 0 320 528" width="320" height="528"'
    )
    surface = ""
    if layout == "compact":
        surface = (
            f'<rect width="320" height="528" fill="#0B1020"/>'
            f'<rect x="0.5" y="0.5" width="319" height="527" fill="none" stroke="{tokens["hairline"]}"/>'
            f'<path d="M22 493h276" stroke="{tokens["hairline"]}"/>'
            f'<text x="160" y="512" fill="{tokens["secondary"]}">GITHUB GRAPHQL CONTRIBUTION CALENDAR</text>'
            f'<text x="186.4" y="266" fill="{tokens["secondary"]}">LESS</text>'
            + "".join(
                f'<rect x="{218 + index * 10}" y="259" width="8" height="8" data-legend-level="{index}"/>'
                for index in range(5)
            )
            + f'<text x="276" y="266" fill="{tokens["secondary"]}">MORE</text>'
            f'<text x="22" y="285" fill="{tokens["secondary"]}" font-size="7.5" data-activity-summary="true">ACTIVE 23/30 · STREAK 16 · PEAK 672</text>'
        )
    weekdays = "".join(
        f'<text x="{20 + index * 20}" y="300" fill="{tokens["secondary"]}" data-weekday-label="{index}">{name}</text>'
        for index, name in enumerate(("SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"))
    )
    month = f'<text x="20" y="320" fill="{tokens["primary"]}" font-size="5.5" font-weight="800" data-month-boundary="AUG">AUG</text>'
    latest = (
        f'<rect x="186" y="426" width="34" height="24" rx="5" fill="#FF2BD6" '
        f'stroke="#FF2BD6" stroke-width="2" data-date="2026-09-03" data-count="1" '
        f'data-level="1" data-latest-day="true"/>'
    )
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" {geometry} data-theme="yunior-portal-neon-v2" '
        f'data-activity-layout="month-calendar-v2" data-activity-week-rows="{week_rows}" '
        f'data-active-days="23" data-current-streak="16" data-peak-count="672" '
        f'data-peak-date="2026-09-02">{surface}{weekdays}{month}{latest}</svg>'
    )


def self_test() -> None:
    for scheme in THEME_TOKENS:
        for layout in ("wide", "compact"):
            polished = polish_svg(fixture(layout, scheme), layout, scheme)
            assert f'data-polish="{POLISH_ID}"' in polished
            assert polished.count('data-latest-outline="outer"') == 1
            if layout == "compact":
                assert 'x="196.4" y="266"' in polished
                assert 'x="286" y="266"' in polished
                assert "PEAK SEP 02 · 672" in polished
                assert 'viewBox="0 0 320 500"' in polished

        six_week = polish_svg(fixture("compact", scheme, week_rows=6), "compact", scheme)
        assert 'viewBox="0 0 320 528"' in six_week

    print(f"Signal Field polish self-test passed: {POLISH_ID}")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError(
                "usage: polish-signal-field-v2.py <generated-directory> | --self-test"
            )
        polish_directory(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
