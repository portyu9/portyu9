#!/usr/bin/env python3
"""Apply Signal Field v2.2 semantics, accessibility, and evidence refinements.

This deterministic layer runs after the v2 theme/calendar customizer and v2.1 visual
polisher. It preserves GitHub-provided raw counts and contribution levels while making
the meaning and provenance of the activity field clearer:
- soften the latest-day cyan outer hairline
- make level-0 / LESS visibly gray in dark mode without changing its semantic level
- declare GitHub contribution-level 0–4 intensity semantics and raw-count provenance
- enrich accessible description text with active/streak/peak/window/source evidence
- replace generic footers with a compact evidence footer describing window/source/scale
  and refresh cadence

Unexpected v2.1 structure fails closed instead of publishing a partial artifact.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
import re
import sys

ENHANCEMENT_ID = "signal-field-v2.2"
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)

DARK_LEVEL_ZERO = "#3A465B"
DARK_LEVEL_ZERO_STROKE = "#59657A"
LATEST_OUTLINE_OPACITY = "0.68"
LATEST_OUTLINE_WIDTH = "1.25"

SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
DESC = re.compile(r"<desc\b([^>]*)>([^<]*)</desc>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
LATEST_OUTLINE = re.compile(
    r'<rect\b[^>]*\bdata-latest-outline="outer"[^>]*/>', re.I
)
LEGEND_ZERO = re.compile(
    r'<rect\b[^>]*\bdata-legend-level="0"[^>]*/>', re.I
)
ZERO_TILE = re.compile(
    r'<rect\b(?=[^>]*\bdata-date="\d{4}-\d{2}-\d{2}")'
    r'(?=[^>]*\bdata-level="0")[^>]*/>',
    re.I,
)
COMPACT_FOOTER = re.compile(
    r'<text x="160" y="(486|512)"[^>]*>GITHUB GRAPHQL CONTRIBUTION CALENDAR</text>',
    re.I,
)
WIDE_FOOTER_LEFT = re.compile(
    r'<text x="30" y="410"[^>]*>SOURCE · GITHUB GRAPHQL CONTRIBUTION CALENDAR</text>',
    re.I,
)
WIDE_FOOTER_RIGHT = re.compile(
    r'<text x="610" y="410"[^>]*>CONTRIBUTIONS THROUGH · [^<]+</text>',
    re.I,
)

MONO_FONT = "ui-monospace,SFMono-Regular,Consolas,Liberation Mono,monospace"


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
    index = element.rfind("/>") if element.endswith("/>") else element.find(">")
    if index < 0:
        raise ValueError(f"cannot add attribute {name!r} to malformed element")
    return element[:index] + f' {replacement}' + element[index:]


def replace_text(element: str, value: str) -> str:
    changed, count = re.subn(r">[^<]*</text>$", f">{value}</text>", element, count=1)
    if count != 1:
        raise ValueError("could not replace SVG text content")
    return changed


def add_root_evidence(text: str) -> str:
    match = SVG_OPEN.search(text)
    if not match:
        raise ValueError("SVG root element is missing")
    root = match.group(0)
    attrs = attrs_of(root)
    if attrs.get("data-polish") != "signal-field-v2.1":
        raise ValueError("Signal Field v2.1 polish provenance is missing")
    if attrs.get("data-activity-window-days") != "30":
        raise ValueError("Signal Field must retain the 30-day rolling window")
    if "data-enhancement" in attrs:
        raise ValueError("Signal Field unexpectedly already contains v2.2 provenance")

    evidence_attrs = (
        f' data-enhancement="{ENHANCEMENT_ID}"'
        ' data-intensity-scale="github-contribution-levels-0-4"'
        ' data-count-semantics="raw-github-contribution-counts"'
        ' data-window-timezone="UTC"'
        ' data-refresh-cadence="daily"'
        ' data-source="github-graphql-contribution-calendar"'
    )
    replacement = root[:-1] + evidence_attrs + ">"
    return text[:match.start()] + replacement + text[match.end():]


def soften_latest_outline(text: str) -> str:
    matches = LATEST_OUTLINE.findall(text)
    if len(matches) != 1:
        raise ValueError(f"expected one latest-day outer outline, found {len(matches)}")
    element = matches[0]
    element = set_attr(element, "opacity", LATEST_OUTLINE_OPACITY)
    element = set_attr(element, "stroke-width", LATEST_OUTLINE_WIDTH)
    return text.replace(matches[0], element, 1)


def brighten_dark_level_zero(text: str, scheme: str) -> str:
    if scheme != "dark":
        return text

    legend = LEGEND_ZERO.findall(text)
    if len(legend) != 1:
        raise ValueError(f"expected one level-0 legend swatch, found {len(legend)}")
    legend_element = set_attr(legend[0], "fill", DARK_LEVEL_ZERO)
    legend_element = set_attr(legend_element, "stroke", DARK_LEVEL_ZERO_STROKE)
    legend_element = set_attr(legend_element, "stroke-width", "0.75")
    text = text.replace(legend[0], legend_element, 1)

    zero_tiles = ZERO_TILE.findall(text)
    if not zero_tiles:
        raise ValueError("expected at least one level-0 date tile in the live 30-day fixture")
    for original in zero_tiles:
        enhanced = set_attr(original, "fill", DARK_LEVEL_ZERO)
        enhanced = set_attr(enhanced, "stroke", DARK_LEVEL_ZERO_STROKE)
        enhanced = set_attr(enhanced, "stroke-width", "1")
        text = text.replace(original, enhanced, 1)
    return text


def enrich_description(text: str) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root element is missing")
    attrs = attrs_of(root.group(0))
    required = (
        "data-active-days",
        "data-current-streak",
        "data-peak-count",
        "data-peak-date",
        "data-activity-from",
        "data-activity-to",
    )
    missing = [name for name in required if name not in attrs]
    if missing:
        raise ValueError("SVG is missing evidence attributes: " + ", ".join(missing))

    matches = list(DESC.finditer(text))
    if len(matches) != 1:
        raise ValueError(f"expected one SVG description, found {len(matches)}")
    original = matches[0].group(0)
    prefix = matches[0].group(2).strip()
    if "Color encodes GitHub contribution levels" in prefix:
        raise ValueError("SVG description unexpectedly already contains v2.2 semantics")

    peak_date = date.fromisoformat(attrs["data-peak-date"]).strftime("%B %d, %Y")
    evidence = (
        f" In the rolling 30-day UTC window from {attrs['data-activity-from']} through "
        f"{attrs['data-activity-to']}, {attrs['data-active-days']} of 30 days are active; "
        f"the current streak is {attrs['data-current-streak']} days; the peak is "
        f"{attrs['data-peak-count']} contributions on {peak_date}. "
        "Color encodes GitHub contribution levels 0 through 4 while each date preserves "
        "its raw GitHub contribution count. Source: GitHub GraphQL contribution calendar. "
        "Refresh cadence: daily."
    )
    enhanced = f"<desc{matches[0].group(1)}>{prefix}{evidence}</desc>"
    return text.replace(original, enhanced, 1)


def render_footer(layout: str, y: str | None = None) -> str:
    if layout == "compact":
        if y is None:
            raise ValueError("compact footer requires y coordinate")
        return (
            f'<text x="160" y="{y}" fill="#A7B0C4" font-family="{MONO_FONT}" '
            f'font-size="7.2" font-weight="650" text-anchor="middle" '
            f'data-evidence-footer="true">'
            f'30 UTC DAYS · GITHUB GRAPHQL · LEVELS 0–4 · DAILY</text>'
        )
    raise ValueError(f"unsupported footer layout: {layout}")


def enhance_footer(text: str, layout: str, scheme: str) -> str:
    secondary = "#A7B0C4" if scheme == "dark" else "#5B6475"
    if layout == "compact":
        matches = list(COMPACT_FOOTER.finditer(text))
        if len(matches) != 1:
            raise ValueError(f"expected one compact evidence footer target, found {len(matches)}")
        y = matches[0].group(1)
        footer = render_footer("compact", y).replace('#A7B0C4', secondary)
        return text[:matches[0].start()] + footer + text[matches[0].end():]

    left = WIDE_FOOTER_LEFT.findall(text)
    right = WIDE_FOOTER_RIGHT.findall(text)
    if len(left) != 1 or len(right) != 1:
        raise ValueError("wide evidence footer geometry signature changed")

    left_footer = (
        f'<text x="30" y="410" fill="{secondary}" font-family="{MONO_FONT}" '
        f'font-size="8.5" font-weight="650" data-evidence-footer="true">'
        f'WINDOW · 30 UTC DAYS · LEVELS 0–4 · RAW COUNTS</text>'
    )
    right_footer = (
        f'<text x="610" y="410" fill="{secondary}" font-family="{MONO_FONT}" '
        f'font-size="8.5" font-weight="650" text-anchor="end" '
        f'data-evidence-footer="true">SOURCE · GITHUB GRAPHQL · REFRESH · DAILY</text>'
    )
    text = WIDE_FOOTER_LEFT.sub(left_footer, text, count=1)
    return WIDE_FOOTER_RIGHT.sub(right_footer, text, count=1)


def validate(text: str, layout: str, scheme: str) -> None:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root element is missing after enhancement")
    attrs = attrs_of(root.group(0))
    expected_attrs = {
        "data-enhancement": ENHANCEMENT_ID,
        "data-intensity-scale": "github-contribution-levels-0-4",
        "data-count-semantics": "raw-github-contribution-counts",
        "data-window-timezone": "UTC",
        "data-refresh-cadence": "daily",
        "data-source": "github-graphql-contribution-calendar",
    }
    for name, value in expected_attrs.items():
        if attrs.get(name) != value:
            raise ValueError(f"missing or invalid root evidence attribute: {name}")

    outlines = LATEST_OUTLINE.findall(text)
    if len(outlines) != 1:
        raise ValueError("latest-day outer outline count changed")
    outline_attrs = attrs_of(outlines[0])
    if outline_attrs.get("opacity") != LATEST_OUTLINE_OPACITY:
        raise ValueError("latest-day cyan outer outline was not softened")
    if outline_attrs.get("stroke-width") != LATEST_OUTLINE_WIDTH:
        raise ValueError("latest-day cyan outer outline width is not v2.2")

    desc = DESC.findall(text)
    if len(desc) != 1:
        raise ValueError("accessible description count changed")
    desc_text = desc[0][1]
    for phrase in (
        "rolling 30-day UTC window",
        "current streak",
        "Color encodes GitHub contribution levels 0 through 4",
        "raw GitHub contribution count",
        "Source: GitHub GraphQL contribution calendar",
        "Refresh cadence: daily",
    ):
        if phrase not in desc_text:
            raise ValueError(f"accessible evidence description is missing: {phrase}")

    footer_count = text.count('data-evidence-footer="true"')
    expected_footer_count = 1 if layout == "compact" else 2
    if footer_count != expected_footer_count:
        raise ValueError("evidence footer count does not match layout")

    if scheme == "dark":
        legend = LEGEND_ZERO.findall(text)
        if len(legend) != 1 or attrs_of(legend[0]).get("fill") != DARK_LEVEL_ZERO:
            raise ValueError("dark level-0 legend swatch is not visibly gray")
        zero_tiles = ZERO_TILE.findall(text)
        if not zero_tiles:
            raise ValueError("dark activity field lost level-0 tiles")
        for tile in zero_tiles:
            tile_attrs = attrs_of(tile)
            if tile_attrs.get("fill") != DARK_LEVEL_ZERO:
                raise ValueError("dark level-0 date tile does not match the legend")


def enhance_svg(text: str, layout: str, scheme: str) -> str:
    enhanced = add_root_evidence(text)
    enhanced = soften_latest_outline(enhanced)
    enhanced = brighten_dark_level_zero(enhanced, scheme)
    enhanced = enrich_description(enhanced)
    enhanced = enhance_footer(enhanced, layout, scheme)
    validate(enhanced, layout, scheme)
    return enhanced


def enhance_directory(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        layout = layout_for(path)
        scheme = scheme_for(path)
        enhanced = enhance_svg(path.read_text(encoding="utf-8"), layout, scheme)
        path.write_text(enhanced, encoding="utf-8")
        print(f"enhanced {filename} -> {ENHANCEMENT_ID}")


def fixture(layout: str, scheme: str, compact_y: str = "486") -> str:
    secondary = "#A7B0C4" if scheme == "dark" else "#5B6475"
    zero_fill = "#171D2D" if scheme == "dark" else "#EEF2FF"
    if layout == "compact":
        footer = (
            f'<text x="160" y="{compact_y}" fill="{secondary}">'
            f'GITHUB GRAPHQL CONTRIBUTION CALENDAR</text>'
        )
    else:
        footer = (
            f'<text x="30" y="410" fill="{secondary}">'
            f'SOURCE · GITHUB GRAPHQL CONTRIBUTION CALENDAR</text>'
            f'<text x="610" y="410" fill="{secondary}">'
            f'CONTRIBUTIONS THROUGH · SEP 03, 2026</text>'
        )
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" data-polish="signal-field-v2.1" '
        'data-theme="yunior-portal-neon-v2" data-activity-window-days="30" '
        'data-activity-from="2026-08-05" data-activity-to="2026-09-03" '
        'data-active-days="23" data-current-streak="16" data-peak-count="672" '
        'data-peak-date="2026-09-02">'
        '<title>fixture</title>'
        '<desc>Fixture. 30 daily activity marks from 2026-08-05 through 2026-09-03, inclusive.</desc>'
        f'<rect x="1" y="1" width="8" height="8" fill="{zero_fill}" data-legend-level="0"/>'
        f'<rect x="20" y="20" width="34" height="24" rx="5" fill="{zero_fill}" '
        'stroke="#28324A" stroke-width="1" data-date="2026-08-10" data-count="0" data-level="0"/>'
        '<rect x="60" y="20" width="34" height="24" rx="5" fill="#A020F0" '
        'stroke="#F8FAFC" stroke-width="1" data-date="2026-09-03" data-count="28" '
        'data-level="2" data-latest-day="true"/>'
        '<rect x="58" y="18" width="38" height="28" rx="7" fill="none" stroke="#00AEEF" '
        'stroke-width="1.5" opacity="0.96" data-latest-outline="outer"/>'
        f'{footer}</svg>'
    )


def self_test() -> None:
    for scheme in ("light", "dark"):
        for layout in ("wide", "compact"):
            enhanced = enhance_svg(fixture(layout, scheme), layout, scheme)
            assert f'data-enhancement="{ENHANCEMENT_ID}"' in enhanced
            assert f'opacity="{LATEST_OUTLINE_OPACITY}"' in enhanced
            assert "Color encodes GitHub contribution levels 0 through 4" in enhanced
            assert 'data-evidence-footer="true"' in enhanced
            if scheme == "dark":
                assert DARK_LEVEL_ZERO in enhanced
            if layout == "compact":
                assert "30 UTC DAYS · GITHUB GRAPHQL · LEVELS 0–4 · DAILY" in enhanced
            else:
                assert "WINDOW · 30 UTC DAYS · LEVELS 0–4 · RAW COUNTS" in enhanced
                assert "SOURCE · GITHUB GRAPHQL · REFRESH · DAILY" in enhanced

        six_week = enhance_svg(fixture("compact", scheme, compact_y="512"), "compact", scheme)
        assert 'y="512"' in six_week

    print(f"Signal Field evidence self-test passed: {ENHANCEMENT_ID}")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError(
                "usage: enhance-signal-field-v2.py <generated-directory> | --self-test"
            )
        enhance_directory(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
