#!/usr/bin/env python3
"""Balance Signal Field secondary metric glyphs and the wide Pull Requests column.

Signal Field v2.12 keeps the v2.11 inline-vector glyphs but makes them legible at
README scale. On wide cards it also moves Pull Requests onto the exact midpoint
between the Stars and Bugs Found metric axes, centering both the value and label.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

VERSION = "signal-field-v2.12"
PREVIOUS_GLYPH_VERSION = "signal-field-v2.11"
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)
METRICS = ("stars", "pull_requests", "issues")
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
PULL_LABEL = re.compile(r'(?P<tag><text\b[^>]*>)PULL REQUESTS</text>', re.I)
COMPACT_VIEWBOXES = {"0 0 320 500", "0 0 320 528"}

WIDE_GLYPH_SIZE = 17.5
COMPACT_GLYPH_SIZE = 14.5
WIDE_GAP = 5.0
COMPACT_GAP = 4.0
WIDE_PULL_CENTER = 447.0
WIDE_PULL_LINE_D = "M404 73h86"


def attrs_of(tag: str) -> dict[str, str]:
    return dict(ATTR.findall(tag))


def set_attr(tag: str, name: str, value: str) -> str:
    pattern = re.compile(rf'\b{re.escape(name)}="[^"]*"')
    replacement = f'{name}="{value}"'
    if pattern.search(tag):
        return pattern.sub(replacement, tag, count=1)
    return tag[:-1] + f' {replacement}>'


def metric_pattern(metric: str) -> re.Pattern[str]:
    return re.compile(
        rf'(?P<tag><text\b(?=[^>]*\bdata-metric-phosphor="{re.escape(metric)}")[^>]*>)'
        r'(?P<value>[\d,]+)</text>',
        re.I,
    )


def glyph_pattern(metric: str) -> re.Pattern[str]:
    return re.compile(
        rf'(?P<tag><g\b(?=[^>]*\bdata-metric-glyph="{re.escape(metric)}")[^>]*>)',
        re.I,
    )


def approximate_width(value: str, font_size: float) -> float:
    digits = sum(char.isdigit() for char in value)
    commas = value.count(",")
    return digits * font_size * 0.59 + commas * font_size * 0.28


def layout_of(root_tag: str) -> str:
    view_box = attrs_of(root_tag).get("viewBox")
    if view_box == "0 0 640 425":
        return "wide"
    if view_box in COMPACT_VIEWBOXES:
        return "compact"
    raise ValueError(f"unexpected Signal Field viewBox: {view_box!r}")


def center_wide_pull_requests(text: str) -> str:
    pattern = metric_pattern("pull_requests")
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise ValueError("expected exactly one Pull Requests value")
    match = matches[0]
    tag = set_attr(match.group("tag"), "x", f"{WIDE_PULL_CENTER:g}")
    tag = set_attr(tag, "text-anchor", "middle")
    text = text[: match.start("tag")] + tag + text[match.end("tag") :]

    labels = list(PULL_LABEL.finditer(text))
    if len(labels) != 1:
        raise ValueError("expected exactly one Pull Requests label")
    label = labels[0]
    label_tag = set_attr(label.group("tag"), "x", f"{WIDE_PULL_CENTER:g}")
    label_tag = set_attr(label_tag, "text-anchor", "middle")
    text = text[: label.start("tag")] + label_tag + text[label.end("tag") :]

    line_pattern = re.compile(
        r'(?P<tag><path\b(?=[^>]*\bdata-metric-phosphor-line="pull_requests")[^>]*>)',
        re.I,
    )
    lines = list(line_pattern.finditer(text))
    if len(lines) != 1:
        raise ValueError("expected exactly one Pull Requests phosphor line")
    line = lines[0]
    line_tag = set_attr(line.group("tag"), "d", WIDE_PULL_LINE_D)
    text = text[: line.start("tag")] + line_tag + text[line.end("tag") :]
    return text


def expected_glyph_transform(metric: str, text: str, layout: str) -> str:
    matches = list(metric_pattern(metric).finditer(text))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one metric value for {metric}")
    match = matches[0]
    attrs = attrs_of(match.group("tag"))
    try:
        x = float(attrs["x"])
        y = float(attrs["y"])
        font_size = float(attrs["font-size"])
    except (KeyError, ValueError) as exc:
        raise ValueError(f"{metric} metric geometry signature changed") from exc

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

    size = WIDE_GLYPH_SIZE if layout == "wide" else COMPACT_GLYPH_SIZE
    gap = WIDE_GAP if layout == "wide" else COMPACT_GAP
    cx = left - gap - size / 2.0
    cy = y - font_size * 0.35
    scale = size / 12.0
    return f"translate({cx:.2f} {cy:.2f}) scale({scale:.4f})"


def rewrite_glyph_transforms(text: str, layout: str) -> str:
    for metric in METRICS:
        matches = list(glyph_pattern(metric).finditer(text))
        if len(matches) != 1:
            raise ValueError(f"expected exactly one existing v2.11 glyph for {metric}")
        match = matches[0]
        transform = expected_glyph_transform(metric, text, layout)
        tag = set_attr(match.group("tag"), "transform", transform)
        text = text[: match.start("tag")] + tag + text[match.end("tag") :]
    return text


def validate_balance(text: str, layout: str) -> None:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing")
    root_attrs = attrs_of(root.group(0))
    if root_attrs.get("data-secondary-metric-balance") != VERSION:
        raise ValueError("v2.12 secondary-metric balance provenance is missing")

    expected_scale = "1.4583" if layout == "wide" else "1.2083"
    for metric in METRICS:
        glyphs = list(glyph_pattern(metric).finditer(text))
        if len(glyphs) != 1:
            raise ValueError(f"balanced glyph missing for {metric}")
        attrs = attrs_of(glyphs[0].group("tag"))
        expected = expected_glyph_transform(metric, text, layout)
        if attrs.get("transform") != expected or f"scale({expected_scale})" not in expected:
            raise ValueError(f"{metric} glyph balance geometry changed")

    pull = list(metric_pattern("pull_requests").finditer(text))
    if len(pull) != 1:
        raise ValueError("Pull Requests value missing during balance validation")
    pull_attrs = attrs_of(pull[0].group("tag"))
    labels = list(PULL_LABEL.finditer(text))
    if len(labels) != 1:
        raise ValueError("Pull Requests label missing during balance validation")
    label_attrs = attrs_of(labels[0].group("tag"))

    if layout == "wide":
        if pull_attrs.get("x") != "447" or pull_attrs.get("text-anchor") != "middle":
            raise ValueError("wide Pull Requests value is not centered on the secondary-metric midpoint")
        if label_attrs.get("x") != "447" or label_attrs.get("text-anchor") != "middle":
            raise ValueError("wide Pull Requests label is not centered on the secondary-metric midpoint")
        if text.count(f'd="{WIDE_PULL_LINE_D}"') != 1:
            raise ValueError("wide Pull Requests phosphor line is not centered with its metric")
    else:
        if pull_attrs.get("x") != "160" or pull_attrs.get("text-anchor") != "middle":
            raise ValueError("compact Pull Requests value must remain centered at x=160")


def balance_svg(text: str) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing")
    root_tag = root.group(0)
    layout = layout_of(root_tag)

    if f'data-secondary-metric-balance="{VERSION}"' in root_tag:
        validate_balance(text, layout)
        return text
    if f'data-metric-glyphs="{PREVIOUS_GLYPH_VERSION}"' not in root_tag:
        raise ValueError("Signal Field v2.11 glyph provenance must exist before v2.12 balancing")

    if layout == "wide":
        text = center_wide_pull_requests(text)
    text = rewrite_glyph_transforms(text, layout)

    root = SVG_OPEN.search(text)
    assert root is not None
    replacement = root.group(0)[:-1] + f' data-secondary-metric-balance="{VERSION}">'
    text = text[: root.start()] + replacement + text[root.end() :]
    validate_balance(text, layout)
    return text


def fixture(layout: str, compact_view_box: str = "0 0 320 500") -> str:
    if layout == "wide":
        return (
            '<svg viewBox="0 0 640 425" data-metric-glyphs="signal-field-v2.11">'
            '<g data-metric-glyph="stars" transform="translate(1 1) scale(.9)"></g>'
            '<text x="284" y="108" fill="#C96BFF" font-size="26" data-metric-phosphor="stars">14</text>'
            '<path d="M390 73h86" data-metric-phosphor-line="pull_requests"/>'
            '<g data-metric-glyph="pull_requests" transform="translate(1 1) scale(.9)"></g>'
            '<text x="390" y="108" fill="#8C7CFF" font-size="26" data-metric-phosphor="pull_requests">476</text>'
            '<text x="390" y="132">PULL REQUESTS</text>'
            '<g data-metric-glyph="issues" transform="translate(1 1) scale(.9)"></g>'
            '<text x="610" y="108" text-anchor="end" fill="#28D7FF" font-size="26" data-metric-phosphor="issues">33</text>'
            '</svg>'
        )
    return (
        f'<svg viewBox="{compact_view_box}" data-metric-glyphs="signal-field-v2.11">'
        '<g data-metric-glyph="stars" transform="translate(1 1) scale(.8)"></g>'
        '<text x="66" y="206" text-anchor="middle" fill="#C96BFF" font-size="22" data-metric-phosphor="stars">14</text>'
        '<g data-metric-glyph="pull_requests" transform="translate(1 1) scale(.8)"></g>'
        '<text x="160" y="206" text-anchor="middle" fill="#8C7CFF" font-size="22" data-metric-phosphor="pull_requests">476</text>'
        '<text x="160" y="226" text-anchor="middle">PULL REQUESTS</text>'
        '<g data-metric-glyph="issues" transform="translate(1 1) scale(.8)"></g>'
        '<text x="254" y="206" text-anchor="middle" fill="#28D7FF" font-size="22" data-metric-phosphor="issues">33</text>'
        '</svg>'
    )


def self_test() -> None:
    cases = (
        ("wide", fixture("wide")),
        ("compact-5-row", fixture("compact", "0 0 320 500")),
        ("compact-6-row", fixture("compact", "0 0 320 528")),
    )
    for label, source in cases:
        layout = "wide" if label == "wide" else "compact"
        transformed = balance_svg(source)
        assert f'data-secondary-metric-balance="{VERSION}"' in transformed
        assert balance_svg(transformed) == transformed
        if layout == "wide":
            assert 'x="447"' in transformed
            assert 'd="M404 73h86"' in transformed
            assert transformed.count("scale(1.4583)") == 3
        else:
            assert transformed.count("scale(1.2083)") == 3
        print(f"{label} v2.12 secondary-metric balance fixture passed")
    print(f"Signal Field secondary-metric balance self-test passed: {VERSION}")


def apply(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        path.write_text(balance_svg(path.read_text(encoding="utf-8")), encoding="utf-8")
        print(f"balanced {filename}: larger glyphs; wide Pull Requests centered")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError(
                "usage: balance-signal-field-secondary-metrics.py <generated-directory> | --self-test"
            )
        apply(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
