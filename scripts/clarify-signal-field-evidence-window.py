#!/usr/bin/env python3
"""Clarify Signal Field's measured 30-day evidence window versus calendar context.

Signal Field v2.13 is a presentation-only pass after v2.12. It changes no metric,
count, source, date, contribution level, or evidence-window membership. Monday-aligned
leading context is visually subordinate and empty calendar slots are quieter.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

VERSION = "signal-field-v2.13"
PREVIOUS = "signal-field-v2.12"
EXPECTED_FILES = tuple(
    f"signal-field-{layout}-{theme}.svg"
    for layout in ("wide", "compact")
    for theme in ("light", "dark")
)
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
LEADING_RECT = re.compile(r'(?P<tag><rect\b(?=[^>]*\bdata-window-context="leading")[^>]*/>)', re.I)
MEASURED_RECT = re.compile(r'(?P<tag><rect\b(?=[^>]*\bdata-window-day="\d+")[^>]*/>)', re.I)
OUTSIDE_RECT = re.compile(r'(?P<tag><rect\b(?=[^>]*\bdata-slot-state="outside-window")[^>]*/>)', re.I)
DAY_LABEL = re.compile(r'(?P<tag><text\b(?=[^>]*\bdata-day-label="(?P<date>\d{4}-\d{2}-\d{2})")[^>]*>)', re.I)
MONTH_LABEL = re.compile(r'(?P<tag><text\b(?=[^>]*\bdata-month-boundary="(?P<month>[A-Z]{3})")[^>]*>)', re.I)
COMPACT_VIEWBOXES = {"0 0 320 500", "0 0 320 528"}

HEADINGS = {
    "wide": ("DAILY ACTIVITY · LAST 30 DAYS", "DAILY ACTIVITY · 30-DAY EVIDENCE WINDOW"),
    # Compact intentionally stays short so it cannot collide with the LESS/MORE legend.
    "compact": ("DAILY ACTIVITY · 30 DAYS", "DAILY ACTIVITY · 30D"),
}
WIDE_FOOTERS = (
    "WINDOW · 30 UTC DAYS · LEVELS 0–4 · RAW COUNTS",
    "30D EVIDENCE · DIM CONTEXT · LEVELS 0–4 · RAW COUNTS",
)
DESC_CONTEXT = (
    "for Monday-aligned context.",
    "as dimmed Monday-aligned context.",
)
CONTEXT_OPACITY = "0.50"
CONTEXT_LABEL_OPACITY = "0.58"
OUTSIDE_OPACITY = "0.16"


def attrs_of(tag: str) -> dict[str, str]:
    return dict(ATTR.findall(tag))


def set_attr(tag: str, name: str, value: str) -> str:
    pattern = re.compile(rf'\b{re.escape(name)}="[^"]*"')
    replacement = f'{name}="{value}"'
    if pattern.search(tag):
        return pattern.sub(replacement, tag, count=1)
    close = tag.rfind("/>")
    if close < 0:
        close = tag.rfind(">")
    if close < 0:
        raise ValueError(f"cannot set {name!r} on malformed SVG element")
    return tag[:close].rstrip() + f' {replacement}' + tag[close:]


def layout_of(root_tag: str) -> str:
    viewbox = attrs_of(root_tag).get("viewBox")
    if viewbox == "0 0 640 425": return "wide"
    if viewbox in COMPACT_VIEWBOXES: return "compact"
    raise ValueError(f"unexpected Signal Field viewBox: {viewbox!r}")


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise ValueError(f"expected exactly one {label}: {old!r}")
    return text.replace(old, new, 1)


def mark_calendar_roles(text: str) -> str:
    original_leading = list(LEADING_RECT.finditer(text))
    leading_dates = {attrs_of(m.group("tag"))["data-date"] for m in original_leading}
    leading_months = {
        attrs["data-month-boundary"]
        for m in original_leading
        if "data-month-boundary" in (attrs := attrs_of(m.group("tag")))
    }

    def leading(match: re.Match[str]) -> str:
        tag = set_attr(match.group("tag"), "opacity", CONTEXT_OPACITY)
        return set_attr(tag, "data-evidence-window-role", "context")

    def measured(match: re.Match[str]) -> str:
        return set_attr(match.group("tag"), "data-evidence-window-role", "measured")

    def outside(match: re.Match[str]) -> str:
        tag = set_attr(match.group("tag"), "opacity", OUTSIDE_OPACITY)
        return set_attr(tag, "data-evidence-window-role", "empty")

    text = LEADING_RECT.sub(leading, text)
    text = MEASURED_RECT.sub(measured, text)
    text = OUTSIDE_RECT.sub(outside, text)

    def day_label(match: re.Match[str]) -> str:
        tag = match.group("tag")
        if match.group("date") not in leading_dates:
            return tag
        tag = set_attr(tag, "opacity", CONTEXT_LABEL_OPACITY)
        return set_attr(tag, "data-evidence-context-label", "calendar-leading")

    def month_label(match: re.Match[str]) -> str:
        tag = match.group("tag")
        if match.group("month") not in leading_months:
            return tag
        tag = set_attr(tag, "opacity", CONTEXT_LABEL_OPACITY)
        return set_attr(tag, "data-evidence-context-label", "calendar-leading")

    return MONTH_LABEL.sub(month_label, DAY_LABEL.sub(day_label, text))


def add_root_provenance(text: str) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing")
    tag = set_attr(root.group(0), "data-evidence-window-clarity", VERSION)
    tag = set_attr(tag, "data-calendar-context-visual", "dimmed")
    return text[:root.start()] + tag + text[root.end():]


def validate(text: str, layout: str) -> None:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing after v2.13")
    attrs = attrs_of(root.group(0))
    if attrs.get("data-evidence-window-clarity") != VERSION:
        raise ValueError("v2.13 evidence-window provenance missing")
    if attrs.get("data-calendar-context-visual") != "dimmed":
        raise ValueError("calendar-context visual provenance changed")
    if attrs.get("data-secondary-metric-balance") != PREVIOUS:
        raise ValueError("v2.12 must precede v2.13")
    try:
        window_days = int(attrs["data-activity-window-days"])
        display_days = int(attrs["data-activity-display-days"])
    except (KeyError, ValueError) as exc:
        raise ValueError("activity-window provenance is malformed") from exc
    if window_days != 30:
        raise ValueError("v2.13 requires the reviewed 30-day evidence window")

    measured = [m.group("tag") for m in MEASURED_RECT.finditer(text)]
    leading = [m.group("tag") for m in LEADING_RECT.finditer(text)]
    outside = [m.group("tag") for m in OUTSIDE_RECT.finditer(text)]
    if len(measured) != window_days:
        raise ValueError(f"expected {window_days} measured evidence tiles, found {len(measured)}")
    if len(leading) != display_days - window_days:
        raise ValueError("leading-context tile count does not match display provenance")
    if not outside:
        raise ValueError("calendar outside-window slots unexpectedly disappeared")

    if any(attrs_of(t).get("data-evidence-window-role") != "measured" for t in measured):
        raise ValueError("measured evidence tile role missing")
    for tag in leading:
        a = attrs_of(tag)
        if a.get("data-evidence-window-role") != "context" or a.get("opacity") != CONTEXT_OPACITY:
            raise ValueError("leading calendar context styling/provenance changed")
    for tag in outside:
        a = attrs_of(tag)
        if a.get("data-evidence-window-role") != "empty" or a.get("opacity") != OUTSIDE_OPACITY:
            raise ValueError("outside calendar slot styling/provenance changed")

    if leading:
        leading_dates = {attrs_of(t)["data-date"] for t in leading}
        found = 0
        for match in DAY_LABEL.finditer(text):
            if match.group("date") not in leading_dates:
                continue
            found += 1
            a = attrs_of(match.group("tag"))
            if a.get("opacity") != CONTEXT_LABEL_OPACITY or a.get("data-evidence-context-label") != "calendar-leading":
                raise ValueError("leading context day label is not correctly dimmed")
        if found != len(leading_dates):
            raise ValueError("leading context day-label count changed")

    old_heading, new_heading = HEADINGS[layout]
    if text.count(new_heading) != 1 or old_heading in text:
        raise ValueError(f"{layout} evidence-window heading contract changed")
    old_desc, new_desc = DESC_CONTEXT
    if old_desc in text or text.count(new_desc) != 1:
        raise ValueError("accessible dimmed-context semantics changed")
    if layout == "wide":
        old_footer, new_footer = WIDE_FOOTERS
        if text.count(new_footer) != 1 or old_footer in text:
            raise ValueError("wide evidence footer clarity contract changed")


def clarify_svg(text: str) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing")
    layout = layout_of(root.group(0))
    attrs = attrs_of(root.group(0))
    if attrs.get("data-evidence-window-clarity") == VERSION:
        validate(text, layout)
        return text
    if attrs.get("data-secondary-metric-balance") != PREVIOUS:
        raise ValueError("Signal Field v2.12 must exist before v2.13")

    old_heading, new_heading = HEADINGS[layout]
    text = replace_once(text, old_heading, new_heading, f"{layout} activity heading")
    if layout == "wide":
        text = replace_once(text, *WIDE_FOOTERS, "wide evidence footer")
    text = replace_once(text, *DESC_CONTEXT, "accessible calendar-context phrase")
    text = add_root_provenance(mark_calendar_roles(text))
    validate(text, layout)
    return text


def fixture(layout: str, compact_view_box: str = "0 0 320 500") -> str:
    geometry = 'viewBox="0 0 640 425" width="640" height="425"' if layout == "wide" else f'viewBox="{compact_view_box}" width="320" height="{compact_view_box.rsplit(" ", 1)[-1]}"'
    leading = (
        '<rect data-date="2026-08-01" data-window-context="leading" data-month-boundary="AUG"/>'
        '<text data-month-boundary="AUG" opacity="1">AUG</text>'
        '<text data-day-label="2026-08-01">01</text>'
        '<rect data-date="2026-08-02" data-window-context="leading"/><text data-day-label="2026-08-02">02</text>'
        '<rect data-date="2026-08-03" data-window-context="leading"/><text data-day-label="2026-08-03">03</text>'
    )
    measured = ''.join(f'<rect data-date="2026-09-{i:02d}" data-window-day="{i}"/>' for i in range(1, 31))
    outside = '<rect opacity="0.38" data-slot-state="outside-window"/><rect opacity="0.38" data-slot-state="outside-window"/>'
    old_heading, _ = HEADINGS[layout]
    footer = f'<text>{WIDE_FOOTERS[0]}</text>' if layout == "wide" else ""
    return (
        f'<svg {geometry} data-activity-window-days="30" data-activity-display-days="33" data-secondary-metric-balance="{PREVIOUS}">'
        '<desc>calendar display includes 33 dated marks from 2026-08-01 through 2026-09-30 for Monday-aligned context.</desc>'
        f'<text>{old_heading}</text>{leading}{measured}{outside}{footer}</svg>'
    )


def self_test() -> None:
    cases = (
        ("wide", fixture("wide")),
        ("compact-5-row", fixture("compact", "0 0 320 500")),
        ("compact-6-row", fixture("compact", "0 0 320 528")),
    )
    for label, source in cases:
        layout = "wide" if label == "wide" else "compact"
        transformed = clarify_svg(source)
        validate(transformed, layout)
        if clarify_svg(transformed) != transformed:
            raise AssertionError("v2.13 transform must be idempotent")
        print(f"{label} v2.13 evidence-window clarity fixture passed")
    print(f"Signal Field evidence-window clarity self-test passed: {VERSION}")


def apply(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        path.write_text(clarify_svg(path.read_text(encoding="utf-8")), encoding="utf-8")
        print(f"clarified {filename}: measured 30-day window separated from calendar context")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test(); return 0
        if len(sys.argv) != 2:
            raise ValueError("usage: clarify-signal-field-evidence-window.py <generated-directory> | --self-test")
        apply(Path(sys.argv[1])); return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())
