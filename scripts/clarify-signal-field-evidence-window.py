#!/usr/bin/env python3
"""Clarify Signal Field's measured 30-day evidence window versus calendar context.

Signal Field v2.13 is a presentation-only pass after v2.12. It does not change any
metric, count, source, date, contribution level, or evidence-window membership.
It makes the Monday-aligned leading calendar context visually subordinate, quiets
empty calendar slots, and labels the measured window more precisely.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

VERSION = "signal-field-v2.13"
PREVIOUS = "signal-field-v2.12"
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)

SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
LEADING_RECT = re.compile(
    r'(?P<tag><rect\b(?=[^>]*\bdata-window-context="leading")[^>]*/>)', re.I
)
MEASURED_RECT = re.compile(
    r'(?P<tag><rect\b(?=[^>]*\bdata-window-day="\d+")[^>]*/>)', re.I
)
OUTSIDE_RECT = re.compile(
    r'(?P<tag><rect\b(?=[^>]*\bdata-slot-state="outside-window")[^>]*/>)', re.I
)
DAY_LABEL = re.compile(
    r'(?P<tag><text\b(?=[^>]*\bdata-day-label="(?P<date>\d{4}-\d{2}-\d{2})")[^>]*>)', re.I
)
MONTH_LABEL = re.compile(
    r'(?P<tag><text\b(?=[^>]*\bdata-month-boundary="(?P<month>[A-Z]{3})")[^>]*>)', re.I
)

WIDE_OLD_HEADING = "DAILY ACTIVITY · LAST 30 DAYS"
WIDE_NEW_HEADING = "DAILY ACTIVITY · 30-DAY EVIDENCE WINDOW"
COMPACT_OLD_HEADING = "DAILY ACTIVITY · 30 DAYS"
COMPACT_NEW_HEADING = "DAILY ACTIVITY · 30D EVIDENCE"
WIDE_OLD_FOOTER = "WINDOW · 30 UTC DAYS · LEVELS 0–4 · RAW COUNTS"
WIDE_NEW_FOOTER = "30D EVIDENCE · DIM CONTEXT · LEVELS 0–4 · RAW COUNTS"
OLD_DESC_CONTEXT = "for Monday-aligned context."
NEW_DESC_CONTEXT = "as dimmed Monday-aligned context."
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
    if viewbox == "0 0 640 425":
        return "wide"
    if viewbox == "0 0 320 500":
        return "compact"
    raise ValueError(f"unexpected Signal Field viewBox: {viewbox!r}")


def add_root_provenance(text: str) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing")
    tag = root.group(0)
    tag = set_attr(tag, "data-evidence-window-clarity", VERSION)
    tag = set_attr(tag, "data-calendar-context-visual", "dimmed")
    return text[: root.start()] + tag + text[root.end() :]


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise ValueError(f"expected exactly one {label}: {old!r}")
    return text.replace(old, new, 1)


def mark_calendar_roles(text: str) -> str:
    leading_matches = list(LEADING_RECT.finditer(text))
    leading_dates = {
        attrs_of(match.group("tag"))["data-date"] for match in leading_matches
    }
    leading_months = {
        attrs.get("data-month-boundary")
        for match in leading_matches
        if (attrs := attrs_of(match.group("tag"))).get("data-month-boundary")
    }

    def leading_repl(match: re.Match[str]) -> str:
        tag = set_attr(match.group("tag"), "opacity", CONTEXT_OPACITY)
        tag = set_attr(tag, "data-evidence-window-role", "context")
        return tag

    text = LEADING_RECT.sub(leading_repl, text)

    def measured_repl(match: re.Match[str]) -> str:
        return set_attr(match.group("tag"), "data-evidence-window-role", "measured")

    text = MEASURED_RECT.sub(measured_repl, text)

    def outside_repl(match: re.Match[str]) -> str:
        tag = set_attr(match.group("tag"), "opacity", OUTSIDE_OPACITY)
        tag = set_attr(tag, "data-evidence-window-role", "empty")
        return tag

    text = OUTSIDE_RECT.sub(outside_repl, text)

    def day_repl(match: re.Match[str]) -> str:
        tag = match.group("tag")
        if match.group("date") not in leading_dates:
            return tag
        tag = set_attr(tag, "opacity", CONTEXT_LABEL_OPACITY)
        return set_attr(tag, "data-evidence-context-label", "calendar-leading")

    text = DAY_LABEL.sub(day_repl, text)

    def month_repl(match: re.Match[str]) -> str:
        tag = match.group("tag")
        if match.group("month") not in leading_months:
            return tag
        tag = set_attr(tag, "opacity", CONTEXT_LABEL_OPACITY)
        return set_attr(tag, "data-evidence-context-label", "calendar-leading")

    return MONTH_LABEL.sub(month_repl, text)


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

    for tag in measured:
        if attrs_of(tag).get("data-evidence-window-role") != "measured":
            raise ValueError("measured evidence tile role missing")
    for tag in leading:
        tag_attrs = attrs_of(tag)
        if tag_attrs.get("data-evidence-window-role") != "context":
            raise ValueError("leading context role missing")
        if tag_attrs.get("opacity") != CONTEXT_OPACITY:
            raise ValueError("leading context opacity changed")
    for tag in outside:
        tag_attrs = attrs_of(tag)
        if tag_attrs.get("data-evidence-window-role") != "empty":
            raise ValueError("outside calendar role missing")
        if tag_attrs.get("opacity") != OUTSIDE_OPACITY:
            raise ValueError("outside calendar opacity changed")

    if leading:
        leading_dates = {attrs_of(tag)["data-date"] for tag in leading}
        label_count = 0
        for match in DAY_LABEL.finditer(text):
            if match.group("date") in leading_dates:
                label_count += 1
                tag_attrs = attrs_of(match.group("tag"))
                if tag_attrs.get("opacity") != CONTEXT_LABEL_OPACITY:
                    raise ValueError("leading context day label is not dimmed")
                if tag_attrs.get("data-evidence-context-label") != "calendar-leading":
                    raise ValueError("leading context day-label provenance missing")
        if label_count != len(leading_dates):
            raise ValueError("leading context day-label count changed")

    expected_heading = WIDE_NEW_HEADING if layout == "wide" else COMPACT_NEW_HEADING
    stale_heading = WIDE_OLD_HEADING if layout == "wide" else COMPACT_OLD_HEADING
    if text.count(expected_heading) != 1 or stale_heading in text:
        raise ValueError(f"{layout} evidence-window heading contract changed")

    if OLD_DESC_CONTEXT in text or text.count(NEW_DESC_CONTEXT) != 1:
        raise ValueError("accessible dimmed-context semantics changed")
    if layout == "wide":
        if text.count(WIDE_NEW_FOOTER) != 1 or WIDE_OLD_FOOTER in text:
            raise ValueError("wide evidence footer clarity contract changed")


def clarify_svg(text: str) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing")
    layout = layout_of(root.group(0))
    root_attrs = attrs_of(root.group(0))
    if root_attrs.get("data-evidence-window-clarity") == VERSION:
        validate(text, layout)
        return text
    if root_attrs.get("data-secondary-metric-balance") != PREVIOUS:
        raise ValueError("Signal Field v2.12 must exist before v2.13")

    if layout == "wide":
        text = replace_once(text, WIDE_OLD_HEADING, WIDE_NEW_HEADING, "wide activity heading")
        text = replace_once(text, WIDE_OLD_FOOTER, WIDE_NEW_FOOTER, "wide evidence footer")
    else:
        text = replace_once(text, COMPACT_OLD_HEADING, COMPACT_NEW_HEADING, "compact activity heading")

    text = replace_once(text, OLD_DESC_CONTEXT, NEW_DESC_CONTEXT, "accessible calendar-context phrase")
    text = mark_calendar_roles(text)
    text = add_root_provenance(text)
    validate(text, layout)
    return text


def fixture(layout: str) -> str:
    geometry = (
        'viewBox="0 0 640 425" width="640" height="425"'
        if layout == "wide"
        else 'viewBox="0 0 320 500" width="320" height="500"'
    )
    heading = WIDE_OLD_HEADING if layout == "wide" else COMPACT_OLD_HEADING
    footer = f'<text>{WIDE_OLD_FOOTER}</text>' if layout == "wide" else ""
    leading = []
    for day in range(1, 4):
        month = ' data-month-boundary="AUG"' if day == 1 else ""
        leading.append(
            f'<rect data-date="2026-08-0{day}" data-window-context="leading"{month}/>'
            f'<text data-day-label="2026-08-0{day}">0{day}</text>'
        )
    leading.insert(1, '<text data-month-boundary="AUG" opacity="1">AUG</text>')
    measured = ''.join(
        f'<rect data-date="2026-08-{day:02d}" data-window-day="{index}"/>'
        for index, day in enumerate(range(4, 34), start=1)
    )
    outside = '<rect opacity="0.38" data-slot-state="outside-window"/><rect opacity="0.38" data-slot-state="outside-window"/>'
    return (
        f'<svg {geometry} data-activity-window-days="30" data-activity-display-days="33" '
        f'data-secondary-metric-balance="{PREVIOUS}"><desc>calendar display includes 33 dated marks '
        f'from 2026-08-01 through 2026-09-02 for Monday-aligned context.</desc>'
        f'<text>{heading}</text>{"".join(leading)}{measured}{outside}{footer}</svg>'
    )


def self_test() -> None:
    for layout in ("wide", "compact"):
        transformed = clarify_svg(fixture(layout))
        validate(transformed, layout)
        if clarify_svg(transformed) != transformed:
            raise AssertionError("v2.13 transform must be idempotent")
        print(f"{layout} v2.13 evidence-window clarity fixture passed")
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
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError(
                "usage: clarify-signal-field-evidence-window.py <generated-directory> | --self-test"
            )
        apply(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
