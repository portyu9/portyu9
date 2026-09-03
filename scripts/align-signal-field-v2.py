#!/usr/bin/env python3
"""Apply deterministic Signal Field v2.5 layout corrections.

This layer runs after v2.4. It owns two presentation-only corrections:
- wide/month-boundary day numbers are centered like all other day numbers while
  their small AUG/SEP marker remains independently positioned
- the wide ISSUES block is right-aligned to the 610px content edge; compact/mobile
  metric alignment is intentionally untouched

The transformation fails closed if the expected generated geometry changes.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
import re
import sys

LAYOUT_ID = "signal-field-v2.5"
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)

SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
MONTH_TILE = re.compile(
    r'<rect\b[^>]*\bdata-date="(\d{4}-\d{2}-\d{2})"[^>]*\bdata-month-boundary="[A-Z]{3}"[^>]*/>',
    re.I,
)
DAY_LABEL = re.compile(
    r'<text\b[^>]*\bdata-day-label="(\d{4}-\d{2}-\d{2})"[^>]*>[^<]+</text>',
    re.I,
)

WIDE_ISSUES_DIVIDER = '<path d="M496 73h86"'
WIDE_ISSUES_VALUE = '<text x="496" y="108"'
WIDE_ISSUES_LABEL = '<text x="496" y="132"'
TARGET_ISSUES_DIVIDER = '<path d="M524 73h86"'
TARGET_ISSUES_VALUE = '<text x="610" y="108" text-anchor="end"'
TARGET_ISSUES_LABEL = '<text x="610" y="132" text-anchor="end"'


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
    index = element.find(">")
    if index < 0:
        raise ValueError(f"cannot add attribute {name!r} to malformed element")
    return element[:index] + f' {replacement}' + element[index:]


def add_provenance(text: str) -> str:
    match = SVG_OPEN.search(text)
    if not match:
        raise ValueError("SVG root element is missing")
    if "data-metric-layout=" in match.group(0):
        raise ValueError("Signal Field unexpectedly already contains v2.5 layout provenance")
    attrs = match.group(1)
    replacement = f'<svg{attrs} data-metric-layout="{LAYOUT_ID}">'
    return text[:match.start()] + replacement + text[match.end():]


def center_wide_month_days(text: str) -> str:
    tiles = MONTH_TILE.findall(text)
    if not tiles:
        raise ValueError("wide calendar must contain month-boundary tiles")

    for current_date in tiles:
        rect_match = re.search(
            rf'<rect\b[^>]*\bdata-date="{re.escape(current_date)}"[^>]*/>', text, re.I
        )
        if not rect_match:
            raise ValueError(f"month-boundary tile missing for {current_date}")
        rect_attrs = attrs_of(rect_match.group(0))
        for required in ("x", "width"):
            if required not in rect_attrs:
                raise ValueError(f"month-boundary tile missing {required}: {current_date}")
        center_x = float(rect_attrs["x"]) + float(rect_attrs["width"]) / 2

        label_match = re.search(
            rf'<text\b[^>]*\bdata-day-label="{re.escape(current_date)}"[^>]*>[^<]+</text>',
            text,
            re.I,
        )
        if not label_match:
            raise ValueError(f"month-boundary day label missing for {current_date}")
        label = set_attr(label_match.group(0), "x", f"{center_x:g}")
        label = set_attr(label, "text-anchor", "middle")
        label = set_attr(label, "data-day-alignment", "centered-month-boundary")
        text = text[:label_match.start()] + label + text[label_match.end():]

    return text


def right_align_wide_issues(text: str) -> str:
    signatures = (
        (WIDE_ISSUES_DIVIDER, TARGET_ISSUES_DIVIDER),
        (WIDE_ISSUES_VALUE, TARGET_ISSUES_VALUE),
        (WIDE_ISSUES_LABEL, TARGET_ISSUES_LABEL),
    )
    for old, new in signatures:
        if text.count(old) != 1:
            raise ValueError(f"wide ISSUES geometry signature changed: {old}")
        text = text.replace(old, new, 1)
    return text


def validate_wide(text: str) -> None:
    if f'data-metric-layout="{LAYOUT_ID}"' not in text:
        raise ValueError("v2.5 metric-layout provenance is missing")
    for old in (WIDE_ISSUES_DIVIDER, WIDE_ISSUES_VALUE, WIDE_ISSUES_LABEL):
        if old in text:
            raise ValueError(f"legacy wide ISSUES position remains: {old}")
    for new in (TARGET_ISSUES_DIVIDER, TARGET_ISSUES_VALUE, TARGET_ISSUES_LABEL):
        if text.count(new) != 1:
            raise ValueError(f"target wide ISSUES alignment is missing: {new}")

    month_dates = MONTH_TILE.findall(text)
    if not month_dates:
        raise ValueError("month-boundary tiles disappeared after v2.5")
    for current_date in month_dates:
        label_match = re.search(
            rf'<text\b[^>]*\bdata-day-label="{re.escape(current_date)}"[^>]*>[^<]+</text>',
            text,
            re.I,
        )
        if not label_match:
            raise ValueError(f"month day label disappeared: {current_date}")
        attrs = attrs_of(label_match.group(0))
        if attrs.get("text-anchor") != "middle":
            raise ValueError(f"month day must be centered: {current_date}")
        if attrs.get("data-day-alignment") != "centered-month-boundary":
            raise ValueError(f"month day centering provenance missing: {current_date}")


def align_svg(text: str, layout: str) -> str:
    if layout == "compact":
        return text
    if layout != "wide":
        raise ValueError(f"unsupported layout: {layout}")
    aligned = center_wide_month_days(text)
    aligned = right_align_wide_issues(aligned)
    aligned = add_provenance(aligned)
    validate_wide(aligned)
    return aligned


def align_directory(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        layout = layout_for(path)
        original = path.read_text(encoding="utf-8")
        aligned = align_svg(original, layout)
        if layout == "compact" and aligned != original:
            raise ValueError("compact Signal Field must remain unchanged by v2.5")
        path.write_text(aligned, encoding="utf-8")
        print(f"aligned {filename} -> {LAYOUT_ID if layout == 'wide' else 'unchanged compact'}")


def fixture(layout: str) -> str:
    if layout == "compact":
        return (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 500">'
            '<text x="254" y="206" text-anchor="middle">32</text>'
            '<text x="254" y="227" text-anchor="middle">ISSUES</text></svg>'
        )
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 425">'
        '<path d="M496 73h86" stroke="#28324A"/>'
        '<text x="496" y="108" fill="#F8FAFC">32</text>'
        '<text x="496" y="132" fill="#A7B0C4">ISSUES</text>'
        '<rect x="286" y="225" width="56" height="21" rx="5" fill="#A020F0" '
        'data-date="2026-08-05" data-count="3" data-level="2" data-month-boundary="AUG"/>'
        '<text x="337" y="240" text-anchor="end" data-day-label="2026-08-05">05</text>'
        '<rect x="208" y="325" width="56" height="21" rx="5" fill="#00AEEF" '
        'data-date="2026-09-01" data-count="8" data-level="4" data-month-boundary="SEP"/>'
        '<text x="259" y="340" text-anchor="end" data-day-label="2026-09-01">01</text>'
        '</svg>'
    )


def self_test() -> None:
    wide = align_svg(fixture("wide"), "wide")
    validate_wide(wide)
    assert '<path d="M524 73h86"' in wide
    assert '<text x="610" y="108" text-anchor="end"' in wide
    assert '<text x="610" y="132" text-anchor="end"' in wide
    assert 'x="314"' in wide and 'data-day-label="2026-08-05"' in wide
    assert 'x="236"' in wide and 'data-day-label="2026-09-01"' in wide

    compact = fixture("compact")
    assert align_svg(compact, "compact") == compact
    assert "data-metric-layout=" not in compact

    print(f"Signal Field layout alignment self-test passed: {LAYOUT_ID}")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError(
                "usage: align-signal-field-v2.py <generated-directory> | --self-test"
            )
        align_directory(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
