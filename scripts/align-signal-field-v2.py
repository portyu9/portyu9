#!/usr/bin/env python3
"""Apply a deterministic desktop-only metric alignment refinement to Signal Field.

This layer runs after the existing v2.4 portal treatment. It intentionally changes
only the wide layout: the ISSUES metric block moves 16 SVG units to the right so
its spacing from PULL REQUESTS is visually balanced. Compact/mobile artifacts are
left byte-for-byte unchanged by this layer.
"""

from __future__ import annotations

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
WIDE_ISSUES_DIVIDER = '<path d="M496 73h86"'
WIDE_ISSUES_VALUE = '<text x="496" y="108"'
WIDE_ISSUES_LABEL = '<text x="496" y="132"'
TARGET_ISSUES_DIVIDER = '<path d="M512 73h86"'
TARGET_ISSUES_VALUE = '<text x="512" y="108"'
TARGET_ISSUES_LABEL = '<text x="512" y="132"'


def layout_for(path: Path) -> str:
    if "-wide-" in path.name:
        return "wide"
    if "-compact-" in path.name:
        return "compact"
    raise ValueError(f"unsupported Signal Field layout: {path.name}")


def add_provenance(text: str) -> str:
    match = SVG_OPEN.search(text)
    if not match:
        raise ValueError("SVG root element is missing")
    if "data-metric-layout=" in match.group(0):
        raise ValueError("Signal Field unexpectedly already contains v2.5 layout provenance")
    attrs = match.group(1)
    replacement = f'<svg{attrs} data-metric-layout="{LAYOUT_ID}">'
    return text[:match.start()] + replacement + text[match.end():]


def align_wide_issues(text: str) -> str:
    signatures = (
        (WIDE_ISSUES_DIVIDER, TARGET_ISSUES_DIVIDER),
        (WIDE_ISSUES_VALUE, TARGET_ISSUES_VALUE),
        (WIDE_ISSUES_LABEL, TARGET_ISSUES_LABEL),
    )
    for old, new in signatures:
        if text.count(old) != 1:
            raise ValueError(f"wide ISSUES geometry signature changed: {old}")
        text = text.replace(old, new, 1)
    return add_provenance(text)


def validate_wide(text: str) -> None:
    if f'data-metric-layout="{LAYOUT_ID}"' not in text:
        raise ValueError("v2.5 metric-layout provenance is missing")
    for old in (WIDE_ISSUES_DIVIDER, WIDE_ISSUES_VALUE, WIDE_ISSUES_LABEL):
        if old in text:
            raise ValueError(f"legacy wide ISSUES position remains: {old}")
    for new in (TARGET_ISSUES_DIVIDER, TARGET_ISSUES_VALUE, TARGET_ISSUES_LABEL):
        if text.count(new) != 1:
            raise ValueError(f"target wide ISSUES position is missing: {new}")


def align_svg(text: str, layout: str) -> str:
    if layout == "compact":
        return text
    if layout != "wide":
        raise ValueError(f"unsupported layout: {layout}")
    aligned = align_wide_issues(text)
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
        return '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 320 500"><text x="250" y="80">32</text><text x="250" y="100">ISSUES</text></svg>'
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 640 425">'
        '<path d="M496 73h86" stroke="#28324A"/>'
        '<text x="496" y="108" fill="#F8FAFC">32</text>'
        '<text x="496" y="132" fill="#A7B0C4">ISSUES</text>'
        '</svg>'
    )


def self_test() -> None:
    wide = align_svg(fixture("wide"), "wide")
    validate_wide(wide)
    assert '<text x="512" y="108"' in wide
    assert '<text x="512" y="132"' in wide

    compact = fixture("compact")
    assert align_svg(compact, "compact") == compact
    assert "data-metric-layout=" not in compact

    print(f"Signal Field metric alignment self-test passed: {LAYOUT_ID}")


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
