#!/usr/bin/env python3
"""Relabel the visible GitHub Issues headline as BUGS FOUND without changing its data semantics.

The underlying metric remains exactly the authored public GitHub Issues total supplied
by the SHA-pinned upstream REST Search collector. This stage changes presentation only:
ISSUES -> BUGS FOUND. It records that alias explicitly, proves the numeric Issues value
is unchanged across the rewrite, preserves the accessible GitHub Issues description,
and removes the stale upstream ``data-period-days=365`` attribute now that v2.9 owns the
exact GitHub ContributionsCollection period.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

VERSION = "signal-field-v2.10"
OLD_LABEL = "ISSUES"
NEW_LABEL = "BUGS FOUND"
ISSUE_SOURCE = "github-rest-search-authored-public-issues"
ISSUE_DISPLAY_ALIAS = "bugs-found"
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ISSUE_VALUE = re.compile(
    r'<text\b(?=[^>]*\bdata-metric-phosphor="issues")[^>]*>([\d,]+)</text>',
    re.I,
)
ACCESSIBLE_ISSUES = re.compile(
    r'([\d,]+) authored public issues reported by GitHub REST Search',
    re.I,
)


def set_attr(tag: str, name: str, value: str) -> str:
    pattern = re.compile(rf'\b{re.escape(name)}="[^"]*"')
    replacement = f'{name}="{value}"'
    if pattern.search(tag):
        return pattern.sub(replacement, tag, count=1)
    return tag[:-1] + f' {replacement}>'


def remove_attr(tag: str, name: str) -> str:
    return re.sub(rf'\s+{re.escape(name)}="[^"]*"', "", tag, count=1)


def issue_count(text: str) -> str:
    values = ISSUE_VALUE.findall(text)
    if len(values) != 1:
        raise ValueError("expected exactly one authored public Issues metric value")
    accessible = ACCESSIBLE_ISSUES.findall(text)
    if len(accessible) != 1:
        raise ValueError("accessible GitHub Issues source semantics are missing or duplicated")
    if accessible[0] != values[0]:
        raise ValueError("visible Issues metric diverges from accessible GitHub REST Search total")
    return values[0]


def normalize_root_provenance(text: str) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing")
    root_tag = root.group(0)
    root_tag = remove_attr(root_tag, "data-period-days")
    root_tag = set_attr(root_tag, "data-metric-labels", VERSION)
    root_tag = set_attr(root_tag, "data-issues-metric-source", ISSUE_SOURCE)
    root_tag = set_attr(root_tag, "data-issues-display-alias", ISSUE_DISPLAY_ALIAS)
    return text[: root.start()] + root_tag + text[root.end() :]


def validate_semantics(text: str, expected_count: str) -> None:
    if issue_count(text) != expected_count:
        raise ValueError("BUGS FOUND relabel changed the underlying authored public Issues total")
    if text.count(f'data-metric-labels="{VERSION}"') != 1:
        raise ValueError("metric-label provenance is missing or duplicated")
    if text.count(f'data-issues-metric-source="{ISSUE_SOURCE}"') != 1:
        raise ValueError("authored public Issues source provenance is missing or duplicated")
    if text.count(f'data-issues-display-alias="{ISSUE_DISPLAY_ALIAS}"') != 1:
        raise ValueError("BUGS FOUND display-alias provenance is missing or duplicated")
    if "data-period-days=" in text:
        raise ValueError("stale upstream data-period-days provenance must be removed")


def relabel_svg(text: str) -> str:
    old_token = f">{OLD_LABEL}</text>"
    new_token = f">{NEW_LABEL}</text>"
    old_count = text.count(old_token)
    new_count = text.count(new_token)
    original_issue_count = issue_count(text)

    if old_count == 0 and new_count == 1 and f'data-metric-labels="{VERSION}"' in text:
        text = normalize_root_provenance(text)
        validate_semantics(text, original_issue_count)
        return text
    if old_count != 1 or new_count != 0:
        raise ValueError(
            f"expected exactly one visible {OLD_LABEL!r} metric label and no pre-existing {NEW_LABEL!r} label"
        )

    text = text.replace(old_token, new_token, 1)
    text = normalize_root_provenance(text)

    if text.count(new_token) != 1 or old_token in text:
        raise ValueError("BUGS FOUND label rewrite did not converge")
    validate_semantics(text, original_issue_count)
    return text


def self_test() -> None:
    for layout in ("wide", "compact"):
        fixture = (
            f'<svg data-layout="{layout}" data-period-days="365">'
            '<desc>5,030 contributions in the past year; 14 stars; 480 authored public pull requests '
            'reported by GitHub REST Search; 33 authored public issues reported by GitHub REST Search.</desc>'
            '<text data-metric-phosphor="issues">33</text>'
            '<text x="10" y="20">ISSUES</text></svg>'
        )
        transformed = relabel_svg(fixture)
        assert ">BUGS FOUND</text>" in transformed
        assert ">ISSUES</text>" not in transformed
        assert f'data-metric-labels="{VERSION}"' in transformed
        assert f'data-issues-metric-source="{ISSUE_SOURCE}"' in transformed
        assert f'data-issues-display-alias="{ISSUE_DISPLAY_ALIAS}"' in transformed
        assert "data-period-days=" not in transformed
        assert '<text data-metric-phosphor="issues">33</text>' in transformed
        assert "33 authored public issues reported by GitHub REST Search" in transformed
        assert relabel_svg(transformed) == transformed

    try:
        relabel_svg("<svg><text>STARS</text></svg>")
    except ValueError:
        pass
    else:
        raise AssertionError("missing Issues metric/source semantics must fail closed")

    print(
        f"Signal Field metric-label self-test passed: {VERSION}; visible ISSUES -> BUGS FOUND; "
        "underlying authored public GitHub Issues total unchanged"
    )


def apply(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        path.write_text(relabel_svg(path.read_text(encoding="utf-8")), encoding="utf-8")
        print(f"relabeled {filename}: {OLD_LABEL} -> {NEW_LABEL}; Issues total preserved")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError("usage: relabel-signal-field-metrics.py <generated-directory> | --self-test")
        apply(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
