#!/usr/bin/env python3
"""Relabel the visible GitHub Issues headline as BUGS FOUND without changing its data semantics.

The underlying metric remains the authored public GitHub Issues count supplied by the
pinned upstream generator. Only the visible presentation label changes; accessible
source wording remains explicit about GitHub Issues so the card stays attributable.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

VERSION = "signal-field-v2.10"
OLD_LABEL = "ISSUES"
NEW_LABEL = "BUGS FOUND"
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)


def relabel_svg(text: str) -> str:
    old_token = f">{OLD_LABEL}</text>"
    new_token = f">{NEW_LABEL}</text>"
    old_count = text.count(old_token)
    new_count = text.count(new_token)

    if old_count == 0 and new_count == 1 and f'data-metric-labels="{VERSION}"' in text:
        return text
    if old_count != 1 or new_count != 0:
        raise ValueError(
            f"expected exactly one visible {OLD_LABEL!r} metric label and no pre-existing {NEW_LABEL!r} label"
        )

    text = text.replace(old_token, new_token, 1)
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing")
    if "data-metric-labels=" in root.group(0):
        raise ValueError("unexpected pre-existing metric-label provenance")

    replacement = root.group(0)[:-1] + f' data-metric-labels="{VERSION}">'
    text = text[: root.start()] + replacement + text[root.end() :]

    if text.count(new_token) != 1 or old_token in text:
        raise ValueError("BUGS FOUND label rewrite did not converge")
    if text.count(f'data-metric-labels="{VERSION}"') != 1:
        raise ValueError("metric-label provenance is missing or duplicated")
    return text


def self_test() -> None:
    for layout in ("wide", "compact"):
        fixture = (
            f'<svg data-layout="{layout}"><text data-metric-phosphor="issues">33</text>'
            '<text x="10" y="20">ISSUES</text></svg>'
        )
        transformed = relabel_svg(fixture)
        assert ">BUGS FOUND</text>" in transformed
        assert ">ISSUES</text>" not in transformed
        assert f'data-metric-labels="{VERSION}"' in transformed
        assert relabel_svg(transformed) == transformed

    try:
        relabel_svg("<svg><text>STARS</text></svg>")
    except ValueError:
        pass
    else:
        raise AssertionError("missing Issues label must fail closed")

    print(f"Signal Field metric-label self-test passed: {VERSION}; ISSUES -> BUGS FOUND")


def apply(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        path.write_text(relabel_svg(path.read_text(encoding="utf-8")), encoding="utf-8")
        print(f"relabeled {filename}: {OLD_LABEL} -> {NEW_LABEL}")


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
