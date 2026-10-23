#!/usr/bin/env python3
"""Project the already-validated Signal Field into independent five-minute cadence.

The existing governed eleven-subject publication remains immutable. This module
may change only four presentation-only cadence strings, never measured evidence
or Signal Field Evidence IDs. The inverse projection proves all other bytes are
identical to the validated upstream candidate.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys
import tempfile
import xml.etree.ElementTree as ET

FILES = tuple(
    f"signal-field-{layout}-{theme}.svg"
    for layout in ("wide", "compact")
    for theme in ("light", "dark")
)
COMMON = (
    ('data-generation-schedule="1-hour"', 'data-generation-schedule="5-minutes"'),
    ('data-generation-cadence-contract="profile-refresh-v2"',
     'data-generation-cadence-contract="independent-activity-v1"'),
    ('Generation refresh: every hour; execution and README cache propagation are best-effort.',
     'Generation refresh: every five minutes (best effort); execution and README cache propagation are not guaranteed.'),
)
FOOTERS = {
    "wide": (
        "SOURCES · GITHUB GRAPHQL + REST · REFRESH · 1 HR",
        "SOURCES · GITHUB GRAPHQL + REST · REFRESH · 5 MIN",
    ),
    "compact": (
        "GITHUB API · GRAPHQL + REST · REFRESH · 1 HR",
        "GITHUB API · GRAPHQL + REST · REFRESH · 5 MIN",
    ),
}
EVIDENCE_ID = re.compile(r'data-evidence-id="([^"]+)"')


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def projection_pairs(name: str) -> tuple[tuple[str, str], ...]:
    layout = "wide" if "-wide-" in name else "compact" if "-compact-" in name else None
    require(layout is not None and name in FILES, f"unexpected SVG subject: {name}")
    return (*COMMON, FOOTERS[layout])


def project(original: str, name: str) -> str:
    result = original
    for old, new in projection_pairs(name):
        require(result.count(old) == 1 and new not in result,
                f"{name}: source cadence projection authority changed: {old!r}")
        result = result.replace(old, new, 1)
    reconstructed = result
    for old, new in reversed(projection_pairs(name)):
        require(reconstructed.count(new) == 1 and old not in reconstructed,
                f"{name}: projection is not uniquely reversible")
        reconstructed = reconstructed.replace(new, old, 1)
    require(reconstructed == original, f"{name}: unrelated Signal Field bytes changed")
    require(EVIDENCE_ID.findall(original) == EVIDENCE_ID.findall(result),
            f"{name}: Signal Field Evidence ID changed")
    ET.fromstring(result)
    return result


def render(directory: Path) -> None:
    require(directory.is_dir() and not directory.is_symlink(), "candidate directory is missing or aliased")
    found = sorted(path.name for path in directory.iterdir())
    require(found == sorted(FILES), f"activity metrics subject inventory changed: {found}")
    source = {}
    for name in FILES:
        path = directory / name
        require(path.is_file() and not path.is_symlink(), f"unreviewed SVG input type: {name}")
        source[name] = path.read_text(encoding="utf-8")
    projections = {name: project(data, name) for name, data in source.items()}
    for name, data in projections.items():
        (directory / name).write_text(data, encoding="utf-8")
    print(f"Independent activity projection validated: {len(projections)} SVGs, five-minute best-effort cadence")


def self_test() -> None:
    for name in FILES:
        root = '<svg xmlns="http://www.w3.org/2000" data-evidence-id="SF1-AAAA" '
        sample = root + ' '.join(old for old, _new in COMMON[:2]) + '>'
        sample += '<desc>' + COMMON[2][0] + '</desc><text>' + projection_pairs(name)[-1][0] + '</text></svg>'
        result = project(sample, name)
        require('SF1-AAAA' in result and 'REFRESH · 5 MIN' in result, f"{name}: projection self-test failed")
        for corrupt in (sample + sample, sample.replace("1-hour", "2-hour")):
            try:
                project(corrupt, name)
            except (ValueError, ET.ParseError):
                pass
            else:
                raise ValueError(f"{name}: invalid projection unexpectedly passed")
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch)
        for name in FILES:
            sample = '<svg xmlns="http://www.w3.org/2000" data-evidence-id="SF1-AAAA" '
            sample += ' '.join(old for old, _new in COMMON[:2]) + '>'
            sample += '<desc>' + COMMON[2][0] + '</desc><text>' + projection_pairs(name)[-1][0] + '</text></svg>'
            (root / name).write_text(sample, encoding="utf-8")
        render(root)
        require(len(list(root.glob("*.svg"))) == 4, "render changed exact subject count")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            require(args.directory is None, "--self-test cannot take a directory")
            self_test()
            return 0
        require(args.directory is not None, "validated Signal Field directory is required")
        render(args.directory)
        return 0
    except (ValueError, OSError, ET.ParseError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
