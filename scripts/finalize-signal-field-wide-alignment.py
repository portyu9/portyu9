#!/usr/bin/env python3
"""Finalize desktop Signal Field metric alignment without changing evidence semantics.

v2.18 keeps the v2.17 EID clearance, preserves Pull Requests byte-for-byte, and fixes
the remaining Stars geometry by mirroring the already-reviewed Pull Requests layout:

- the Stars rule still starts at x=284;
- the star glyph is optically anchored to the rule start (same +6.25 center offset as
  the Pull Requests glyph uses from its own rule start);
- the Stars value and label are optically centered at x=320 to the right of that glyph;
- the visible EID remains 8 SVG units above its v2.14 base geometry.

Compact/mobile variants are validation-only and must remain untouched.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

VERSION = "signal-field-v2.18"
ROOT_ATTR = "data-wide-detail-alignment"
WIDE_FILES = ("signal-field-wide-light.svg", "signal-field-wide-dark.svg")
COMPACT_FILES = ("signal-field-compact-light.svg", "signal-field-compact-dark.svg")
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
STAR_LINE = re.compile(r'(?P<tag><path\b(?=[^>]*data-metric-phosphor-line="stars")[^>]*>)', re.I)
STAR_VALUE = re.compile(r'(?P<tag><text\b(?=[^>]*data-metric-phosphor="stars")[^>]*>)(?P<value>[\d,]+)</text>', re.I)
STAR_LABEL = re.compile(r'(?P<tag><text\b[^>]*>)STARS</text>', re.I)
STAR_GLYPH = re.compile(
    r'(?P<glyph><g\b(?=[^>]*data-metric-glyph="stars")[^>]*>.*?</g>)',
    re.I | re.S,
)
EID = re.compile(
    r'(?P<tag><text\b(?=[^>]*data-signal-field-evidence-id="true")[^>]*>)(?P<value>EID · SF1-[0-9A-F]{16})</text>',
    re.I,
)
PULL_VALUE = re.compile(r'<text\b(?=[^>]*data-metric-phosphor="pull_requests")[^>]*>[\d,]+</text>', re.I)
PULL_LABEL = re.compile(r'<text\b[^>]*>PULL REQUESTS</text>', re.I)
PULL_LINE = re.compile(r'<path\b(?=[^>]*data-metric-phosphor-line="pull_requests")[^>]*>', re.I)
PULL_GLYPH = re.compile(r'<g\b(?=[^>]*data-metric-glyph="pull_requests")[^>]*>', re.I)

STAR_LINE_D = "M284 73h86"
STAR_VALUE_X = "320"
STAR_LABEL_X = "320"
STAR_WRAPPER_TRANSFORM = "translate(20 1.5)"
STAR_WRAPPER = (
    '<g data-wide-star-optical-alignment="true" '
    f'transform="{STAR_WRAPPER_TRANSFORM}">{{glyph}}</g>'
)
EID_TRANSFORM = "translate(0 -8)"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def attrs_of(tag: str) -> dict[str, str]:
    return dict(ATTR.findall(tag))


def set_attr(tag: str, name: str, value: str) -> str:
    pattern = re.compile(rf'\b{re.escape(name)}="[^"]*"')
    replacement = f'{name}="{value}"'
    if pattern.search(tag):
        return pattern.sub(replacement, tag, count=1)
    close = tag.rfind(">")
    require(close >= 0, f"malformed element while setting {name}")
    return tag[:close] + f' {replacement}' + tag[close:]


def one(pattern: re.Pattern[str], text: str, label: str) -> re.Match[str]:
    matches = list(pattern.finditer(text))
    require(len(matches) == 1, f"expected exactly one {label}, found {len(matches)}")
    return matches[0]


def pull_signature(text: str) -> tuple[str, str, str, str]:
    return (
        one(PULL_LINE, text, "Pull Requests rule").group(0),
        one(PULL_GLYPH, text, "Pull Requests glyph").group(0),
        one(PULL_VALUE, text, "Pull Requests value").group(0),
        one(PULL_LABEL, text, "Pull Requests label").group(0),
    )


def validate_wide(text: str, name: str) -> None:
    root = one(SVG_OPEN, text, "SVG root")
    root_attrs = attrs_of(root.group(0))
    require(root_attrs.get("viewBox") == "0 0 640 425", f"{name}: wide viewBox changed")
    require(root_attrs.get("data-issues-label-balance") == "signal-field-v2.16", f"{name}: v2.16 must precede v2.18")
    require(root_attrs.get("data-generation-cadence-contract") == "profile-refresh-v1", f"{name}: cadence finalizer must precede v2.18")
    require(root_attrs.get(ROOT_ATTR) == VERSION, f"{name}: v2.18 provenance missing")

    line = attrs_of(one(STAR_LINE, text, "Stars rule").group("tag"))
    require(line.get("d") == STAR_LINE_D, f"{name}: Stars rule start changed")

    value = attrs_of(one(STAR_VALUE, text, "Stars value").group("tag"))
    label = attrs_of(one(STAR_LABEL, text, "STARS label").group("tag"))
    require(
        value.get("x") == STAR_VALUE_X and value.get("text-anchor") == "middle",
        f"{name}: Stars value must be centered at x={STAR_VALUE_X}",
    )
    require(
        label.get("x") == STAR_LABEL_X and label.get("text-anchor") == "middle",
        f"{name}: STARS label must be centered at x={STAR_LABEL_X}",
    )

    glyph = one(STAR_GLYPH, text, "Stars glyph")
    prefix = text[max(0, glyph.start() - 130):glyph.start()]
    require('data-wide-star-optical-alignment="true"' in prefix, f"{name}: Stars alignment wrapper missing")
    require(f'transform="{STAR_WRAPPER_TRANSFORM}"' in prefix, f"{name}: Stars horizontal/vertical alignment changed")
    inner = attrs_of(glyph.group("glyph").split(">", 1)[0] + ">")
    require(
        inner.get("transform") == "translate(270.25 98.90) scale(1.4583)",
        f"{name}: reviewed inner Stars glyph geometry changed",
    )

    eid = one(EID, text, "visible Evidence ID")
    eid_attrs = attrs_of(eid.group("tag"))
    require(eid_attrs.get("x") == "320" and eid_attrs.get("y") == "391", f"{name}: base EID geometry must stay compatible with v2.14")
    require(eid_attrs.get("text-anchor") == "middle", f"{name}: EID anchor changed")
    require(eid_attrs.get("transform") == EID_TRANSFORM, f"{name}: EID must remain 8 units above its base position")
    require(eid_attrs.get("data-wide-eid-clearance") == "true", f"{name}: EID clearance provenance missing")


def validate_compact(text: str, name: str) -> None:
    root = one(SVG_OPEN, text, "SVG root")
    attrs = attrs_of(root.group(0))
    require(attrs.get("viewBox") == "0 0 320 500", f"{name}: compact viewBox changed")
    require(ROOT_ATTR not in attrs, f"{name}: desktop-only provenance leaked into compact output")
    require('data-wide-star-optical-alignment="true"' not in text, f"{name}: desktop Stars wrapper leaked into compact output")
    eid = one(EID, text, "visible Evidence ID")
    require("transform" not in attrs_of(eid.group("tag")), f"{name}: desktop EID transform leaked into compact output")


def transform_wide(text: str, name: str) -> str:
    root = one(SVG_OPEN, text, "SVG root")
    root_attrs = attrs_of(root.group(0))
    if root_attrs.get(ROOT_ATTR) == VERSION:
        validate_wide(text, name)
        return text
    require(ROOT_ATTR not in root_attrs, f"{name}: unexpected pre-existing desktop alignment provenance")
    require(root_attrs.get("viewBox") == "0 0 640 425", f"{name}: expected wide Signal Field")
    require(root_attrs.get("data-issues-label-balance") == "signal-field-v2.16", f"{name}: v2.16 must precede v2.18")
    require(root_attrs.get("data-generation-cadence-contract") == "profile-refresh-v1", f"{name}: cadence finalizer must precede v2.18")

    before_pull = pull_signature(text)

    root_tag = set_attr(root.group(0), ROOT_ATTR, VERSION)
    text = text[:root.start()] + root_tag + text[root.end():]

    glyph = one(STAR_GLYPH, text, "Stars glyph")
    prefix = text[max(0, glyph.start() - 130):glyph.start()]
    require('data-wide-star-optical-alignment="true"' not in prefix, f"{name}: Stars glyph is already wrapped without v2.18 provenance")
    wrapped = STAR_WRAPPER.format(glyph=glyph.group("glyph"))
    text = text[:glyph.start()] + wrapped + text[glyph.end():]

    value = one(STAR_VALUE, text, "Stars value")
    value_tag = set_attr(value.group("tag"), "x", STAR_VALUE_X)
    value_tag = set_attr(value_tag, "text-anchor", "middle")
    text = text[:value.start("tag")] + value_tag + text[value.end("tag"):]

    label = one(STAR_LABEL, text, "STARS label")
    label_tag = set_attr(label.group("tag"), "x", STAR_LABEL_X)
    label_tag = set_attr(label_tag, "text-anchor", "middle")
    text = text[:label.start("tag")] + label_tag + text[label.end("tag"):]

    eid = one(EID, text, "visible Evidence ID")
    eid_tag = set_attr(eid.group("tag"), "transform", EID_TRANSFORM)
    eid_tag = set_attr(eid_tag, "data-wide-eid-clearance", "true")
    text = text[:eid.start("tag")] + eid_tag + text[eid.end("tag"):]

    require(pull_signature(text) == before_pull, f"{name}: Pull Requests geometry changed; v2.18 must not touch it")
    validate_wide(text, name)
    return text


def self_test() -> None:
    wide = (
        '<svg viewBox="0 0 640 425" data-issues-label-balance="signal-field-v2.16" data-generation-cadence-contract="profile-refresh-v1">'
        '<path d="M284 73h86" data-metric-phosphor-line="stars"/>'
        '<g data-metric-glyph="stars" transform="translate(270.25 98.90) scale(1.4583)"><path/></g>'
        '<text x="284" y="108" data-metric-phosphor="stars">14</text><text x="284" y="132">STARS</text>'
        '<path d="M404 73h86" data-metric-phosphor-line="pull_requests"/>'
        '<g data-metric-glyph="pull_requests" transform="translate(410.24 98.90) scale(1.4583)"></g>'
        '<text x="447" y="108" text-anchor="middle" data-metric-phosphor="pull_requests">558</text><text x="447" y="132" text-anchor="middle">PULL REQUESTS</text>'
        '<text x="320" y="391" text-anchor="middle" data-signal-field-evidence-id="true">EID · SF1-0123456789ABCDEF</text></svg>'
    )
    transformed = transform_wide(wide, "fixture-wide.svg")
    require(transform_wide(transformed, "fixture-wide.svg") == transformed, "v2.18 wide transform must be idempotent")
    require(f'transform="{STAR_WRAPPER_TRANSFORM}"' in transformed, "self-test Stars rule-start alignment missing")
    require(f'x="{STAR_VALUE_X}"' in transformed and 'text-anchor="middle"' in transformed, "self-test Stars value alignment missing")
    require('transform="translate(0 -8)"' in transformed, "self-test EID shift missing")

    compact = (
        '<svg viewBox="0 0 320 500"><text x="160" y="463" text-anchor="middle" '
        'data-signal-field-evidence-id="true">EID · SF1-0123456789ABCDEF</text></svg>'
    )
    validate_compact(compact, "fixture-compact.svg")
    print(f"Signal Field desktop alignment self-test passed: {VERSION}")


def apply(directory: Path, check_only: bool) -> None:
    for filename in WIDE_FILES:
        path = directory / filename
        require(path.is_file() and path.stat().st_size > 0, f"missing generated Signal Field artifact: {filename}")
        text = path.read_text(encoding="utf-8")
        if check_only:
            validate_wide(text, filename)
        else:
            path.write_text(transform_wide(text, filename), encoding="utf-8")
        print(f"{'validated' if check_only else 'aligned'} {filename}: desktop EID/Stars detail contract")

    for filename in COMPACT_FILES:
        path = directory / filename
        require(path.is_file() and path.stat().st_size > 0, f"missing generated Signal Field artifact: {filename}")
        validate_compact(path.read_text(encoding="utf-8"), filename)
        print(f"validated {filename}: compact bytes remain outside desktop alignment contract")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", nargs="?", type=Path)
    parser.add_argument("--check", action="store_true", help="validate v2.18 without mutating candidate bytes")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.self_test:
            require(args.directory is None and not args.check, "--self-test cannot be combined with a directory/--check")
            self_test()
            return 0
        require(args.directory is not None, "usage: finalize-signal-field-wide-alignment.py <directory> [--check] | --self-test")
        apply(args.directory, args.check)
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
