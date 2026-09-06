#!/usr/bin/env python3
"""Finalize Signal Field v2.15 evidence presentation after v2.14 identity stamping.

This pass changes presentation only. It preserves measured counts, contribution levels,
30-day membership, Evidence ID/digest, metric values, source provenance, and the
BUG FOUND display alias for the authored-public GitHub Issues metric while:
- encoding leading calendar context with an outline instead of opacity,
- restoring maximum-contrast month markers,
- simplifying the latest-day state to one outer ring, and
- replacing implementation wording DIM CONTEXT with LEADING CONTEXT.

The transform is idempotent and fails closed on unexpected final-artifact structure.
The read-only validation path also recognizes the reviewed profile-refresh-v2 successor,
which changes only the latest/current-day outer ring to fixed phosphorescent red.
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

VERSION = "signal-field-v2.15"
PREVIOUS = "signal-field-v2.14"
FINAL_REFRESH = "profile-refresh-v2"
FINAL_CURRENT_DAY = "phosphorescent-red-v1"
FINAL_LATEST_COLOR = "#FF335F"
FINAL_LATEST_OPACITY = "0.96"
EXPECTED_FILES = tuple(
    f"signal-field-{layout}-{theme}.svg"
    for layout in ("wide", "compact")
    for theme in ("light", "dark")
)

SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
CONTEXT_RECT = re.compile(
    r'(?P<tag><rect\b(?=[^>]*\bdata-evidence-window-role="context")[^>]*/>)', re.I
)
CONTEXT_DAY = re.compile(
    r'(?P<tag><text\b(?=[^>]*\bdata-evidence-context-label="calendar-leading")'
    r'(?=[^>]*\bdata-day-label="\d{4}-\d{2}-\d{2}")[^>]*>)', re.I
)
MONTH_LABEL = re.compile(
    r'(?P<tag><text\b(?=[^>]*\bdata-month-boundary="[A-Z]{3}")[^>]*>)', re.I
)
LATEST_TILE = re.compile(
    r'(?P<tag><rect\b(?=[^>]*\bdata-latest-day="true")[^>]*/>)', re.I
)
LATEST_OUTLINE = re.compile(
    r'(?P<tag><rect\b(?=[^>]*\bdata-latest-outline="outer")[^>]*/>)', re.I
)
ISSUE_LABEL = re.compile(r'(?P<tag><text\b[^>]*>)BUG FOUND</text>', re.I)

THEMES = {
    "dark": {
        "primary": "#F8FAFC",
        "month": "#FFFFFF",
        "context": "#59657A",
        "latest": "#00AEEF",
    },
    "light": {
        "primary": "#111827",
        "month": "#111827",
        "context": "#A7B0C4",
        "latest": "#007EA8",
    },
}

OLD_FOOTER = "30D EVIDENCE · DIM CONTEXT · LEVELS 0–4 · RAW COUNTS"
NEW_FOOTER = "30D EVIDENCE · LEADING CONTEXT · LEVELS 0–4 · RAW COUNTS"
OLD_DESC = "as dimmed Monday-aligned context."
NEW_DESC = "as Monday-aligned leading context."


def attrs_of(tag: str) -> dict[str, str]:
    return dict(ATTR.findall(tag))


def set_attr(tag: str, name: str, value: str) -> str:
    pattern = re.compile(rf'\b{re.escape(name)}="[^"]*"')
    replacement = f'{name}="{value}"'
    if pattern.search(tag):
        return pattern.sub(replacement, tag, count=1)
    close = tag.rfind("/>") if tag.endswith("/>") else tag.rfind(">")
    if close < 0:
        raise ValueError(f"cannot set {name!r} on malformed SVG element")
    return tag[:close].rstrip() + f' {replacement}' + tag[close:]


def remove_attr(tag: str, name: str) -> str:
    return re.sub(rf'\s+{re.escape(name)}="[^"]*"', "", tag, count=1)


def scheme_for(path: Path) -> str:
    if path.name.endswith("-dark.svg"):
        return "dark"
    if path.name.endswith("-light.svg"):
        return "light"
    raise ValueError(f"unsupported Signal Field theme: {path.name}")


def layout_for(path: Path) -> str:
    if "-wide-" in path.name:
        return "wide"
    if "-compact-" in path.name:
        return "compact"
    raise ValueError(f"unsupported Signal Field layout: {path.name}")


def add_root_provenance(text: str) -> str:
    match = SVG_OPEN.search(text)
    if not match:
        raise ValueError("SVG root missing")
    root = match.group(0)
    attrs = attrs_of(root)
    if attrs.get("data-evidence-identity") != PREVIOUS:
        raise ValueError("Signal Field v2.14 Evidence ID must precede v2.15")
    root = set_attr(root, "data-evidence-presentation", VERSION)
    root = set_attr(root, "data-calendar-context-visual", "outlined")
    root = set_attr(root, "data-issues-display-alias", "bug-found")
    return text[:match.start()] + root + text[match.end():]


def outline_context(text: str, scheme: str) -> str:
    context = THEMES[scheme]["context"]
    matches = list(CONTEXT_RECT.finditer(text))
    if not matches:
        raise ValueError("expected at least one leading-context tile")

    def tile(match: re.Match[str]) -> str:
        tag = remove_attr(match.group("tag"), "opacity")
        tag = set_attr(tag, "stroke", context)
        tag = set_attr(tag, "stroke-width", "1.15")
        tag = set_attr(tag, "stroke-dasharray", "3 2")
        return set_attr(tag, "data-context-encoding", "outline")

    text = CONTEXT_RECT.sub(tile, text)

    primary = THEMES[scheme]["primary"]
    day_matches = list(CONTEXT_DAY.finditer(text))
    if len(day_matches) != len(matches):
        raise ValueError("leading-context day-label count changed")

    def day(match: re.Match[str]) -> str:
        tag = set_attr(match.group("tag"), "fill", primary)
        return set_attr(tag, "opacity", "0.92")

    return CONTEXT_DAY.sub(day, text)


def brighten_months(text: str, scheme: str, layout: str) -> str:
    matches = list(MONTH_LABEL.finditer(text))
    if not matches:
        raise ValueError("month-boundary labels are missing")
    color = THEMES[scheme]["month"]
    size = "7.2" if layout == "wide" else "6"

    def month(match: re.Match[str]) -> str:
        tag = set_attr(match.group("tag"), "fill", color)
        tag = set_attr(tag, "font-size", size)
        tag = set_attr(tag, "font-weight", "800")
        return set_attr(tag, "opacity", "1")

    return MONTH_LABEL.sub(month, text)


def simplify_latest(text: str, scheme: str) -> str:
    tiles = list(LATEST_TILE.finditer(text))
    outlines = list(LATEST_OUTLINE.finditer(text))
    if len(tiles) != 1 or len(outlines) != 1:
        raise ValueError("latest-day tile/outline contract changed")

    tile = set_attr(tiles[0].group("tag"), "stroke", "none")
    tile = set_attr(tile, "stroke-width", "0")
    text = text[:tiles[0].start()] + tile + text[tiles[0].end():]

    outline_match = LATEST_OUTLINE.search(text)
    assert outline_match is not None
    outline = set_attr(outline_match.group("tag"), "stroke", THEMES[scheme]["latest"])
    outline = set_attr(outline, "stroke-width", "1.4")
    outline = set_attr(outline, "opacity", "0.92")
    return text[:outline_match.start()] + outline + text[outline_match.end():]


def clarify_copy(text: str) -> str:
    if OLD_FOOTER in text:
        text = text.replace(OLD_FOOTER, NEW_FOOTER, 1)
    if OLD_DESC in text:
        text = text.replace(OLD_DESC, NEW_DESC, 1)

    labels = list(ISSUE_LABEL.finditer(text))
    if len(labels) != 1:
        raise ValueError("expected exactly one BUG FOUND display label")
    if ">BUGS FOUND</text>" in text or ">ISSUES AUTHORED</text>" in text:
        raise ValueError("stale Issues display alias reached v2.15")
    return text


def transform(text: str, path: Path) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing")
    attrs = attrs_of(root.group(0))
    if attrs.get("data-evidence-presentation") == VERSION:
        validate(text, path)
        return text

    transformed = add_root_provenance(text)
    transformed = outline_context(transformed, scheme_for(path))
    transformed = brighten_months(transformed, scheme_for(path), layout_for(path))
    transformed = simplify_latest(transformed, scheme_for(path))
    transformed = clarify_copy(transformed)
    validate(transformed, path)
    return transformed


def validate(text: str, path: Path) -> None:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing after v2.15")
    attrs = attrs_of(root.group(0))
    if attrs.get("data-evidence-identity") != PREVIOUS:
        raise ValueError("v2.14 Evidence ID provenance changed")
    if attrs.get("data-evidence-presentation") != VERSION:
        raise ValueError("v2.15 presentation provenance missing")
    if attrs.get("data-calendar-context-visual") != "outlined":
        raise ValueError("calendar context must be outline-encoded")
    if attrs.get("data-issues-display-alias") != "bug-found":
        raise ValueError("Issues display alias must remain BUG FOUND")
    if not re.fullmatch(r"SF1-[0-9A-F]{16}", attrs.get("data-evidence-id", "")):
        raise ValueError("Evidence ID changed or disappeared")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", attrs.get("data-evidence-digest", "")):
        raise ValueError("Evidence digest changed or disappeared")

    context = THEMES[scheme_for(path)]["context"]
    tiles = [m.group("tag") for m in CONTEXT_RECT.finditer(text)]
    if not tiles:
        raise ValueError("leading-context tiles disappeared")
    for tag in tiles:
        a = attrs_of(tag)
        if "opacity" in a:
            raise ValueError("leading context must not alter contribution-intensity opacity")
        if a.get("stroke") != context or a.get("stroke-width") != "1.15":
            raise ValueError("leading context outline styling changed")
        if a.get("stroke-dasharray") != "3 2" or a.get("data-context-encoding") != "outline":
            raise ValueError("leading context outline encoding changed")

    primary = THEMES[scheme_for(path)]["primary"]
    days = [m.group("tag") for m in CONTEXT_DAY.finditer(text)]
    if len(days) != len(tiles):
        raise ValueError("leading-context day-label count changed")
    for tag in days:
        a = attrs_of(tag)
        if a.get("fill") != primary or a.get("opacity") != "0.92":
            raise ValueError("leading context day labels are not legible")

    month_color = THEMES[scheme_for(path)]["month"]
    month_size = "7.2" if layout_for(path) == "wide" else "6"
    months = [m.group("tag") for m in MONTH_LABEL.finditer(text)]
    if not months:
        raise ValueError("month markers disappeared")
    for tag in months:
        a = attrs_of(tag)
        if a.get("fill") != month_color or a.get("opacity") != "1":
            raise ValueError("month markers must remain maximum contrast")
        if a.get("font-size") != month_size or a.get("font-weight") != "800":
            raise ValueError("month marker scale/weight changed")

    latest = LATEST_TILE.search(text)
    outline = LATEST_OUTLINE.search(text)
    if not latest or not outline:
        raise ValueError("latest-day state disappeared")
    la = attrs_of(latest.group("tag"))
    oa = attrs_of(outline.group("tag"))
    if la.get("stroke") != "none" or la.get("stroke-width") != "0":
        raise ValueError("latest-day tile must not retain a second keyline")

    refresh = attrs.get("data-generation-cadence-contract")
    if refresh == FINAL_REFRESH:
        if attrs.get("data-current-day-highlight") != FINAL_CURRENT_DAY:
            raise ValueError("profile-refresh-v2 current-day highlight provenance is missing")
        expected_latest = FINAL_LATEST_COLOR
        expected_opacity = FINAL_LATEST_OPACITY
    else:
        if attrs.get("data-current-day-highlight"):
            raise ValueError("current-day successor provenance exists without profile-refresh-v2")
        expected_latest = THEMES[scheme_for(path)]["latest"]
        expected_opacity = "0.92"
    if oa.get("stroke") != expected_latest or oa.get("stroke-width") != "1.4" or oa.get("opacity") != expected_opacity:
        raise ValueError("latest-day outer ring changed")

    if text.count(">BUG FOUND</text>") != 1:
        raise ValueError("BUG FOUND label contract changed")
    if ">BUGS FOUND</text>" in text or ">ISSUES AUTHORED</text>" in text:
        raise ValueError("stale Issues display alias returned")
    if layout_for(path) == "wide":
        if text.count(NEW_FOOTER) != 1 or OLD_FOOTER in text:
            raise ValueError("wide leading-context footer wording changed")
    if OLD_DESC in text or text.count(NEW_DESC) != 1:
        raise ValueError("accessible leading-context semantics changed")


def self_test() -> None:
    for layout in ("wide", "compact"):
        for scheme in ("light", "dark"):
            filename = Path(f"signal-field-{layout}-{scheme}.svg")
            viewbox = "0 0 640 425" if layout == "wide" else "0 0 320 500"
            footer = f"<text>{OLD_FOOTER}</text>" if layout == "wide" else ""
            text = (
                f'<svg viewBox="{viewbox}" data-evidence-identity="{PREVIOUS}" '
                'data-evidence-id="SF1-0123456789ABCDEF" '
                'data-evidence-digest="sha256:' + 'a' * 64 + '" '
                'data-calendar-context-visual="dimmed" data-issues-display-alias="bug-found">'
                f'<desc>calendar display includes context {OLD_DESC}</desc>'
                '<rect data-evidence-window-role="context" data-date="2026-08-03" opacity="0.50"/>'
                '<text data-day-label="2026-08-03" opacity="0.58" data-evidence-context-label="calendar-leading">03</text>'
                '<text data-month-boundary="AUG" opacity="0.58" data-evidence-context-label="calendar-leading">AUG</text>'
                '<text data-month-boundary="SEP">SEP</text>'
                '<rect data-latest-day="true" stroke="#F8FAFC" stroke-width="1"/>'
                '<rect data-latest-outline="outer" stroke="#00AEEF" stroke-width="1.25" opacity="0.68"/>'
                '<text>BUG FOUND</text>' + footer + '</svg>'
            )
            transformed = transform(text, filename)
            validate(transformed, filename)
            if transform(transformed, filename) != transformed:
                raise AssertionError("v2.15 transform must be idempotent")

            successor_root = SVG_OPEN.search(transformed)
            assert successor_root is not None
            successor_tag = set_attr(successor_root.group(0), "data-generation-cadence-contract", FINAL_REFRESH)
            successor_tag = set_attr(successor_tag, "data-current-day-highlight", FINAL_CURRENT_DAY)
            successor = transformed[:successor_root.start()] + successor_tag + transformed[successor_root.end():]
            successor_outline = LATEST_OUTLINE.search(successor)
            assert successor_outline is not None
            outline_tag = set_attr(successor_outline.group("tag"), "stroke", FINAL_LATEST_COLOR)
            outline_tag = set_attr(outline_tag, "opacity", FINAL_LATEST_OPACITY)
            successor = successor[:successor_outline.start()] + outline_tag + successor[successor_outline.end():]
            validate(successor, filename)
    print("Signal Field v2.15 evidence-presentation self-test passed")


def apply(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        transformed = transform(path.read_text(encoding="utf-8"), path)
        path.write_text(transformed, encoding="utf-8")
        print(f"polished {filename}: outlined context, bright months, single latest ring, BUG FOUND label")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test(); return 0
        if len(sys.argv) != 2:
            raise ValueError("usage: polish-signal-field-evidence-v215.py <generated-directory> | --self-test")
        apply(Path(sys.argv[1])); return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr); return 1


if __name__ == "__main__":
    raise SystemExit(main())
