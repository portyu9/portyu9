#!/usr/bin/env python3
"""Finalize publishable Signal Field refresh provenance and current-day emphasis.

Earlier presentation stages predate the current refresh contract and encode the
historical five-minute request. This final, idempotent transform runs after evidence
identity/presentation finalization and before the publishable-artifact validator. It
changes refresh provenance/copy and the presentation-only current-day outline; measured
evidence, contribution levels, and Evidence ID semantics are not modified. The normal
production entrypoint then applies the desktop-only v2.18 detail alignment.
"""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import re
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
WIDE_ALIGNMENT_PATH = ROOT / "scripts" / "finalize-signal-field-wide-alignment.py"
VERSION = "profile-refresh-v2"
GENERATION_SCHEDULE = "1-hour"
DESCRIPTION = "every hour"
CURRENT_DAY_HIGHLIGHT = "phosphorescent-red-v1"
CURRENT_DAY_RED = "#FF335F"
EXPECTED_FILES = tuple(
    f"signal-field-{layout}-{theme}.svg"
    for layout in ("wide", "compact")
    for theme in ("light", "dark")
)
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
LATEST_OUTLINE = re.compile(
    r'(?P<tag><rect\b(?=[^>]*\bdata-latest-outline="outer")[^>]*/>)', re.I
)

PROVENANCE = f'data-generation-cadence-contract="{VERSION}"'
HIGHLIGHT_PROVENANCE = f'data-current-day-highlight="{CURRENT_DAY_HIGHLIGHT}"'
LEGACY_DESCRIPTIONS = (
    "Generation schedule: every 5 minutes; execution and README cache propagation are best-effort.",
    "Generation schedule: every 30 minutes; execution and README cache propagation are best-effort.",
)
NEW_DESCRIPTION = f"Generation refresh: {DESCRIPTION}; execution and README cache propagation are best-effort."
WIDE_FOOTERS = (
    "SOURCES · GITHUB GRAPHQL + REST · SCHEDULE · 5 MIN",
    "SOURCES · GITHUB GRAPHQL + REST · SCHEDULE · 30 MIN",
)
NEW_WIDE = "SOURCES · GITHUB GRAPHQL + REST · REFRESH · 1 HR"
COMPACT_FOOTERS = (
    "GITHUB API · GRAPHQL + REST · SCHEDULE · 5 MIN",
    "GITHUB API · GRAPHQL + REST · SCHEDULE · 30 MIN",
)
NEW_COMPACT = "GITHUB API · GRAPHQL + REST · REFRESH · 1 HR"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_wide_alignment():
    spec = importlib.util.spec_from_file_location("signal_field_wide_alignment", WIDE_ALIGNMENT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load desktop Signal Field alignment finalizer")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def root_attrs(text: str) -> dict[str, str]:
    match = SVG_OPEN.search(text)
    require(match is not None, "Signal Field SVG root is missing")
    return dict(ATTR.findall(match.group(0)))


def attrs_of(tag: str) -> dict[str, str]:
    return dict(ATTR.findall(tag))


def set_attr(tag: str, name: str, value: str) -> str:
    pattern = re.compile(rf'\b{re.escape(name)}="[^"]*"')
    replacement = f'{name}="{value}"'
    if pattern.search(tag):
        return pattern.sub(replacement, tag, count=1)
    close = tag.rfind("/>") if tag.endswith("/>") else tag.rfind(">")
    require(close >= 0, f"cannot set {name!r} on malformed SVG element")
    return tag[:close].rstrip() + f" {replacement}" + tag[close:]


def set_root_contract(text: str) -> str:
    match = SVG_OPEN.search(text)
    require(match is not None, "Signal Field SVG root is missing")
    root = match.group(0)
    attrs = dict(ATTR.findall(root))
    current = attrs.get("data-generation-schedule")
    require(
        current in {"5-minutes", "30-minutes", GENERATION_SCHEDULE},
        f"unexpected generation schedule provenance: {current!r}",
    )
    root = set_attr(root, "data-generation-schedule", GENERATION_SCHEDULE)
    root = set_attr(root, "data-generation-cadence-contract", VERSION)
    root = set_attr(root, "data-current-day-highlight", CURRENT_DAY_HIGHLIGHT)
    return text[: match.start()] + root + text[match.end() :]


def replace_reviewed_value(text: str, historical: tuple[str, ...], final: str, label: str) -> str:
    counts = [text.count(item) for item in (*historical, final)]
    require(sum(counts) == 1, f"{label} must have exactly one reviewed historical or final value")
    if text.count(final) == 1:
        return text
    for item in historical:
        if item in text:
            return text.replace(item, final, 1)
    raise AssertionError(f"unreachable reviewed-value replacement for {label}")


def set_current_day_outline(text: str) -> str:
    matches = list(LATEST_OUTLINE.finditer(text))
    require(len(matches) == 1, "current-day outer outline must exist exactly once")
    match = matches[0]
    outline = set_attr(match.group("tag"), "stroke", CURRENT_DAY_RED)
    outline = set_attr(outline, "stroke-width", "1.4")
    outline = set_attr(outline, "opacity", "0.96")
    return text[: match.start()] + outline + text[match.end() :]


def transform(text: str, path: Path) -> str:
    text = set_root_contract(text)
    text = replace_reviewed_value(text, LEGACY_DESCRIPTIONS, NEW_DESCRIPTION, "accessible refresh description")
    if "wide" in path.name:
        text = replace_reviewed_value(text, WIDE_FOOTERS, NEW_WIDE, "wide refresh footer")
        require(
            not any(value in text for value in (*COMPACT_FOOTERS, NEW_COMPACT)),
            "wide artifact contains compact refresh footer",
        )
    elif "compact" in path.name:
        text = replace_reviewed_value(text, COMPACT_FOOTERS, NEW_COMPACT, "compact refresh footer")
        require(
            not any(value in text for value in (*WIDE_FOOTERS, NEW_WIDE)),
            "compact artifact contains wide refresh footer",
        )
    else:
        raise ValueError(f"unsupported Signal Field layout: {path.name}")
    text = set_current_day_outline(text)
    validate(text, path)
    return text


def validate(text: str, path: Path) -> None:
    attrs = root_attrs(text)
    require(attrs.get("data-generation-schedule") == GENERATION_SCHEDULE, f"{path.name}: generation refresh is not hourly")
    require(attrs.get("data-generation-cadence-contract") == VERSION, f"{path.name}: refresh contract provenance is missing")
    require(attrs.get("data-current-day-highlight") == CURRENT_DAY_HIGHLIGHT, f"{path.name}: current-day highlight provenance is missing")
    require(text.count(NEW_DESCRIPTION) == 1, f"{path.name}: accessible hourly refresh description is missing")
    require(not any(value in text for value in LEGACY_DESCRIPTIONS), f"{path.name}: stale schedule description remains")
    expected = NEW_WIDE if "wide" in path.name else NEW_COMPACT
    stale = WIDE_FOOTERS if "wide" in path.name else COMPACT_FOOTERS
    require(text.count(expected) == 1, f"{path.name}: visible hourly REFRESH footer is missing")
    require(not any(value in text for value in stale), f"{path.name}: stale SCHEDULE footer remains")

    outline = LATEST_OUTLINE.search(text)
    require(outline is not None, f"{path.name}: current-day outline is missing")
    outline_attrs = attrs_of(outline.group("tag"))
    require(outline_attrs.get("stroke") == CURRENT_DAY_RED, f"{path.name}: current-day outline is not phosphorescent red")
    require(outline_attrs.get("stroke-width") == "1.4", f"{path.name}: current-day outline width changed")
    require(outline_attrs.get("opacity") == "0.96", f"{path.name}: current-day outline opacity changed")


def apply(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        require(path.is_file() and path.stat().st_size > 0, f"missing Signal Field artifact: {filename}")
        final = transform(path.read_text(encoding="utf-8"), path)
        path.write_text(final, encoding="utf-8")
        print(f"refresh presentation finalized {filename}: hourly · current-day phosphorescent red")


def apply_publishable(directory: Path) -> None:
    apply(directory)
    load_wide_alignment().apply(directory, False)


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for filename in EXPECTED_FILES:
            path = root / filename
            footer = WIDE_FOOTERS[0] if "wide" in filename else COMPACT_FOOTERS[0]
            path.write_text(
                '<svg data-generation-schedule="5-minutes" data-evidence-id="SF1-0123456789ABCDEF">'
                f'<desc>{LEGACY_DESCRIPTIONS[0]}</desc><text>{footer}</text>'
                '<rect data-latest-outline="outer" stroke="#00AEEF" stroke-width="1.4" opacity="0.92"/>'
                '</svg>',
                encoding="utf-8",
            )
        apply(root)
        first = {path.name: path.read_text(encoding="utf-8") for path in root.iterdir()}
        apply(root)
        second = {path.name: path.read_text(encoding="utf-8") for path in root.iterdir()}
        require(first == second, "refresh presentation finalizer must be idempotent")
    load_wide_alignment().self_test()
    print("Signal Field refresh self-test passed: best-effort hourly generation + phosphorescent-red current day")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path, nargs="?")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
            return 0
        require(args.directory is not None, "usage: set-signal-field-refresh-cadence.py <directory> | --self-test")
        apply_publishable(args.directory)
        return 0
    except (OSError, ValueError, RuntimeError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
