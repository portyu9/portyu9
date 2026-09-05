#!/usr/bin/env python3
"""Finalize the publishable Signal Field generation-cadence provenance.

Earlier presentation stages predate the Portfolio Ledger and encode the historical
five-minute schedule. This final, idempotent transform runs after v2.14/v2.15
presentation finalization and before the publishable-artifact validator. It changes
only schedule provenance/copy; measured evidence and Evidence ID semantics are not
modified. The normal production entrypoint then applies the desktop-only v2.17 detail
alignment as the final presentation layer.
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
VERSION = "profile-refresh-v1"
GENERATION_SCHEDULE = "30-minutes"
DESCRIPTION = "every 30 minutes"
EXPECTED_FILES = tuple(
    f"signal-field-{layout}-{theme}.svg"
    for layout in ("wide", "compact")
    for theme in ("light", "dark")
)
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')

OLD_ROOT = 'data-generation-schedule="5-minutes"'
NEW_ROOT = f'data-generation-schedule="{GENERATION_SCHEDULE}"'
PROVENANCE = f'data-generation-cadence-contract="{VERSION}"'
OLD_DESCRIPTION = "Generation schedule: every 5 minutes; execution and README cache propagation are best-effort."
NEW_DESCRIPTION = f"Generation schedule: {DESCRIPTION}; execution and README cache propagation are best-effort."
OLD_WIDE = "SOURCES · GITHUB GRAPHQL + REST · SCHEDULE · 5 MIN"
NEW_WIDE = "SOURCES · GITHUB GRAPHQL + REST · SCHEDULE · 30 MIN"
OLD_COMPACT = "GITHUB API · GRAPHQL + REST · SCHEDULE · 5 MIN"
NEW_COMPACT = "GITHUB API · GRAPHQL + REST · SCHEDULE · 30 MIN"


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


def set_root_contract(text: str) -> str:
    match = SVG_OPEN.search(text)
    require(match is not None, "Signal Field SVG root is missing")
    root = match.group(0)
    attrs = dict(ATTR.findall(root))
    current = attrs.get("data-generation-schedule")
    require(current in {"5-minutes", GENERATION_SCHEDULE}, f"unexpected generation schedule provenance: {current!r}")
    if current == "5-minutes":
        root = root.replace(OLD_ROOT, NEW_ROOT, 1)
    if 'data-generation-cadence-contract="' in root:
        root = re.sub(r'data-generation-cadence-contract="[^"]*"', PROVENANCE, root, count=1)
    else:
        root = root[:-1] + f" {PROVENANCE}>"
    return text[: match.start()] + root + text[match.end() :]


def replace_exact_or_final(text: str, old: str, new: str, label: str) -> str:
    old_count = text.count(old)
    new_count = text.count(new)
    require((old_count, new_count) in {(1, 0), (0, 1)}, f"{label} must have exactly one historical or final value")
    return text.replace(old, new, 1) if old_count == 1 else text


def transform(text: str, path: Path) -> str:
    text = set_root_contract(text)
    text = replace_exact_or_final(text, OLD_DESCRIPTION, NEW_DESCRIPTION, "accessible schedule description")
    if "wide" in path.name:
        text = replace_exact_or_final(text, OLD_WIDE, NEW_WIDE, "wide schedule footer")
        require(OLD_COMPACT not in text and NEW_COMPACT not in text, "wide artifact contains compact schedule footer")
    elif "compact" in path.name:
        text = replace_exact_or_final(text, OLD_COMPACT, NEW_COMPACT, "compact schedule footer")
        require(OLD_WIDE not in text and NEW_WIDE not in text, "compact artifact contains wide schedule footer")
    else:
        raise ValueError(f"unsupported Signal Field layout: {path.name}")
    validate(text, path)
    return text


def validate(text: str, path: Path) -> None:
    attrs = root_attrs(text)
    require(attrs.get("data-generation-schedule") == GENERATION_SCHEDULE, f"{path.name}: generation schedule is not 30 minutes")
    require(attrs.get("data-generation-cadence-contract") == VERSION, f"{path.name}: cadence contract provenance is missing")
    require(text.count(NEW_DESCRIPTION) == 1, f"{path.name}: accessible 30-minute schedule description is missing")
    require(OLD_DESCRIPTION not in text, f"{path.name}: stale five-minute schedule description remains")
    expected = NEW_WIDE if "wide" in path.name else NEW_COMPACT
    stale = OLD_WIDE if "wide" in path.name else OLD_COMPACT
    require(text.count(expected) == 1, f"{path.name}: visible 30-minute schedule footer is missing")
    require(stale not in text, f"{path.name}: stale five-minute schedule footer remains")


def apply(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        require(path.is_file() and path.stat().st_size > 0, f"missing Signal Field artifact: {filename}")
        final = transform(path.read_text(encoding="utf-8"), path)
        path.write_text(final, encoding="utf-8")
        print(f"generation cadence finalized {filename}: {GENERATION_SCHEDULE}")


def apply_publishable(directory: Path) -> None:
    apply(directory)
    load_wide_alignment().apply(directory, False)


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for filename in EXPECTED_FILES:
            path = root / filename
            footer = OLD_WIDE if "wide" in filename else OLD_COMPACT
            path.write_text(
                '<svg data-generation-schedule="5-minutes" data-evidence-id="SF1-0123456789ABCDEF">'
                f'<desc>{OLD_DESCRIPTION}</desc><text>{footer}</text></svg>',
                encoding="utf-8",
            )
        apply(root)
        first = {path.name: path.read_text(encoding="utf-8") for path in root.iterdir()}
        apply(root)
        second = {path.name: path.read_text(encoding="utf-8") for path in root.iterdir()}
        require(first == second, "cadence finalizer must be idempotent")
    load_wide_alignment().self_test()
    print("Signal Field refresh-cadence self-test passed: final artifacts encode best-effort 30-minute generation")


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
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
