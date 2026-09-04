#!/usr/bin/env python3
"""Validate Signal Field v2.13 evidence-window semantics without modifying artifacts.

The original v2.13 dimmed-context presentation remains valid before finalization. Final
v2.15 artifacts may supersede that presentation with outline-encoded leading context,
while preserving the same 30 measured days and Monday-aligned context membership.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
CLARITY_SCRIPT = ROOT / "clarify-signal-field-evidence-window.py"
V215 = "signal-field-v2.15"


def load_clarity():
    spec = importlib.util.spec_from_file_location("signal_field_v213", CLARITY_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Signal Field v2.13 clarity module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_superseded(text: str, root_tag: str, layout: str, clarity) -> None:
    attrs = clarity.attrs_of(root_tag)
    if attrs.get("data-evidence-window-clarity") != clarity.VERSION:
        raise ValueError("v2.13 evidence-window provenance missing")
    if attrs.get("data-evidence-presentation") != V215:
        raise ValueError("unexpected evidence-window presentation successor")
    if attrs.get("data-calendar-context-visual") != "outlined":
        raise ValueError("v2.15 must encode leading context with outlines")

    window_days = int(attrs.get("data-activity-window-days", "0"))
    display_days = int(attrs.get("data-activity-display-days", "0"))
    if window_days != 30 or not (30 <= display_days <= 36):
        raise ValueError("30-day evidence/display provenance changed")

    measured = [m.group("tag") for m in clarity.MEASURED_RECT.finditer(text)]
    leading = [m.group("tag") for m in clarity.LEADING_RECT.finditer(text)]
    if len(measured) != 30:
        raise ValueError("v2.15 must preserve exactly 30 measured evidence tiles")
    if len(leading) != display_days - 30:
        raise ValueError("v2.15 leading-context membership changed")
    if any(clarity.attrs_of(tag).get("data-evidence-window-role") != "measured" for tag in measured):
        raise ValueError("measured evidence roles changed")
    for tag in leading:
        a = clarity.attrs_of(tag)
        if a.get("data-evidence-window-role") != "context":
            raise ValueError("leading context role changed")
        if "opacity" in a:
            raise ValueError("v2.15 leading context must not alter contribution intensity with opacity")

    _, new_heading = clarity.HEADINGS[layout]
    if text.count(new_heading) != 1:
        raise ValueError("evidence-window heading changed")
    if "as Monday-aligned leading context." not in text:
        raise ValueError("accessible leading-context semantics missing")


def validate_directory(directory: Path) -> None:
    clarity = load_clarity()
    superseded = 0
    for filename in clarity.EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing or empty v2.13 artifact: {filename}")
        text = path.read_text(encoding="utf-8")
        root = clarity.SVG_OPEN.search(text)
        if not root:
            raise ValueError(f"SVG root missing: {filename}")
        layout = clarity.layout_of(root.group(0))
        attrs = clarity.attrs_of(root.group(0))
        if attrs.get("data-evidence-presentation") == V215:
            validate_superseded(text, root.group(0), layout, clarity)
            superseded += 1
        else:
            clarity.validate(text, layout)
    detail = (
        "outline-encoded v2.15 leading context" if superseded else "reviewed v2.13 dimmed leading context"
    )
    print(
        "Signal Field v2.13 evidence-window validation passed: exact 30-day measured membership, "
        f"Monday-aligned context, clarified headings, and accessible semantics are intact using {detail}."
    )


def main() -> int:
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: validate-signal-field-v213.py <generated-directory>")
        validate_directory(Path(sys.argv[1])); return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
