#!/usr/bin/env python3
"""Validate Signal Field v2.13 artifacts without modifying them."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
CLARITY_SCRIPT = ROOT / "clarify-signal-field-evidence-window.py"


def load_clarity():
    spec = importlib.util.spec_from_file_location("signal_field_v213", CLARITY_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Signal Field v2.13 clarity module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_directory(directory: Path) -> None:
    clarity = load_clarity()
    for filename in clarity.EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing or empty v2.13 artifact: {filename}")
        text = path.read_text(encoding="utf-8")
        root = clarity.SVG_OPEN.search(text)
        if not root:
            raise ValueError(f"SVG root missing: {filename}")
        layout = clarity.layout_of(root.group(0))
        clarity.validate(text, layout)
    print(
        "Signal Field v2.13 publish-boundary validation passed: exact 30-day measured roles, "
        "dimmed Monday context, quieter empty slots, clarified headings, and accessible "
        "context semantics are intact across all four artifacts."
    )


def main() -> int:
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: validate-signal-field-v213.py <generated-directory>")
        validate_directory(Path(sys.argv[1]))
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
