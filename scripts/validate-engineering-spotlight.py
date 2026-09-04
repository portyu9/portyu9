#!/usr/bin/env python3
"""Validate generated engineering Evidence Spotlight artifacts."""
from __future__ import annotations
import argparse, json, re
from pathlib import Path
EXPECTED = tuple(f"spotlight-{slot}-{theme}.svg" for slot in (1,2) for theme in ("light","dark"))
MANIFEST = "spotlight-manifest.json"
VERSION = "engineering-spotlight-v1"
def require(condition: bool, message: str) -> None:
    if not condition: raise ValueError(message)
def main() -> int:
    parser=argparse.ArgumentParser(); parser.add_argument("directory", type=Path); parser.add_argument("--require-live", action="store_true"); args=parser.parse_args()
    try:
        root=args.directory; require(root.is_dir(), f"Spotlight directory is missing: {root}")
        manifest_path=root/MANIFEST; require(manifest_path.is_file(), "Spotlight manifest is missing")
        manifest=json.loads(manifest_path.read_text(encoding="utf-8")); require(manifest.get("version")==VERSION, "Spotlight manifest version changed")
        slots=manifest.get("slots"); require(isinstance(slots,list) and len(slots)==2, "Exactly two spotlight slots are required")
        repos=[slot.get("repository") for slot in slots]; require(len(set(repos))==2, "Spotlight slots must select distinct repositories")
        if args.require_live:
            for slot in slots:
                for label, signal in (slot.get("statuses") or {}).items():
                    require(signal not in {"UNAVAILABLE","NO SIGNAL","UNKNOWN"}, f"Live spotlight evidence unavailable for {slot.get('repository')} {label}: {signal}")
        require(all(str(repo).startswith("portyu9/") for repo in repos), "Spotlight repository scope changed")
        require(re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(manifest.get("selection_date_utc")) or ""), "Spotlight UTC date is invalid")
        for name in EXPECTED:
            path=root/name; require(path.is_file(), f"Missing spotlight SVG: {name}"); content=path.read_text(encoding="utf-8")
            require(len(content.encode())<=30000, f"Spotlight SVG exceeds 30 KB: {name}")
            require(f'data-spotlight="{VERSION}"' in content, f"Spotlight provenance missing: {name}")
            require("DAILY EVIDENCE SPOTLIGHT" in content, f"Spotlight identity missing: {name}")
            require("CI · " in content and "SECURITY · " in content, f"Workflow evidence labels missing: {name}")
            lowered=content.lower()
            for forbidden in ("<image","<foreignobject","<script","javascript:","data:image"):
                require(forbidden not in lowered, f"Unsafe SVG content {forbidden!r}: {name}")
        require('fill="#FFFFFF"' in (root/"spotlight-1-light.svg").read_text(encoding="utf-8"), "Light spotlight surface changed")
        require('fill="#0D1117"' in (root/"spotlight-1-dark.svg").read_text(encoding="utf-8"), "Dark spotlight surface changed")
        print("Engineering spotlight validation passed: two distinct daily slots, explicit theme variants, scoped workflow evidence, and safe SVG contracts are intact.")
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}"); return 1
if __name__ == "__main__": raise SystemExit(main())
