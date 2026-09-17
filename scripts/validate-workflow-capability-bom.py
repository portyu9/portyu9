#!/usr/bin/env python3
"""Diagnostic: report exact Dependabot controller BOM API-surface drift."""
from __future__ import annotations

import json
import sys

import workflow_capability_bom as compiler
import workflow_capability_snapshot


def stable(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def main() -> int:
    try:
        compiled = compiler.compile_bom()
        snapshot = workflow_capability_snapshot.load_combined()
        expected = next(w for w in compiled["workflows"] if w["id"] == "dependabot-controller")
        observed = next(w for w in snapshot["workflows"] if w["id"] == "dependabot-controller")
        expected_job = next(j for j in expected["jobs"] if j["id"] == "controller")
        observed_job = next(j for j in observed["jobs"] if j["id"] == "controller")
        expected_surfaces = {stable(item): item for item in expected_job["apiSurfaces"]}
        observed_surfaces = {stable(item): item for item in observed_job["apiSurfaces"]}
        print("MISSING_CONTROLLER_API_SURFACES=" + json.dumps(
            [expected_surfaces[key] for key in sorted(expected_surfaces.keys() - observed_surfaces.keys())],
            sort_keys=True,
            separators=(",", ":"),
        ))
        print("EXTRA_CONTROLLER_API_SURFACES=" + json.dumps(
            [observed_surfaces[key] for key in sorted(observed_surfaces.keys() - expected_surfaces.keys())],
            sort_keys=True,
            separators=(",", ":"),
        ))
        raise ValueError("diagnostic controller BOM surface drift")
    except (OSError, StopIteration, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
