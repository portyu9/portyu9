#!/usr/bin/env python3
"""Diagnostic: report exact Dependabot controller BOM API-surface multiplicity drift."""
from __future__ import annotations

from collections import Counter
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
        expected_items = {stable(item): item for item in expected_job["apiSurfaces"]}
        observed_items = {stable(item): item for item in observed_job["apiSurfaces"]}
        expected_counts = Counter(stable(item) for item in expected_job["apiSurfaces"])
        observed_counts = Counter(stable(item) for item in observed_job["apiSurfaces"])
        deltas = []
        for key in sorted(set(expected_counts) | set(observed_counts)):
            delta = expected_counts[key] - observed_counts[key]
            if delta:
                deltas.append({
                    "delta": delta,
                    "expectedCount": expected_counts[key],
                    "observedCount": observed_counts[key],
                    "surface": expected_items.get(key, observed_items.get(key)),
                })
        print("CONTROLLER_API_SURFACE_MULTIPLICITY_DELTA=" + json.dumps(
            deltas, sort_keys=True, separators=(",", ":")
        ))
        raise ValueError("diagnostic controller BOM surface multiplicity drift")
    except (OSError, StopIteration, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
