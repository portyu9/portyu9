#!/usr/bin/env python3
"""Self-test the three-slot flagship-exclusive Spotlight selection seam."""
from __future__ import annotations

import datetime as dt

import engineering_spotlight_v21 as spotlight


def main() -> int:
    days = tuple(dt.date(2026, 9, 1) + dt.timedelta(days=offset) for offset in range(31))
    static = set(spotlight.STATIC_REPOSITORIES)
    eligible = {str(system["repo"]) for system in spotlight.ELIGIBLE_POOL}
    if static & eligible:
        raise SystemExit("ERROR: permanent flagship leaked into eligible Spotlight pool")
    if len(eligible) != 9:
        raise SystemExit(f"ERROR: expected nine eligible rotating systems, found {len(eligible)}")
    for day in days:
        first = spotlight.select_systems(day)
        second = spotlight.select_systems(day)
        repos = [str(system["repo"]) for system in first]
        if repos != [str(system["repo"]) for system in second]:
            raise SystemExit(f"ERROR: selection is not deterministic for {day}")
        if len(repos) != 3 or len(set(repos)) != 3:
            raise SystemExit(f"ERROR: {day} did not produce three distinct rotating systems")
        if set(repos) & static:
            raise SystemExit(f"ERROR: {day} selected a permanent flagship")
    print("Spotlight selection contract passed: 31 deterministic dates each select three distinct non-flagship systems from the nine-system rotation pool.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
