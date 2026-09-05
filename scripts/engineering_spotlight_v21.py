#!/usr/bin/env python3
"""Engineering Evidence Spotlight v2.1 selection contract.

v2.1 keeps the reviewed v2 evidence/rendering engine while changing the visible
rotation contract: three distinct daily systems, with the four permanent
Selected Engineering Systems explicitly excluded from the rotating pool.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import random
from typing import Any

import engineering_spotlight_v2 as base

VERSION = "engineering-spotlight-v2.1"
SLOT_COUNT = 3

STATIC_REPOSITORIES = frozenset(
    {
        "ai-qa-automation",
        "qa-automation-ai-agent-evals",
        "qa-automation-graphql",
        "qa-automation-visual-and-accessibility-playwright-axe",
    }
)

ELIGIBLE_POOL = tuple(
    system for system in base.POOL if str(system["repo"]) not in STATIC_REPOSITORIES
)


def select_systems(day: dt.date) -> list[dict[str, Any]]:
    if len(ELIGIBLE_POOL) < SLOT_COUNT:
        raise ValueError("Spotlight eligible pool cannot satisfy the three-slot contract")
    seed = int(hashlib.sha256(f"{VERSION}:{day.isoformat()}".encode()).hexdigest(), 16)
    return random.Random(seed).sample(list(ELIGIBLE_POOL), SLOT_COUNT)


def main() -> int:
    # Keep the reviewed v2 ten-repository pool intact so its base invariant remains
    # fail-closed. Override only the deterministic selection seam; v2.1 samples its
    # three visible cards from ELIGIBLE_POOL, which excludes the four permanent cards.
    base.VERSION = VERSION
    base.select_systems = select_systems
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
