#!/usr/bin/env python3
"""Engineering Evidence Spotlight v2.1 selection contract.

The three visible daily systems are selected from the canonical portfolio registry.
No second repository catalog or permanent-system exclusion list is maintained here.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import random
from typing import Any

import portfolio_system_registry as registry

VERSION = "engineering-spotlight-v2.1"
SLOT_COUNT = 3
STATIC_REPOSITORIES = frozenset(str(system["repo"]) for system in registry.permanent_systems())
ELIGIBLE_POOL = registry.rotating_spotlight_pool()


def select_systems(day: dt.date) -> list[dict[str, Any]]:
    if len(ELIGIBLE_POOL) < SLOT_COUNT:
        raise ValueError("Spotlight eligible pool cannot satisfy the three-slot contract")
    seed = int(hashlib.sha256(f"{VERSION}:{day.isoformat()}".encode()).hexdigest(), 16)
    return random.Random(seed).sample(list(ELIGIBLE_POOL), SLOT_COUNT)


def main() -> int:
    # Legacy direct generation remains available through engineering_spotlight_v2.py;
    # production uses the Ledger-backed renderer and this registry-backed selector.
    import engineering_spotlight_v2 as base
    base.VERSION = VERSION
    base.POOL = registry.legacy_spotlight_pool()
    base.select_systems = select_systems
    return base.main()


if __name__ == "__main__":
    raise SystemExit(main())
