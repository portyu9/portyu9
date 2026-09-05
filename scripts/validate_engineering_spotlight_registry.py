#!/usr/bin/env python3
"""Registry binding adapter for the reviewed Engineering Spotlight v2.1 validator.

The historical v2.1 validator implementation remains intact, while active validation
gets its permanent/rotating inventories and Ledger registry provenance from the single
canonical portfolio registry.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import portfolio_system_registry as registry
import validate_engineering_spotlight_v21 as impl

impl.STATIC_REPOSITORIES = {f"{registry.OWNER}/{item['repo']}" for item in registry.permanent_systems()}
impl.ALLOWED_REPOS = {f"{registry.OWNER}/{item['repo']}" for item in registry.rotating_systems()}

_historical_load_ledger = impl.load_ledger


def load_ledger(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    ledger, by_repo = _historical_load_ledger(path)
    provenance = ledger.get("portfolio_registry")
    if not isinstance(provenance, dict):
        raise ValueError("Portfolio Ledger registry provenance is missing")
    if provenance.get("version") != registry.VERSION:
        raise ValueError("Portfolio Ledger registry version changed")
    if provenance.get("digest") != registry.registry_digest():
        raise ValueError("Portfolio Ledger registry digest does not match reviewed registry bytes")

    reviewed = registry.system_by_repo()
    expected_repos = {f"{registry.OWNER}/{repo}" for repo in reviewed}
    if set(by_repo) != expected_repos:
        raise ValueError("Portfolio Ledger repository inventory differs from canonical registry")
    for repository, entry in by_repo.items():
        slug = repository.split("/", 1)[1]
        expected = reviewed[slug]
        if entry.get("title") != expected["title"]:
            raise ValueError(f"{repository}: title differs from canonical registry")
        if entry.get("classification") != expected["classification"]:
            raise ValueError(f"{repository}: classification differs from canonical registry")
        expected_contract = [
            {"label": spec["label"], "workflow": spec["workflow"], "scope": registry.evidence_scope(spec)}
            for spec in expected["evidence"]
        ]
        if entry.get("evidence_contract") != expected_contract:
            raise ValueError(f"{repository}: evidence contract differs from canonical registry")
    return ledger, by_repo


impl.load_ledger = load_ledger


def main() -> int:
    registry.load_registry()
    return impl.main()


if __name__ == "__main__":
    raise SystemExit(main())
