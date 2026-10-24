#!/usr/bin/env python3
"""Pure, fail-closed contract for creating the third native publication ruleset.

No credentials, API client, network I/O or mutation. The caller supplies REST JSON
retrieved through its separately reviewed read-only transport. The only create
payload is the exact branch-scoped, parameter-free non-deletion/fast-forward rule.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
import sys
from typing import Any

REPOSITORY = "portyu9/portyu9"
LEGACY = frozenset({"Protect Main", "Protect generated"})
NAME = "Protect activity-metrics"
BRANCH = "refs/heads/activity-metrics"
RULES = frozenset({"deletion", "non_fast_forward"})
PAYLOAD = {
    "name": NAME,
    "target": "branch",
    "enforcement": "active",
    "conditions": {"ref_name": {"include": [BRANCH], "exclude": []}},
    "bypass_actors": [],
    "rules": [{"type": "deletion"}, {"type": "non_fast_forward"}],
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact_id(value: Any) -> bool:
    return type(value) is int and value > 0


def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in pairs:
        require(name not in out, f"duplicate ruleset JSON member: {name}")
        out[name] = value
    return out


def read_json(path: Path) -> Any:
    require(path.is_file() and not path.is_symlink(), "ruleset evidence is not a regular file")
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_keys)


def validate_collection(collection: Any) -> dict[str, dict[str, Any]]:
    require(isinstance(collection, list) and len(collection) in (2, 3),
            "native ruleset collection must contain exactly 2 or 3 entries")
    entries: dict[str, dict[str, Any]] = {}
    seen: set[int] = set()
    for item in collection:
        require(type(item) is dict, "native ruleset collection entry is malformed")
        name, identifier = item.get("name"), item.get("id")
        require(type(name) is str and bool(name), "native ruleset name is malformed")
        require(exact_id(identifier), "native ruleset id must be a positive JSON integer")
        require(name not in entries and identifier not in seen,
                "duplicate native ruleset name or id")
        require(item.get("source") == REPOSITORY and item.get("target") == "branch",
                "native ruleset collection has wrong repository/branch target")
        require(item.get("enforcement") == "active",
                "native ruleset collection contains an inactive ruleset")
        entries[name] = item
        seen.add(identifier)
    names = set(entries)
    require(names in (LEGACY, LEGACY | {NAME}),
            "native ruleset collection contains an unreviewed identity")
    return entries


def validate_activity_detail(detail: Any, identifier: int) -> None:
    """Require admin-visible exact third ruleset; no inferred empty bypass list."""
    require(type(detail) is dict and exact_id(identifier) and detail.get("id") == identifier
            and type(detail.get("id")) is int and detail.get("name") == NAME,
            "activity ruleset detail identity mismatched")
    require(detail.get("target") == "branch" and detail.get("enforcement") == "active",
            "activity ruleset target or enforcement mismatched")
    conditions = detail.get("conditions")
    require(type(conditions) is dict and conditions == PAYLOAD["conditions"],
            "activity ruleset branch conditions mismatched")
    require(detail.get("bypass_actors") == [] and type(detail.get("bypass_actors")) is list,
            "activity ruleset bypass actors are missing or non-empty")
    rules = detail.get("rules")
    require(type(rules) is list and len(rules) == 2
            and all(type(rule) is dict and set(rule) == {"type"} for rule in rules)
            and {rule["type"] for rule in rules} == RULES,
            "activity ruleset must contain only parameter-free deletion/non-fast-forward")


def evaluate(
    collection: Any,
    *,
    detail: Any | None = None,
    require_present: bool = False,
    created_response: Any | None = None,
) -> dict[str, Any]:
    entries = validate_collection(collection)
    if NAME not in entries:
        require(not require_present and detail is None and created_response is None,
                "native activity protection is absent after requested creation")
        return {"state": "absent", "repository": REPOSITORY, "rule": NAME}
    identifier = entries[NAME]["id"]
    require(detail is not None, "live activity ruleset detail must be authenticated")
    validate_activity_detail(detail, identifier)
    if created_response is not None:
        validate_activity_detail(created_response, identifier)
    return {"state": "present", "repository": REPOSITORY, "rule": NAME, "rulesetId": identifier}


def self_test() -> None:
    legacy = [
        {"name": "Protect Main", "id": 91, "source": REPOSITORY,
         "target": "branch", "enforcement": "active"},
        {"name": "Protect generated", "id": 106, "source": REPOSITORY,
         "target": "branch", "enforcement": "active"},
    ]
    detail = {"id": 207, **PAYLOAD}
    successor = legacy + [{"name": NAME, "id": 207, "source": REPOSITORY,
                           "target": "branch", "enforcement": "active"}]
    require(evaluate(legacy)["state"] == "absent", "legacy read-only preflight changed")
    require(evaluate(successor, detail=detail)["rulesetId"] == 207,
            "exact native activity successor rejected")
    require(evaluate(successor, detail=detail, require_present=True,
                     created_response=detail)["state"] == "present",
            "native creation-response readback identity changed")
    cases: list[tuple[Any, Any | None]] = [
        (legacy + [{"name": "Protect unwanted", "id": 207, "source": REPOSITORY,
                    "target": "branch", "enforcement": "active"}], detail),
        (legacy + [{"name": NAME, "id": 91, "source": REPOSITORY,
                    "target": "branch", "enforcement": "active"}], detail),
        (legacy + [{"name": NAME, "id": True, "source": REPOSITORY,
                    "target": "branch", "enforcement": "active"}], detail),
        (successor, None),
    ]
    for collection, maybe_detail in cases:
        try:
            evaluate(collection, detail=maybe_detail)
        except ValueError:
            pass
        else:
            raise ValueError("unsafe ruleset collection passed negative fixture")
    bad_values: list[tuple[str, Any]] = [
        ("id", True),
        ("name", "Protect Main"),
        ("target", "tag"),
        ("enforcement", "disabled"),
        ("conditions", {"ref_name": {"include": ["refs/heads/main"], "exclude": []}}),
        ("conditions", {"ref_name": {"include": ["refs/heads/activity-*"], "exclude": []}}),
        ("bypass_actors", [{"actor_id": 1, "actor_type": "OrganizationAdmin",
                            "bypass_mode": "always"}]),
        ("bypass_actors", None),
        ("rules", [{"type": "deletion"}]),
        ("rules", [{"type": "deletion"}, {"type": "non_fast_forward"},
                   {"type": "pull_request"}]),
        ("rules", [{"type": "deletion", "parameters": {}},
                   {"type": "non_fast_forward"}]),
    ]
    for name, value in bad_values:
        bad = copy.deepcopy(detail)
        bad[name] = value
        try:
            evaluate(successor, detail=bad)
        except ValueError:
            pass
        else:
            raise ValueError(f"unsafe activity ruleset detail accepted: {name}")
    try:
        evaluate(legacy, require_present=True)
    except ValueError:
        pass
    else:
        raise ValueError("missing native protection passed required successor proof")
    try:
        unique_keys([("id", 207), ("id", 91)])
    except ValueError:
        pass
    else:
        raise ValueError("duplicate JSON member accepted")


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--emit", action="store_true")
    mode.add_argument("--preflight", type=Path)
    mode.add_argument("--postflight", type=Path)
    parser.add_argument("--detail", type=Path)
    parser.add_argument("--created-response", type=Path)
    args = parser.parse_args()
    try:
        self_test()
        if args.self_test:
            print("Activity native ruleset bootstrap contract passed")
        elif args.emit:
            require(args.detail is None and args.created_response is None,
                    "emit mode cannot consume untrusted detail")
            print(json.dumps(PAYLOAD, sort_keys=True, separators=(",", ":")))
        else:
            path = args.postflight if args.postflight is not None else args.preflight
            require(path is not None, "native ruleset collection evidence required")
            detail = read_json(args.detail) if args.detail else None
            created = read_json(args.created_response) if args.created_response else None
            result = evaluate(read_json(path), detail=detail,
                              require_present=args.postflight is not None,
                              created_response=created)
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, TypeError, ValueError) as exc:
        print(f"ERROR: native activity ruleset bootstrap: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
