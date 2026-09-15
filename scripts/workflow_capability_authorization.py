#!/usr/bin/env python3
"""Validate prior default-branch authorization for exact capability expansion."""
from __future__ import annotations

import copy
import re
from typing import Any

import workflow_capability_diff as capability_diff

SCHEMA_VERSION = 1
LEDGER_ID = "workflow-capability-expansion-authorizations-v1"
REPOSITORY = "portyu9/portyu9"
AUTHORIZATION_ID = re.compile(r"^cap-[a-z0-9][a-z0-9-]{2,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ROOT_KEYS = {"schemaVersion", "ledgerId", "repository", "authorizations"}
ENTRY_KEYS = {"id", "baseBomSha256", "candidateBomSha256", "expansionSha256", "rationale"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label} must be an object")
    require(set(value) == expected,
            f"{label} keys changed: expected={sorted(expected)} observed={sorted(value)}")
    return value


def validate_sha256(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA256.fullmatch(value) is not None,
            f"{label} must be a lowercase SHA-256 digest")
    return value


def validate_ledger(payload: Any) -> dict[str, Any]:
    root = exact_keys(payload, ROOT_KEYS, "capability authorization ledger")
    require(type(root["schemaVersion"]) is int and root["schemaVersion"] == SCHEMA_VERSION,
            "capability authorization schemaVersion must be exact integer 1")
    require(root["ledgerId"] == LEDGER_ID, "capability authorization ledger identity changed")
    require(root["repository"] == REPOSITORY, "capability authorization repository identity changed")
    require(isinstance(root["authorizations"], list), "capability authorizations must be an array")

    ids: set[str] = set()
    targets: set[tuple[str, str, str]] = set()
    previous_id: str | None = None
    for index, value in enumerate(root["authorizations"]):
        label = f"capability authorizations[{index}]"
        entry = exact_keys(value, ENTRY_KEYS, label)
        identity = entry["id"]
        require(isinstance(identity, str) and AUTHORIZATION_ID.fullmatch(identity) is not None,
                f"{label} id is invalid")
        require(identity not in ids, f"capability authorization id is duplicated: {identity}")
        if previous_id is not None:
            require(previous_id < identity, "capability authorizations must be strictly sorted by id")
        previous_id = identity
        ids.add(identity)

        target = (
            validate_sha256(entry["baseBomSha256"], f"{label}.baseBomSha256"),
            validate_sha256(entry["candidateBomSha256"], f"{label}.candidateBomSha256"),
            validate_sha256(entry["expansionSha256"], f"{label}.expansionSha256"),
        )
        require(target not in targets, f"capability authorization semantic target is duplicated: {target!r}")
        targets.add(target)

        rationale = entry["rationale"]
        require(isinstance(rationale, str) and rationale.strip() == rationale and 12 <= len(rationale) <= 500,
                f"{label} rationale must be a trimmed 12-500 character string")
        require("\n" not in rationale and "\r" not in rationale and "\x00" not in rationale,
                f"{label} rationale contains forbidden control characters")
    return root


def validate_diff(value: Any) -> dict[str, Any]:
    expected = {
        "schemaVersion", "diffId", "repository", "baseBomSha256", "candidateBomSha256",
        "expansionSha256", "hasExpansion", "expansions", "reductions",
    }
    diff = exact_keys(value, expected, "workflow capability diff")
    require(diff["schemaVersion"] == capability_diff.SCHEMA_VERSION,
            "workflow capability diff schemaVersion changed")
    require(diff["diffId"] == capability_diff.DIFF_ID, "workflow capability diff identity changed")
    require(diff["repository"] == REPOSITORY, "workflow capability diff repository changed")
    validate_sha256(diff["baseBomSha256"], "workflow capability diff baseBomSha256")
    validate_sha256(diff["candidateBomSha256"], "workflow capability diff candidateBomSha256")
    validate_sha256(diff["expansionSha256"], "workflow capability diff expansionSha256")
    require(type(diff["hasExpansion"]) is bool, "workflow capability diff hasExpansion must be boolean")
    require(isinstance(diff["expansions"], list) and isinstance(diff["reductions"], list),
            "workflow capability diff changes must be arrays")
    require(diff["expansionSha256"] == capability_diff.digest(diff["expansions"]),
            "workflow capability diff expansion digest does not bind the canonical expansion set")
    require(diff["hasExpansion"] == bool(diff["expansions"]),
            "workflow capability diff hasExpansion disagrees with expansion set")
    return diff


def authorize(diff_value: Any, trusted_ledger_value: Any) -> dict[str, Any]:
    diff = validate_diff(diff_value)
    ledger = validate_ledger(trusted_ledger_value)
    if not diff["hasExpansion"]:
        return {
            "allowed": True,
            "authorizationRequired": False,
            "authorizationId": None,
            "baseBomSha256": diff["baseBomSha256"],
            "candidateBomSha256": diff["candidateBomSha256"],
            "expansionSha256": diff["expansionSha256"],
        }

    matches = [entry for entry in ledger["authorizations"] if (
        entry["baseBomSha256"] == diff["baseBomSha256"]
        and entry["candidateBomSha256"] == diff["candidateBomSha256"]
        and entry["expansionSha256"] == diff["expansionSha256"]
    )]
    require(len(matches) == 1,
            "capability expansion lacks exactly one prior trusted authorization: "
            f"matches={len(matches)} base={diff['baseBomSha256']} "
            f"candidate={diff['candidateBomSha256']} expansion={diff['expansionSha256']}")
    return {
        "allowed": True,
        "authorizationRequired": True,
        "authorizationId": matches[0]["id"],
        "baseBomSha256": diff["baseBomSha256"],
        "candidateBomSha256": diff["candidateBomSha256"],
        "expansionSha256": diff["expansionSha256"],
    }


def empty_ledger() -> dict[str, Any]:
    return {
        "schemaVersion": SCHEMA_VERSION,
        "ledgerId": LEDGER_ID,
        "repository": REPOSITORY,
        "authorizations": [],
    }


def fixture_diff(*, expansion: bool = True) -> dict[str, Any]:
    base = capability_diff.fixture()
    candidate = copy.deepcopy(base)
    candidate["workflows"][0]["jobs"][0]["permissions"]["contents"] = "write" if expansion else "none"
    return capability_diff.semantic_diff(base, candidate)


def source_only_fixture_diff() -> dict[str, Any]:
    base = capability_diff.fixture()
    diff = capability_diff.semantic_diff(base, copy.deepcopy(base))
    diff["expansions"] = [{
        "direction": "expansion",
        "category": "trusted-control-source",
        "workflow": "capability-admission",
        "key": "scripts/json.py",
        "before": None,
        "after": {"sha256": "a" * 64, "candidateTcbSha256": "b" * 64},
    }]
    diff["hasExpansion"] = True
    diff["expansionSha256"] = capability_diff.digest(diff["expansions"])
    return diff


def matching_entry(diff: dict[str, Any], identity: str = "cap-self-test") -> dict[str, Any]:
    return {
        "id": identity,
        "baseBomSha256": diff["baseBomSha256"],
        "candidateBomSha256": diff["candidateBomSha256"],
        "expansionSha256": diff["expansionSha256"],
        "rationale": "Reviewed exact capability expansion fixture.",
    }


def expect_failure(callback, fragment: str) -> None:
    try:
        callback()
    except ValueError as exc:
        require(fragment in str(exc), f"capability authorization self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"capability authorization self-test accepted forbidden input: {fragment}")


def self_test() -> None:
    no_expansion = fixture_diff(expansion=False)
    decision = authorize(no_expansion, empty_ledger())
    require(decision["allowed"] and not decision["authorizationRequired"] and decision["authorizationId"] is None,
            "restriction-only capability diff incorrectly required authorization")

    expansion = fixture_diff(expansion=True)
    expect_failure(lambda: authorize(expansion, empty_ledger()), "lacks exactly one prior trusted authorization")
    trusted = empty_ledger()
    trusted["authorizations"].append(matching_entry(expansion))
    decision = authorize(expansion, trusted)
    require(decision["allowed"] and decision["authorizationRequired"] and decision["authorizationId"] == "cap-self-test",
            "exact prior authorization was not accepted")

    source_expansion = source_only_fixture_diff()
    require(source_expansion["baseBomSha256"] == source_expansion["candidateBomSha256"],
            "source-only fixture unexpectedly changed the semantic BOM")
    expect_failure(lambda: authorize(source_expansion, empty_ledger()), "lacks exactly one prior trusted authorization")
    source_trusted = empty_ledger()
    source_trusted["authorizations"].append(matching_entry(source_expansion, "cap-source-self-test"))
    source_decision = authorize(source_expansion, source_trusted)
    require(source_decision["allowed"] and source_decision["authorizationRequired"]
            and source_decision["authorizationId"] == "cap-source-self-test",
            "exact prior source-only authorization was not accepted")

    stale = copy.deepcopy(trusted)
    stale["authorizations"][0]["baseBomSha256"] = "0" * 64
    expect_failure(lambda: authorize(expansion, stale), "lacks exactly one prior trusted authorization")
    wrong_candidate = copy.deepcopy(trusted)
    wrong_candidate["authorizations"][0]["candidateBomSha256"] = "1" * 64
    expect_failure(lambda: authorize(expansion, wrong_candidate), "lacks exactly one prior trusted authorization")
    partial = copy.deepcopy(trusted)
    partial["authorizations"][0]["expansionSha256"] = "2" * 64
    expect_failure(lambda: authorize(expansion, partial), "lacks exactly one prior trusted authorization")

    forged = copy.deepcopy(expansion)
    forged["expansionSha256"] = "3" * 64
    expect_failure(lambda: authorize(forged, trusted), "expansion digest does not bind")

    duplicate = copy.deepcopy(trusted)
    duplicate["authorizations"].append(matching_entry(expansion, "cap-self-test-two"))
    expect_failure(lambda: validate_ledger(duplicate), "semantic target is duplicated")

    unsorted = copy.deepcopy(trusted)
    unsorted["authorizations"] = [
        {**matching_entry(expansion, "cap-z-last"), "candidateBomSha256": "4" * 64},
        matching_entry(expansion, "cap-a-first"),
    ]
    expect_failure(lambda: validate_ledger(unsorted), "strictly sorted by id")

    unknown = copy.deepcopy(trusted)
    unknown["authorizations"][0]["reviewer"] = "self-asserted"
    expect_failure(lambda: validate_ledger(unknown), "keys changed")

    candidate_only = empty_ledger()
    candidate_only["authorizations"].append(matching_entry(expansion))
    expect_failure(lambda: authorize(expansion, empty_ledger()), "lacks exactly one prior trusted authorization")
    require(authorize(expansion, candidate_only)["authorizationId"] == "cap-self-test",
            "self-test fixture for prior trusted authorization is malformed")


if __name__ == "__main__":
    self_test()
    print("Workflow Capability expansion authorization self-test passed.")
