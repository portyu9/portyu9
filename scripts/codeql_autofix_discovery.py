#!/usr/bin/env python3
"""Pure read-only contract for discovering CodeQL alerts eligible for Autofix consideration.

Production automation will fetch GitHub API responses with trusted workflow code and pass the
resulting JSON into these helpers as data. This module performs no network calls and no
repository mutation. It fails closed on incomplete pagination, malformed alert identity,
stale default-branch analysis, duplicate alert numbers, or unknown Autofix status values.
"""
from __future__ import annotations

import copy
import re
from typing import Any, Mapping, Sequence

REPOSITORY = "portyu9/portyu9"
DEFAULT_REF = "refs/heads/main"
TOOL_NAME = "CodeQL"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$")
SAFE_PATH = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9_.@/+ -]{1,500}$")
KNOWN_AUTOFIX_STATUS = {"pending", "success", "error"}


class DiscoveryError(ValueError):
    """Stable fail-closed rejection for untrusted GitHub API response data."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise DiscoveryError(message)


def require_sha(value: Any, label: str) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None,
            f"{label} must be an exact lowercase SHA-40")
    return value


def require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    require(isinstance(value, Mapping), f"{label} must be an object")
    return value


def require_text(value: Any, label: str, *, maximum: int = 500) -> str:
    require(isinstance(value, str) and value.strip() == value and 1 <= len(value) <= maximum,
            f"{label} must be a non-empty trimmed string")
    require(not any(char in value for char in ("\x00", "\r", "\n")),
            f"{label} contains forbidden control characters")
    return value


def normalize_optional_metadata(value: Any, label: str, *, maximum: int) -> str | None:
    if value is None:
        return None
    require(isinstance(value, str), f"{label} must be a string or null")
    normalized = value.strip()
    if normalized == "":
        return None
    return require_text(normalized, label, maximum=maximum)


def normalize_description_metadata(value: Any, label: str, *, maximum: int) -> str | None:
    """Canonicalize GitHub's explanatory Autofix prose without changing authority semantics."""
    if value is None:
        return None
    require(isinstance(value, str), f"{label} must be a string or null")
    require("\x00" not in value, f"{label} contains forbidden control characters")
    normalized = " ".join(value.split())
    if normalized == "":
        return None
    return require_text(normalized, label, maximum=maximum)


def normalize_location(value: Any) -> dict[str, Any]:
    location = require_mapping(value, "CodeQL alert location")
    path = require_text(location.get("path"), "CodeQL alert path")
    require(SAFE_PATH.fullmatch(path) is not None, "CodeQL alert path is not a canonical repository-relative path")
    start_line = location.get("start_line")
    end_line = location.get("end_line")
    require(isinstance(start_line, int) and not isinstance(start_line, bool) and start_line > 0,
            "CodeQL alert start_line must be a positive integer")
    require(isinstance(end_line, int) and not isinstance(end_line, bool) and end_line >= start_line,
            "CodeQL alert end_line must be an integer at or after start_line")
    return {"path": path, "startLine": start_line, "endLine": end_line}


def normalize_alert(value: Any, *, base_sha: str) -> dict[str, Any]:
    """Normalize one open CodeQL alert that is proven to come from the exact main SHA."""
    base_sha = require_sha(base_sha, "base_sha")
    alert = require_mapping(value, "CodeQL alert")

    number = alert.get("number")
    require(isinstance(number, int) and not isinstance(number, bool) and number > 0,
            "CodeQL alert number must be a positive integer")
    require(alert.get("state") == "open", f"CodeQL alert {number} is not open")

    tool = require_mapping(alert.get("tool"), f"CodeQL alert {number} tool")
    require(tool.get("name") == TOOL_NAME, f"CodeQL alert {number} tool identity changed")

    rule = require_mapping(alert.get("rule"), f"CodeQL alert {number} rule")
    rule_id = require_text(rule.get("id"), f"CodeQL alert {number} rule id", maximum=200)
    require(RULE_ID.fullmatch(rule_id) is not None, f"CodeQL alert {number} rule id is not canonical")
    severity = rule.get("security_severity_level")
    if severity is not None:
        severity = require_text(severity, f"CodeQL alert {number} security severity", maximum=32).lower()

    instance = require_mapping(alert.get("most_recent_instance"), f"CodeQL alert {number} instance")
    require(instance.get("ref") == DEFAULT_REF,
            f"CodeQL alert {number} is not bound to the default branch")
    instance_sha = require_sha(instance.get("commit_sha"), f"CodeQL alert {number} instance commit")
    require(instance_sha == base_sha,
            f"CodeQL alert {number} is stale relative to the exact default-branch SHA")
    require(instance.get("state") == "open",
            f"CodeQL alert {number} most recent instance is not open")

    return {
        "number": number,
        "ruleId": rule_id,
        "securitySeverity": severity,
        "baseRef": DEFAULT_REF,
        "baseSha": base_sha,
        "location": normalize_location(instance.get("location")),
    }


def discover(
    alerts: Any,
    *,
    base_sha: str,
    pagination_complete: bool,
) -> dict[str, Any]:
    """Return exact-main open CodeQL alerts in deterministic alert-number order.

    Non-CodeQL or non-open records are ignored because the repository code-scanning endpoint
    can contain findings from other tools/states. Open CodeQL records are never silently
    ignored: if their default-branch instance is stale or malformed, discovery fails closed.
    """
    base_sha = require_sha(base_sha, "base_sha")
    require(pagination_complete is True, "CodeQL discovery pagination is incomplete or ambiguous")
    require(isinstance(alerts, list), "CodeQL discovery response must be a list")

    seen: set[int] = set()
    result: list[dict[str, Any]] = []
    for raw in alerts:
        item = require_mapping(raw, "code-scanning alert list item")
        number = item.get("number")
        require(isinstance(number, int) and not isinstance(number, bool) and number > 0,
                "code-scanning alert list contains an invalid alert number")
        require(number not in seen, f"code-scanning alert list duplicates alert number: {number}")
        seen.add(number)

        if item.get("state") != "open":
            continue
        tool = require_mapping(item.get("tool"), f"code-scanning alert {number} tool")
        if tool.get("name") != TOOL_NAME:
            continue
        result.append(normalize_alert(item, base_sha=base_sha))

    result.sort(key=lambda alert: alert["number"])
    return {
        "repository": REPOSITORY,
        "baseRef": DEFAULT_REF,
        "baseSha": base_sha,
        "alerts": result,
    }


def select_one(discovery: Any) -> dict[str, Any] | None:
    """Select the lowest-number exact-main alert so each controller run handles at most one."""
    value = require_mapping(discovery, "CodeQL discovery record")
    require(value.get("repository") == REPOSITORY, "CodeQL discovery repository identity mismatch")
    require(value.get("baseRef") == DEFAULT_REF, "CodeQL discovery default ref mismatch")
    require_sha(value.get("baseSha"), "CodeQL discovery base SHA")
    alerts = value.get("alerts")
    require(isinstance(alerts, list), "CodeQL discovery alerts must be a list")
    if not alerts:
        return None
    numbers = [alert.get("number") if isinstance(alert, Mapping) else None for alert in alerts]
    require(all(isinstance(number, int) and not isinstance(number, bool) for number in numbers),
            "CodeQL discovery contains a malformed normalized alert")
    require(numbers == sorted(numbers) and len(numbers) == len(set(numbers)),
            "CodeQL discovery alerts must be strictly ordered and unique")
    return copy.deepcopy(alerts[0])


def normalize_autofix_status(alert: Mapping[str, Any], value: Any) -> dict[str, Any]:
    """Bind GitHub's Autofix status response to one previously normalized exact-main alert."""
    number = alert.get("number")
    base_sha = require_sha(alert.get("baseSha"), "Autofix alert base SHA")
    require(isinstance(number, int) and not isinstance(number, bool) and number > 0,
            "Autofix alert number is invalid")
    status_response = require_mapping(value, f"Autofix status for alert {number}")
    status = status_response.get("status")
    require(status in KNOWN_AUTOFIX_STATUS,
            f"Autofix status for alert {number} is unknown: {status!r}")
    description = normalize_description_metadata(
        status_response.get("description"),
        f"Autofix description for alert {number}",
        maximum=4000,
    )
    started_at = normalize_optional_metadata(
        status_response.get("started_at"),
        f"Autofix started_at for alert {number}",
        maximum=64,
    )
    return {
        "repository": REPOSITORY,
        "alertNumber": number,
        "ruleId": alert.get("ruleId"),
        "baseSha": base_sha,
        "status": status,
        "ready": status == "success",
        "description": description,
        "startedAt": started_at,
    }


def alert_fixture(*, number: int = 4, sha: str = "a" * 40) -> dict[str, Any]:
    return {
        "number": number,
        "state": "open",
        "rule": {
            "id": "py/clear-text-logging-sensitive-data",
            "security_severity_level": "high",
        },
        "tool": {"name": TOOL_NAME},
        "most_recent_instance": {
            "ref": DEFAULT_REF,
            "commit_sha": sha,
            "state": "open",
            "location": {
                "path": "scripts/example.py",
                "start_line": 12,
                "end_line": 12,
            },
        },
    }


def expect_failure(fn: Any, expected: str) -> None:
    try:
        fn()
    except DiscoveryError as exc:
        require(expected in str(exc), f"CodeQL discovery self-test failed for the wrong reason: {exc}")
    else:
        raise ValueError(f"CodeQL discovery self-test accepted forbidden case: {expected}")


def self_test() -> None:
    base = "a" * 40
    first = alert_fixture(number=4, sha=base)
    second = alert_fixture(number=9, sha=base)
    other_tool = copy.deepcopy(second)
    other_tool["number"] = 8
    other_tool["tool"]["name"] = "ThirdPartyScanner"
    closed = copy.deepcopy(second)
    closed["number"] = 7
    closed["state"] = "dismissed"

    record = discover([second, other_tool, closed, first], base_sha=base, pagination_complete=True)
    require([alert["number"] for alert in record["alerts"]] == [4, 9],
            "CodeQL discovery self-test did not deterministically select open CodeQL alerts")
    selected = select_one(record)
    require(selected is not None and selected["number"] == 4 and selected["baseSha"] == base,
            "CodeQL discovery self-test selected the wrong alert")

    ready = normalize_autofix_status(selected, {
        "status": "success",
        "description": "Replace the sensitive exception log with a constant message.",
        "started_at": "2026-09-15T22:00:00Z",
    })
    require(ready["ready"] is True and ready["alertNumber"] == 4,
            "Autofix status self-test did not recognize a successful exact alert")
    pending = normalize_autofix_status(selected, {"status": "pending", "description": None, "started_at": None})
    require(pending["ready"] is False, "Autofix status self-test treated pending as ready")
    blank_metadata = normalize_autofix_status(
        selected,
        {"status": "pending", "description": "   ", "started_at": "\t"},
    )
    require(
        blank_metadata["ready"] is False
        and blank_metadata["description"] is None
        and blank_metadata["startedAt"] is None,
        "Autofix status self-test did not canonicalize blank optional GitHub metadata",
    )
    padded_metadata = normalize_autofix_status(
        selected,
        {
            "status": "success",
            "description": "  Replace the sensitive exception log with a constant message.  ",
            "started_at": " 2026-09-15T22:00:00Z ",
        },
    )
    require(
        padded_metadata["description"] == "Replace the sensitive exception log with a constant message."
        and padded_metadata["startedAt"] == "2026-09-15T22:00:00Z",
        "Autofix status self-test did not canonicalize surrounding whitespace in optional GitHub metadata",
    )
    multiline_description = normalize_autofix_status(
        selected,
        {
            "status": "success",
            "description": "Replace the sensitive exception log\nwith a constant message.\r\nNo authority data is carried here.",
            "started_at": "2026-09-15T22:00:00Z",
        },
    )
    require(
        multiline_description["description"]
        == "Replace the sensitive exception log with a constant message. No authority data is carried here.",
        "Autofix status self-test did not canonicalize multiline explanatory description metadata",
    )
    expect_failure(
        lambda: normalize_autofix_status(
            selected,
            {"status": "pending", "description": "safe\x00unsafe", "started_at": None},
        ),
        "forbidden control characters",
    )
    expect_failure(
        lambda: normalize_autofix_status(
            selected,
            {"status": "pending", "description": {}, "started_at": None},
        ),
        "string or null",
    )

    expect_failure(lambda: discover([first], base_sha=base, pagination_complete=False), "pagination")
    expect_failure(lambda: discover([first, copy.deepcopy(first)], base_sha=base, pagination_complete=True), "duplicates")

    stale = copy.deepcopy(first)
    stale["most_recent_instance"]["commit_sha"] = "b" * 40
    expect_failure(lambda: discover([stale], base_sha=base, pagination_complete=True), "stale")

    wrong_ref = copy.deepcopy(first)
    wrong_ref["most_recent_instance"]["ref"] = "refs/heads/feature"
    expect_failure(lambda: discover([wrong_ref], base_sha=base, pagination_complete=True), "default branch")

    bad_path = copy.deepcopy(first)
    bad_path["most_recent_instance"]["location"]["path"] = "../escape.py"
    expect_failure(lambda: discover([bad_path], base_sha=base, pagination_complete=True), "canonical repository-relative")

    unknown = {"status": "mystery", "description": None, "started_at": None}
    expect_failure(lambda: normalize_autofix_status(selected, unknown), "unknown")

    empty = discover([], base_sha=base, pagination_complete=True)
    require(select_one(empty) is None, "empty CodeQL discovery must produce no remediation target")


def main() -> int:
    self_test()
    print(
        "CodeQL Autofix discovery self-test passed: complete pagination, exact main SHA binding, open CodeQL identity, "
        "deterministic one-alert selection, canonical location data, and known Autofix statuses are required."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())