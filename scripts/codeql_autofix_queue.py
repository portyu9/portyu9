#!/usr/bin/env python3
"""Pure queue semantics for bounded CodeQL Autofix attempts.

This module grants no API or repository authority. It consumes normalized discovery
records and explicit Autofix request outcomes as data so the production controller can
later distinguish GitHub's documented unsupported-Autofix response from ambiguous
failures without allowing one unsupported alert to starve later exact-main findings.
"""
from __future__ import annotations

import copy
from typing import Any, Mapping

from codeql_autofix_discovery import REPOSITORY, DEFAULT_REF, require, require_mapping, require_sha

UNSUPPORTED_STATUS = 422
UNSUPPORTED_MESSAGE = "Alert is not supported by autofix."


def ordered_targets(discovery: Any) -> list[dict[str, Any]]:
    """Return a defensive ordered copy of all exact-main normalized alerts."""
    value = require_mapping(discovery, "CodeQL discovery record")
    require(value.get("repository") == REPOSITORY, "CodeQL discovery repository identity mismatch")
    require(value.get("baseRef") == DEFAULT_REF, "CodeQL discovery default ref mismatch")
    base_sha = require_sha(value.get("baseSha"), "CodeQL discovery base SHA")
    alerts = value.get("alerts")
    require(isinstance(alerts, list), "CodeQL discovery alerts must be a list")

    numbers: list[int] = []
    targets: list[dict[str, Any]] = []
    for raw in alerts:
        alert = require_mapping(raw, "normalized CodeQL alert")
        number = alert.get("number")
        require(isinstance(number, int) and not isinstance(number, bool) and number > 0,
                "CodeQL discovery contains an invalid alert number")
        require(alert.get("baseSha") == base_sha,
                f"CodeQL alert {number} is not bound to the discovery base SHA")
        numbers.append(number)
        targets.append(copy.deepcopy(dict(alert)))

    require(numbers == sorted(numbers) and len(numbers) == len(set(numbers)),
            "CodeQL discovery alerts must be strictly ordered and unique")
    return targets


def classify_request_failure(*, http_status: Any, message: Any) -> dict[str, str]:
    """Classify only GitHub's exact known unsupported-Autofix response.

    Every other status/message pair remains an error so authentication, API, network,
    rate-limit, validation, and unexpected platform failures cannot be silently skipped.
    """
    require(isinstance(http_status, int) and not isinstance(http_status, bool),
            "Autofix request HTTP status must be an integer")
    require(isinstance(message, str), "Autofix request error message must be a string")
    if http_status == UNSUPPORTED_STATUS and message.strip() == UNSUPPORTED_MESSAGE:
        return {"classification": "unsupported", "reason": "github-autofix-unsupported"}
    raise ValueError(
        f"Autofix request failure is not a reviewed unsupported response: status={http_status} message={message!r}"
    )


def next_after_unsupported(discovery: Any, *, unsupported_alert: int) -> dict[str, Any] | None:
    """Return the next normalized target after one explicitly unsupported alert."""
    require(isinstance(unsupported_alert, int) and not isinstance(unsupported_alert, bool) and unsupported_alert > 0,
            "unsupported alert number must be a positive integer")
    targets = ordered_targets(discovery)
    numbers = [target["number"] for target in targets]
    require(unsupported_alert in numbers,
            "unsupported alert must be present in the exact discovery record")
    index = numbers.index(unsupported_alert)
    if index + 1 >= len(targets):
        return None
    return copy.deepcopy(targets[index + 1])


def self_test() -> None:
    sha = "a" * 40
    discovery = {
        "repository": REPOSITORY,
        "baseRef": DEFAULT_REF,
        "baseSha": sha,
        "alerts": [
            {"number": 10, "ruleId": "py/unsupported", "baseSha": sha},
            {"number": 11, "ruleId": "py/supported", "baseSha": sha},
            {"number": 12, "ruleId": "py/later", "baseSha": sha},
        ],
    }
    targets = ordered_targets(discovery)
    require([target["number"] for target in targets] == [10, 11, 12],
            "CodeQL queue changed deterministic alert ordering")
    targets[0]["number"] = 999
    require(discovery["alerts"][0]["number"] == 10,
            "CodeQL queue must not alias the trusted discovery record")

    unsupported = classify_request_failure(http_status=422, message=UNSUPPORTED_MESSAGE)
    require(unsupported == {"classification": "unsupported", "reason": "github-autofix-unsupported"},
            "CodeQL queue changed exact unsupported classification")
    require(next_after_unsupported(discovery, unsupported_alert=10)["number"] == 11,
            "CodeQL queue allowed an unsupported alert to starve the next target")
    require(next_after_unsupported(discovery, unsupported_alert=12) is None,
            "CodeQL queue invented a target after the final alert")

    for status, message in (
        (500, UNSUPPORTED_MESSAGE),
        (422, "Validation failed"),
        (403, "Resource not accessible by integration"),
        (429, "rate limited"),
    ):
        try:
            classify_request_failure(http_status=status, message=message)
        except ValueError:
            pass
        else:
            raise ValueError(f"CodeQL queue silently skipped non-reviewed failure: {status} {message}")

    malformed = copy.deepcopy(discovery)
    malformed["alerts"][1]["baseSha"] = "b" * 40
    try:
        ordered_targets(malformed)
    except ValueError as exc:
        require("discovery base SHA" in str(exc),
                f"CodeQL queue rejected stale target for the wrong reason: {exc}")
    else:
        raise ValueError("CodeQL queue accepted an alert from a different base SHA")


def main() -> int:
    self_test()
    print(
        "CodeQL Autofix queue self-test passed: only the exact GitHub 422 unsupported outcome is skippable, "
        "later exact-main alerts remain reachable, and all ambiguous failures stay fail-closed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
