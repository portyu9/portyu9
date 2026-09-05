#!/usr/bin/env python3
"""Validate Portfolio Evidence Ledger v2 semantics and live-collection retry policy."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import io
import json
import re
import urllib.error
from pathlib import Path
from typing import Any

VERSION = "portfolio-evidence-ledger-v2"
KIND = "portfolio-evidence-ledger"
OWNER = "portyu9"
FILENAME = "portfolio-evidence-ledger.json"
EVIDENCE_SEMANTICS = "execution-result-subject-binding-freshness-v1"
SHA40_ZERO = "0" * 40
SHA40 = re.compile(r"^[0-9a-f]{40}$")
EVIDENCE_ID = re.compile(r"^PL2-[0-9A-F]{16}$")
EVIDENCE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
GENERATOR = Path(__file__).with_name("generate-portfolio-evidence-ledger.py")

RESULTS = {
    "PASSING",
    "FAILING",
    "RUNNING",
    "CANCELLED",
    "SKIPPED",
    "NEUTRAL",
    "ACTION REQUIRED",
    "STALE",
    "UNKNOWN",
    "UNAVAILABLE",
    "NO SIGNAL",
}
BINDINGS = {
    "CURRENT_SUBJECT",
    "DIFFERENT_SUBJECT",
    "SUBJECT_UNAVAILABLE",
    "RUN_HEAD_UNAVAILABLE",
    "UNAVAILABLE",
    "SYNTHETIC",
}
FRESHNESS = {"SAME_DAY", "AGED", "UNAVAILABLE", "SYNTHETIC"}

PERMANENT = {
    "portyu9/ai-qa-automation",
    "portyu9/qa-automation-ai-agent-evals",
    "portyu9/qa-automation-graphql",
    "portyu9/qa-automation-visual-and-accessibility-playwright-axe",
}
ROTATING = {
    "portyu9/qa-automation-dotnet-selenium",
    "portyu9/qa-automation-api-postman-newman",
    "portyu9/qa-automation-mobile-appium",
    "portyu9/qa-automation-ui-cypress",
    "portyu9/qa-automation-python-pytest",
    "portyu9/qa-automation-node-supertest",
    "portyu9/qa-automation-java-restassured",
    "portyu9/qa-automation-node-playwright",
    "portyu9/qa-automation-load-k6",
}
EXPECTED = PERMANENT | ROTATING


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical_digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def load_generator() -> Any:
    require(GENERATOR.is_file(), "Portfolio evidence generator is missing")
    spec = importlib.util.spec_from_file_location("portfolio_evidence_retry_contract", GENERATOR)
    require(spec is not None and spec.loader is not None, "Portfolio evidence generator cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeResponse(io.StringIO):
    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


def fake_opener(outcomes: list[Any], calls: list[float]) -> Any:
    queue = list(outcomes)

    def opener(request: Any, *, timeout: float) -> FakeResponse:
        calls.append(timeout)
        require(queue, "retry self-test exhausted fake opener outcomes")
        outcome = queue.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        if isinstance(outcome, str):
            return FakeResponse(outcome)
        return FakeResponse(json.dumps(outcome))

    return opener


def http_error(code: int, headers: dict[str, str] | None = None) -> urllib.error.HTTPError:
    return urllib.error.HTTPError("https://api.github.com/test", code, "fixture", headers or {}, None)


def validate_retry_contract() -> None:
    generator = load_generator()
    require(generator.API_ATTEMPTS == 3, "GitHub evidence retry budget must remain exactly three attempts")
    require(generator.API_TIMEOUT_SECONDS == 12, "GitHub evidence request timeout changed")
    require(generator.API_BACKOFF_SECONDS == (1.0, 2.0), "GitHub evidence backoff schedule changed")
    require(generator.API_MAX_RETRY_AFTER_SECONDS == 5.0, "GitHub Retry-After cap changed")
    require(generator.RETRYABLE_HTTP_STATUS == frozenset({408, 429, 500, 502, 503, 504}), "retryable HTTP status allowlist changed")

    calls: list[float] = []
    sleeps: list[float] = []
    payload = generator.fetch_json(
        "https://api.github.com/test",
        None,
        opener=fake_opener(
            [
                urllib.error.URLError("connection reset"),
                http_error(503, {"Retry-After": "0"}),
                {"ok": True},
            ],
            calls,
        ),
        sleeper=sleeps.append,
    )
    require(payload == {"ok": True}, "transient retry fixture did not return successful payload")
    require(calls == [12, 12, 12], "transient retry fixture did not use exactly three bounded attempts")
    require(sleeps == [1.0, 0.0], "transient retry fixture backoff sequence changed")

    rate_calls: list[float] = []
    rate_sleeps: list[float] = []
    payload = generator.fetch_json(
        "https://api.github.com/test",
        None,
        opener=fake_opener(
            [http_error(403, {"X-RateLimit-Remaining": "0", "Retry-After": "1"}), {"rate": "recovered"}],
            rate_calls,
        ),
        sleeper=rate_sleeps.append,
    )
    require(payload == {"rate": "recovered"}, "rate-limit retry fixture did not recover")
    require(rate_calls == [12, 12] and rate_sleeps == [1.0], "rate-limit retry behavior changed")
    require(
        generator.retry_delay_seconds(http_error(429, {"Retry-After": "999"}), 0) == 5.0,
        "Retry-After must remain capped at five seconds",
    )

    forbidden_calls: list[float] = []
    forbidden_sleeps: list[float] = []
    try:
        generator.fetch_json(
            "https://api.github.com/test",
            None,
            opener=fake_opener([http_error(403)], forbidden_calls),
            sleeper=forbidden_sleeps.append,
        )
    except urllib.error.HTTPError as exc:
        require(exc.code == 403, "non-retryable HTTP fixture failed for wrong reason")
    else:
        raise ValueError("ordinary 403 was incorrectly retried or accepted")
    require(forbidden_calls == [12] and forbidden_sleeps == [], "ordinary 403 must fail on the first attempt")

    malformed_calls: list[float] = []
    malformed_sleeps: list[float] = []
    try:
        generator.fetch_json(
            "https://api.github.com/test",
            None,
            opener=fake_opener(["{"], malformed_calls),
            sleeper=malformed_sleeps.append,
        )
    except json.JSONDecodeError:
        pass
    else:
        raise ValueError("malformed GitHub JSON was incorrectly retried or accepted")
    require(malformed_calls == [12] and malformed_sleeps == [], "malformed JSON must fail without retry")

    exhausted_calls: list[float] = []
    exhausted_sleeps: list[float] = []
    try:
        generator.fetch_json(
            "https://api.github.com/test",
            None,
            opener=fake_opener([http_error(502), http_error(502), http_error(502)], exhausted_calls),
            sleeper=exhausted_sleeps.append,
        )
    except urllib.error.HTTPError as exc:
        require(exc.code == 502, "exhausted retry fixture failed for wrong reason")
    else:
        raise ValueError("exhausted retry budget did not fail closed")
    require(exhausted_calls == [12, 12, 12], "retry budget exceeded or shortened the three-attempt contract")
    require(exhausted_sleeps == [1.0, 2.0], "retry exhaustion backoff sequence changed")

    source = GENERATOR.read_text(encoding="utf-8")
    for forbidden in ("evidence.main_revision(", "evidence.latest_workflow_run(", "evidence.workflow_jobs("):
        require(forbidden not in source, f"production Ledger collection bypasses bounded retry layer: {forbidden}")


def validate_dimensions(repository: str, subject: str, signal: dict[str, Any], require_live: bool) -> None:
    label = signal.get("label")
    workflow = signal.get("workflow")
    result = signal.get("result")
    binding = signal.get("binding")
    freshness = signal.get("freshness")
    require(isinstance(label, str) and label, f"{repository}: evidence label is missing")
    require(isinstance(workflow, str) and workflow.endswith((".yml", ".yaml")), f"{repository} {label}: workflow is invalid")
    require(isinstance(signal.get("scope"), str) and signal.get("scope"), f"{repository} {label}: scope is missing")
    require(result in RESULTS, f"{repository} {label}: execution result is invalid: {result!r}")
    require(result != "STALE", f"{repository} {label}: STALE must not be encoded as an execution result")
    require(binding in BINDINGS, f"{repository} {label}: subject binding is invalid: {binding!r}")
    require(freshness in FRESHNESS, f"{repository} {label}: freshness state is invalid: {freshness!r}")
    require("signal" not in signal, f"{repository} {label}: legacy conflated signal field is forbidden in Ledger v2")

    age = signal.get("age_days")
    require(isinstance(age, int) and age >= 0, f"{repository} {label}: age is invalid")
    ordinal = signal.get("ordinal")
    require(isinstance(ordinal, int) and ordinal >= 1, f"{repository} {label}: ordinal is invalid")
    offline = signal.get("offline")
    require(isinstance(offline, bool), f"{repository} {label}: offline marker is invalid")
    head = signal.get("head_sha")
    require(isinstance(head, str) and SHA40.fullmatch(head) is not None, f"{repository} {label}: workflow head SHA is malformed")
    run_id = signal.get("run_id")
    run_number = signal.get("run_number")
    require(isinstance(run_id, int) and run_id >= 0, f"{repository} {label}: run id is invalid")
    require(isinstance(run_number, int) and run_number >= 0, f"{repository} {label}: run number is invalid")
    completed = signal.get("completed_at_utc")
    require(isinstance(completed, str), f"{repository} {label}: evidence timestamp is invalid")

    if binding == "SYNTHETIC":
        require(offline is True, f"{repository} {label}: SYNTHETIC binding requires offline evidence")
    elif binding == "UNAVAILABLE":
        require(run_id == 0 and head == SHA40_ZERO, f"{repository} {label}: unavailable binding must have no run head")
    elif binding == "SUBJECT_UNAVAILABLE":
        require(subject == SHA40_ZERO and run_id > 0, f"{repository} {label}: SUBJECT_UNAVAILABLE consistency failed")
    elif binding == "RUN_HEAD_UNAVAILABLE":
        require(subject != SHA40_ZERO and head == SHA40_ZERO and run_id > 0, f"{repository} {label}: RUN_HEAD_UNAVAILABLE consistency failed")
    elif binding == "CURRENT_SUBJECT":
        require(subject != SHA40_ZERO and head == subject and run_id > 0, f"{repository} {label}: CURRENT_SUBJECT binding is false")
    elif binding == "DIFFERENT_SUBJECT":
        require(subject != SHA40_ZERO and head != SHA40_ZERO and head != subject and run_id > 0, f"{repository} {label}: DIFFERENT_SUBJECT binding is false")

    if freshness == "SYNTHETIC":
        require(offline is True and completed.endswith("Z"), f"{repository} {label}: synthetic freshness is inconsistent")
    elif freshness == "UNAVAILABLE":
        require(completed == "", f"{repository} {label}: unavailable freshness must not carry a timestamp")
    elif freshness == "SAME_DAY":
        require(completed.endswith("Z") and age == 0, f"{repository} {label}: SAME_DAY freshness is inconsistent")
    elif freshness == "AGED":
        require(completed.endswith("Z") and age > 0, f"{repository} {label}: AGED freshness is inconsistent")

    if run_id > 0:
        run_url = signal.get("run_url")
        require(
            isinstance(run_url, str) and run_url == f"https://github.com/{repository}/actions/runs/{run_id}",
            f"{repository} {label}: exact run URL is invalid",
        )

    if require_live:
        require(offline is False, f"{repository} {label}: live ledger cannot contain synthetic evidence")
        require(subject != SHA40_ZERO, f"{repository}: current main revision is unavailable")
        require(result not in {"UNAVAILABLE", "NO SIGNAL", "UNKNOWN"}, f"{repository} {label}: live result is unavailable: {result}")
        require(binding not in {"UNAVAILABLE", "SUBJECT_UNAVAILABLE", "RUN_HEAD_UNAVAILABLE", "SYNTHETIC"}, f"{repository} {label}: live binding is unavailable: {binding}")
        require(freshness in {"SAME_DAY", "AGED"}, f"{repository} {label}: live freshness is unavailable")
        require(run_id > 0 and run_number > 0, f"{repository} {label}: live run provenance is missing")


def summary(systems: list[dict[str, Any]], field: str) -> dict[str, int]:
    result: dict[str, int] = {}
    for system in systems:
        for signal in system["signals"]:
            value = str(signal[field])
            result[value] = result.get(value, 0) + 1
    return dict(sorted(result.items()))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--require-live", action="store_true")
    args = parser.parse_args()
    try:
        validate_retry_contract()
        path = args.directory / FILENAME
        require(path.is_file(), "Portfolio evidence ledger is missing")
        ledger = json.loads(path.read_text(encoding="utf-8"))
        require(isinstance(ledger, dict), "Portfolio evidence ledger must be a JSON object")
        require(ledger.get("version") == VERSION, "Portfolio evidence ledger version changed")
        require(ledger.get("kind") == KIND, "Portfolio evidence ledger kind changed")
        require(ledger.get("owner") == OWNER, "Portfolio evidence ledger owner changed")
        require(re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(ledger.get("as_of_date_utc") or "")) is not None, "Ledger UTC date is invalid")
        require(ledger.get("evidence_semantics") == EVIDENCE_SEMANTICS, "Ledger evidence semantics changed")
        require(ledger.get("subject_policy") == "current-main-revision-per-system", "Ledger subject policy changed")
        require(ledger.get("freshness_basis") == "UTC whole-day age from workflow evidence timestamp", "Ledger freshness basis changed")
        require(
            ledger.get("classification_policy") == "four permanent profile systems plus nine rotating Spotlight systems",
            "Ledger classification policy changed",
        )
        require(ledger.get("system_count") == 13, "Ledger must contain exactly 13 reviewed systems")
        require("signal_summary" not in ledger, "Legacy conflated signal summary is forbidden in Ledger v2")

        systems = ledger.get("systems")
        require(isinstance(systems, list) and len(systems) == 13, "Ledger systems array must contain exactly 13 systems")
        repos = [system.get("repository") for system in systems if isinstance(system, dict)]
        require(len(repos) == 13 and len(set(repos)) == 13, "Ledger repositories must be 13 distinct values")
        require(set(repos) == EXPECTED, "Ledger reviewed repository inventory changed")

        for system in systems:
            require(isinstance(system, dict), "Ledger system entry must be an object")
            repository = str(system.get("repository") or "")
            expected_class = "permanent" if repository in PERMANENT else "rotating"
            require(system.get("classification") == expected_class, f"{repository}: portfolio classification changed")
            require(isinstance(system.get("title"), str) and system.get("title"), f"{repository}: title is missing")
            subject = system.get("subject_revision")
            require(isinstance(subject, str) and SHA40.fullmatch(subject) is not None, f"{repository}: subject revision is malformed")
            require(isinstance(system.get("evidence_max_age_days"), int) and system["evidence_max_age_days"] >= 0, f"{repository}: evidence age is invalid")

            contract = system.get("evidence_contract")
            signals = system.get("signals")
            require(isinstance(contract, list) and contract, f"{repository}: evidence contract is missing")
            require(isinstance(signals, list) and signals, f"{repository}: evidence dimensions are missing")
            require(len(contract) == len(signals), f"{repository}: evidence contract/record count diverged")
            contract_keys = [(entry.get("label"), entry.get("workflow"), entry.get("scope")) for entry in contract]
            signal_keys = [(entry.get("label"), entry.get("workflow"), entry.get("scope")) for entry in signals]
            require(contract_keys == signal_keys, f"{repository}: evidence records do not match declared contract")
            require(len({entry.get("label") for entry in signals}) == len(signals), f"{repository}: evidence labels must be distinct")
            available_ages = [int(signal["age_days"]) for signal in signals if signal.get("freshness") != "UNAVAILABLE"]
            require(system["evidence_max_age_days"] == max(available_ages, default=0), f"{repository}: maximum evidence age is inconsistent")
            for signal in signals:
                validate_dimensions(repository, str(subject), signal, args.require_live)

        require(ledger.get("result_summary") == summary(systems, "result"), "Ledger result summary does not match evidence records")
        require(ledger.get("binding_summary") == summary(systems, "binding"), "Ledger binding summary does not match evidence records")
        require(ledger.get("freshness_summary") == summary(systems, "freshness"), "Ledger freshness summary does not match evidence records")

        evidence_id = ledger.get("evidence_id")
        evidence_digest = ledger.get("evidence_digest")
        require(isinstance(evidence_id, str) and EVIDENCE_ID.fullmatch(evidence_id) is not None, "Portfolio Evidence ID is malformed")
        require(isinstance(evidence_digest, str) and EVIDENCE_DIGEST.fullmatch(evidence_digest) is not None, "Portfolio evidence digest is malformed")
        core = {key: value for key, value in ledger.items() if key not in {"evidence_id", "evidence_digest"}}
        digest = canonical_digest(core)
        require(evidence_digest == f"sha256:{digest}", "Portfolio evidence digest does not match canonical ledger bytes")
        require(evidence_id == f"PL2-{digest[:16].upper()}", "Portfolio Evidence ID does not match canonical ledger digest")

        print(
            f"Portfolio evidence ledger v2 validation passed: {evidence_id} binds 13 reviewed systems with "
            "independent execution result, subject binding, UTC freshness, and a bounded fail-closed GitHub API retry contract."
        )
        return 0
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
