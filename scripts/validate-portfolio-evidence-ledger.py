#!/usr/bin/env python3
"""Validate Portfolio Evidence Ledger v2 against the canonical portfolio registry."""
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

import portfolio_system_registry as registry

VERSION = "portfolio-evidence-ledger-v2"
KIND = "portfolio-evidence-ledger"
OWNER = registry.OWNER
FILENAME = "portfolio-evidence-ledger.json"
EVIDENCE_SEMANTICS = "execution-result-subject-binding-freshness-v1"
SHA40_ZERO = "0" * 40
SHA40 = re.compile(r"^[0-9a-f]{40}$")
EVIDENCE_ID = re.compile(r"^PL2-[0-9A-F]{16}$")
EVIDENCE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
GENERATOR = Path(__file__).with_name("generate-portfolio-evidence-ledger.py")

RESULTS = {
    "PASSING", "FAILING", "RUNNING", "CANCELLED", "SKIPPED", "NEUTRAL",
    "ACTION REQUIRED", "STALE_RESULT", "UNKNOWN", "UNAVAILABLE", "NO SIGNAL",
}
BINDINGS = {
    "CURRENT_SUBJECT", "DIFFERENT_SUBJECT", "SUBJECT_UNAVAILABLE",
    "RUN_HEAD_UNAVAILABLE", "UNAVAILABLE", "SYNTHETIC",
}
FRESHNESS = {"SAME_DAY", "AGED", "UNAVAILABLE", "SYNTHETIC"}


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
        "https://api.github.com/test", None,
        opener=fake_opener([urllib.error.URLError("connection reset"), http_error(503, {"Retry-After": "0"}), {"ok": True}], calls),
        sleeper=sleeps.append,
    )
    require(payload == {"ok": True}, "transient retry fixture did not recover")
    require(calls == [12, 12, 12] and sleeps == [1.0, 0.0], "transient retry behavior changed")

    rate_calls: list[float] = []
    rate_sleeps: list[float] = []
    payload = generator.fetch_json(
        "https://api.github.com/test", None,
        opener=fake_opener([http_error(403, {"X-RateLimit-Remaining": "0", "Retry-After": "1"}), {"rate": "recovered"}], rate_calls),
        sleeper=rate_sleeps.append,
    )
    require(payload == {"rate": "recovered"} and rate_calls == [12, 12] and rate_sleeps == [1.0], "rate-limit retry behavior changed")
    require(generator.retry_delay_seconds(http_error(429, {"Retry-After": "999"}), 0) == 5.0, "Retry-After cap changed")

    forbidden_calls: list[float] = []
    try:
        generator.fetch_json("https://api.github.com/test", None, opener=fake_opener([http_error(403)], forbidden_calls), sleeper=lambda _: None)
    except urllib.error.HTTPError as exc:
        require(exc.code == 403, "non-retryable HTTP fixture failed for wrong reason")
    else:
        raise ValueError("ordinary 403 was incorrectly retried or accepted")
    require(forbidden_calls == [12], "ordinary 403 must fail on first attempt")

    malformed_calls: list[float] = []
    try:
        generator.fetch_json("https://api.github.com/test", None, opener=fake_opener(["{"], malformed_calls), sleeper=lambda _: None)
    except json.JSONDecodeError:
        pass
    else:
        raise ValueError("malformed JSON was incorrectly retried or accepted")
    require(malformed_calls == [12], "malformed JSON must fail without retry")

    exhausted_calls: list[float] = []
    exhausted_sleeps: list[float] = []
    try:
        generator.fetch_json(
            "https://api.github.com/test", None,
            opener=fake_opener([http_error(502), http_error(502), http_error(502)], exhausted_calls),
            sleeper=exhausted_sleeps.append,
        )
    except urllib.error.HTTPError as exc:
        require(exc.code == 502, "exhausted retry fixture failed for wrong reason")
    else:
        raise ValueError("exhausted retry budget did not fail closed")
    require(exhausted_calls == [12, 12, 12] and exhausted_sleeps == [1.0, 2.0], "retry exhaustion behavior changed")


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
    require(binding in BINDINGS, f"{repository} {label}: subject binding is invalid: {binding!r}")
    require(freshness in FRESHNESS, f"{repository} {label}: freshness state is invalid: {freshness!r}")
    require("signal" not in signal, f"{repository} {label}: legacy conflated signal field is forbidden")
    age = signal.get("age_days")
    ordinal = signal.get("ordinal")
    offline = signal.get("offline")
    head = signal.get("head_sha")
    run_id = signal.get("run_id")
    run_number = signal.get("run_number")
    completed = signal.get("completed_at_utc")
    require(isinstance(age, int) and age >= 0, f"{repository} {label}: age is invalid")
    require(isinstance(ordinal, int) and ordinal >= 1, f"{repository} {label}: ordinal is invalid")
    require(isinstance(offline, bool), f"{repository} {label}: offline marker is invalid")
    require(isinstance(head, str) and SHA40.fullmatch(head) is not None, f"{repository} {label}: workflow head SHA is malformed")
    require(isinstance(run_id, int) and run_id >= 0, f"{repository} {label}: run id is invalid")
    require(isinstance(run_number, int) and run_number >= 0, f"{repository} {label}: run number is invalid")
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
        require(subject != SHA40_ZERO and head not in {SHA40_ZERO, subject} and run_id > 0, f"{repository} {label}: DIFFERENT_SUBJECT binding is false")

    if freshness == "SYNTHETIC":
        require(offline is True and completed.endswith("Z"), f"{repository} {label}: synthetic freshness is inconsistent")
    elif freshness == "UNAVAILABLE":
        require(completed == "", f"{repository} {label}: unavailable freshness must not carry a timestamp")
    elif freshness == "SAME_DAY":
        require(completed.endswith("Z") and age == 0, f"{repository} {label}: SAME_DAY freshness is inconsistent")
    elif freshness == "AGED":
        require(completed.endswith("Z") and age > 0, f"{repository} {label}: AGED freshness is inconsistent")

    if run_id > 0:
        require(signal.get("run_url") == f"https://github.com/{repository}/actions/runs/{run_id}", f"{repository} {label}: exact run URL is invalid")
    if require_live:
        require(offline is False and subject != SHA40_ZERO, f"{repository} {label}: live evidence subject is unavailable")
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


def expected_contract(entry: dict[str, Any]) -> list[dict[str, str]]:
    return [
        {"label": str(spec["label"]), "workflow": str(spec["workflow"]), "scope": registry.evidence_scope(spec)}
        for spec in entry["evidence"]
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    parser.add_argument("--require-live", action="store_true")
    args = parser.parse_args()
    try:
        validate_retry_contract()
        reviewed = registry.system_by_repo()
        path = args.directory / FILENAME
        require(path.is_file(), "Portfolio evidence ledger is missing")
        ledger = json.loads(path.read_text(encoding="utf-8"))
        require(isinstance(ledger, dict), "Portfolio evidence ledger must be a JSON object")
        require(ledger.get("version") == VERSION and ledger.get("kind") == KIND and ledger.get("owner") == OWNER, "Portfolio ledger identity changed")
        require(re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(ledger.get("as_of_date_utc") or "")) is not None, "Ledger UTC date is invalid")
        require(ledger.get("evidence_semantics") == EVIDENCE_SEMANTICS, "Ledger evidence semantics changed")
        require(ledger.get("subject_policy") == "current-main-revision-per-system", "Ledger subject policy changed")
        require(ledger.get("freshness_basis") == "UTC whole-day age from workflow evidence timestamp", "Ledger freshness basis changed")
        require(ledger.get("classification_policy") == registry.CLASSIFICATION_POLICY, "Ledger classification policy changed")
        provenance = ledger.get("portfolio_registry")
        require(isinstance(provenance, dict), "Ledger registry provenance is missing")
        require(provenance.get("version") == registry.VERSION, "Ledger registry version changed")
        require(provenance.get("digest") == registry.registry_digest(), "Ledger registry digest does not match reviewed registry bytes")
        require(ledger.get("system_count") == 13 and "signal_summary" not in ledger, "Ledger system count/semantics changed")

        systems = ledger.get("systems")
        require(isinstance(systems, list) and len(systems) == 13, "Ledger systems array must contain 13 systems")
        repos = [str(system.get("repository") or "") for system in systems if isinstance(system, dict)]
        expected_repos = {f"{OWNER}/{repo}" for repo in reviewed}
        require(len(repos) == len(set(repos)) == 13 and set(repos) == expected_repos, "Ledger reviewed repository inventory changed")

        for system in systems:
            require(isinstance(system, dict), "Ledger system entry must be an object")
            repository = str(system.get("repository") or "")
            slug = repository.split("/", 1)[1]
            reviewed_entry = reviewed[slug]
            require(system.get("classification") == reviewed_entry["classification"], f"{repository}: portfolio classification differs from registry")
            require(system.get("title") == reviewed_entry["title"], f"{repository}: title differs from registry")
            require(system.get("evidence_contract") == expected_contract(reviewed_entry), f"{repository}: evidence contract differs from registry")
            subject = system.get("subject_revision")
            require(isinstance(subject, str) and SHA40.fullmatch(subject) is not None, f"{repository}: subject revision is malformed")
            require(isinstance(system.get("evidence_max_age_days"), int) and system["evidence_max_age_days"] >= 0, f"{repository}: evidence age is invalid")
            contract = system["evidence_contract"]
            signals = system.get("signals")
            require(isinstance(signals, list) and len(signals) == len(contract), f"{repository}: evidence contract/record count diverged")
            require([(e.get("label"), e.get("workflow"), e.get("scope")) for e in contract] == [(e.get("label"), e.get("workflow"), e.get("scope")) for e in signals], f"{repository}: evidence records do not match declared contract")
            require(len({entry.get("label") for entry in signals}) == len(signals), f"{repository}: evidence labels must be distinct")
            available_ages = [int(signal["age_days"]) for signal in signals if signal.get("freshness") != "UNAVAILABLE"]
            require(system["evidence_max_age_days"] == max(available_ages, default=0), f"{repository}: maximum evidence age is inconsistent")
            for signal in signals:
                validate_dimensions(repository, str(subject), signal, args.require_live)

        require(ledger.get("result_summary") == summary(systems, "result"), "Ledger result summary does not match records")
        require(ledger.get("binding_summary") == summary(systems, "binding"), "Ledger binding summary does not match records")
        require(ledger.get("freshness_summary") == summary(systems, "freshness"), "Ledger freshness summary does not match records")
        evidence_id = ledger.get("evidence_id")
        evidence_digest = ledger.get("evidence_digest")
        require(isinstance(evidence_id, str) and EVIDENCE_ID.fullmatch(evidence_id) is not None, "Portfolio Evidence ID is malformed")
        require(isinstance(evidence_digest, str) and EVIDENCE_DIGEST.fullmatch(evidence_digest) is not None, "Portfolio evidence digest is malformed")
        core = {key: value for key, value in ledger.items() if key not in {"evidence_id", "evidence_digest"}}
        digest = canonical_digest(core)
        require(evidence_digest == f"sha256:{digest}" and evidence_id == f"PL2-{digest[:16].upper()}", "Portfolio Evidence ID/digest do not match canonical ledger semantics")
        print(f"Portfolio evidence ledger v2 validation passed: {evidence_id} · 13 registry-bound systems · {registry.registry_digest()}")
        return 0
    except (OSError, ValueError, json.JSONDecodeError, TypeError, IndexError, KeyError) as exc:
        print(f"ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
