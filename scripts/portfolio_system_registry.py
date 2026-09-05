#!/usr/bin/env python3
"""Load and validate the canonical 13-system portfolio registry."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "scripts" / "portfolio-systems-v1.json"
VERSION = "portfolio-systems-v1"
OWNER = "portyu9"
CLASSIFICATION_POLICY = "four permanent profile systems plus nine rotating Spotlight systems"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def evidence_scope(spec: dict[str, Any]) -> str:
    if spec.get("jobs"):
        return "jobs:" + "|".join(str(item) for item in spec["jobs"])
    if spec.get("job_prefixes"):
        scope = "job-prefix:" + "|".join(str(item) for item in spec["job_prefixes"])
        if spec.get("required_steps"):
            scope += ";steps:" + "|".join(str(item) for item in spec["required_steps"])
        return scope
    return "workflow"


def registry_digest() -> str:
    require(REGISTRY_PATH.is_file(), f"portfolio registry is missing: {REGISTRY_PATH.relative_to(ROOT)}")
    return "sha256:" + hashlib.sha256(REGISTRY_PATH.read_bytes()).hexdigest()


def validate_evidence(repo: str, evidence: Any) -> None:
    require(isinstance(evidence, list) and evidence, f"{repo}: evidence contract must be a non-empty array")
    labels: list[str] = []
    for index, spec in enumerate(evidence, start=1):
        require(isinstance(spec, dict), f"{repo}: evidence entry {index} must be an object")
        label = spec.get("label")
        workflow = spec.get("workflow")
        require(isinstance(label, str) and label, f"{repo}: evidence entry {index} label is missing")
        require(isinstance(workflow, str) and workflow.endswith((".yml", ".yaml")), f"{repo} {label}: workflow must be an explicit YAML filename")
        labels.append(label)
        for key in ("jobs", "job_prefixes", "required_steps"):
            value = spec.get(key)
            if value is not None:
                require(isinstance(value, list) and value, f"{repo} {label}: {key} must be a non-empty array when present")
                require(all(isinstance(item, str) and item for item in value), f"{repo} {label}: {key} entries must be non-empty strings")
    require(len(labels) == len(set(labels)), f"{repo}: evidence labels must be distinct")


def validate_spotlight(repo: str, spotlight: Any) -> None:
    require(isinstance(spotlight, dict), f"{repo}: Spotlight presentation metadata is required")
    for key in ("domain", "signature", "accent", "accent2", "accent3", "glyph", "topology"):
        require(isinstance(spotlight.get(key), str) and spotlight.get(key), f"{repo}: Spotlight {key} is missing")
    for key in ("accent", "accent2", "accent3"):
        value = str(spotlight[key])
        require(len(value) == 7 and value.startswith("#") and all(ch in "0123456789ABCDEFabcdef" for ch in value[1:]), f"{repo}: Spotlight {key} must be #RRGGBB")


def load_registry() -> dict[str, Any]:
    require(REGISTRY_PATH.is_file(), f"portfolio registry is missing: {REGISTRY_PATH.relative_to(ROOT)}")
    data = json.loads(REGISTRY_PATH.read_text(encoding="utf-8"))
    require(isinstance(data, dict), "portfolio registry root must be an object")
    require(data.get("version") == VERSION, "portfolio registry version changed")
    require(data.get("owner") == OWNER, "portfolio registry owner changed")
    require(data.get("classification_policy") == CLASSIFICATION_POLICY, "portfolio registry classification policy changed")
    systems = data.get("systems")
    require(isinstance(systems, list) and len(systems) == 13, "portfolio registry must contain exactly 13 systems")

    repos: list[str] = []
    permanent = 0
    rotating = 0
    spotlight_capable = 0
    rotating_glyphs: list[str] = []
    rotating_topologies: list[str] = []
    for entry in systems:
        require(isinstance(entry, dict), "portfolio registry system entry must be an object")
        repo = entry.get("repo")
        title = entry.get("title")
        classification = entry.get("classification")
        require(isinstance(repo, str) and repo and "/" not in repo, "portfolio registry repository slug is invalid")
        require(isinstance(title, str) and title, f"{repo}: title is missing")
        require(classification in {"permanent", "rotating"}, f"{repo}: classification is invalid")
        validate_evidence(repo, entry.get("evidence"))
        repos.append(repo)
        if classification == "permanent":
            permanent += 1
        else:
            rotating += 1
            validate_spotlight(repo, entry.get("spotlight"))
            rotating_glyphs.append(str(entry["spotlight"]["glyph"]))
            rotating_topologies.append(str(entry["spotlight"]["topology"]))
        if entry.get("spotlight") is not None:
            validate_spotlight(repo, entry.get("spotlight"))
            spotlight_capable += 1

    require(len(repos) == len(set(repos)) == 13, "portfolio registry repositories must be distinct")
    require(permanent == 4 and rotating == 9, "portfolio registry must remain four permanent plus nine rotating systems")
    require(spotlight_capable == 10, "portfolio registry must retain ten Spotlight-capable systems for legacy compatibility")
    require(len(rotating_glyphs) == len(set(rotating_glyphs)) == 9, "rotating Spotlight glyph identities must be distinct")
    require(len(rotating_topologies) == len(set(rotating_topologies)) == 9, "rotating Spotlight topology identities must be distinct")

    by_repo = {str(entry["repo"]): entry for entry in systems}
    agent = by_repo.get("qa-automation-ai-agent-evals")
    require(isinstance(agent, dict), "Agent Evaluation system is missing")
    agent_evidence = agent["evidence"]
    require([item["label"] for item in agent_evidence] == ["QUALITY+SEC", "AGENT LABS"], "Agent Evaluation evidence labels changed")
    require(all(item["workflow"] == "ci.yml" for item in agent_evidence), "Agent Evaluation evidence must remain scoped to ci.yml")
    require(agent_evidence[0].get("required_steps") == ["Tests", "Bandit", "Dependency audit"], "Agent Evaluation required-step contract changed")
    require(len(agent_evidence[1].get("jobs") or []) == 5, "Agent Evaluation lab-job contract changed")
    return data


def systems() -> list[dict[str, Any]]:
    return [dict(item) for item in load_registry()["systems"]]


def system_by_repo() -> dict[str, dict[str, Any]]:
    return {str(item["repo"]): item for item in systems()}


def permanent_systems() -> list[dict[str, Any]]:
    return [item for item in systems() if item["classification"] == "permanent"]


def rotating_systems() -> list[dict[str, Any]]:
    return [item for item in systems() if item["classification"] == "rotating"]


def spotlight_system(entry: dict[str, Any]) -> dict[str, Any]:
    spotlight = entry.get("spotlight")
    validate_spotlight(str(entry["repo"]), spotlight)
    result = {
        "repo": entry["repo"],
        "title": entry["title"],
        "evidence": tuple(dict(spec) for spec in entry["evidence"]),
    }
    result.update(dict(spotlight))
    return result


def rotating_spotlight_pool() -> tuple[dict[str, Any], ...]:
    return tuple(spotlight_system(item) for item in rotating_systems())


def legacy_spotlight_pool() -> tuple[dict[str, Any], ...]:
    return tuple(spotlight_system(item) for item in systems() if item.get("spotlight") is not None)


def self_test() -> None:
    data = load_registry()
    require(len(permanent_systems()) == 4, "permanent registry projection changed")
    require(len(rotating_systems()) == 9, "rotating registry projection changed")
    require(len(rotating_spotlight_pool()) == 9, "rotating Spotlight projection changed")
    require(len(legacy_spotlight_pool()) == 10, "legacy Spotlight projection changed")
    print(f"Portfolio system registry passed: {data['version']} · 13 systems · {registry_digest()}")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) == 2 and sys.argv[1] == "--print-digest":
            load_registry()
            print(registry_digest())
            return 0
        raise ValueError("usage: portfolio_system_registry.py --self-test | --print-digest")
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
