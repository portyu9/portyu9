#!/usr/bin/env python3
"""Compute deterministic semantic diffs between Workflow Capability BOMs.

The diff is descriptive only. Admission/authorization is layered on top of this module so
one canonical semantic model is shared by item 12 compilation and item 13 review gates.
"""
from __future__ import annotations

import copy
import hashlib
import json
from typing import Any, Iterable

SCHEMA_VERSION = 1
DIFF_ID = "workflow-capability-diff-v1"
PERMISSION_LEVEL = {None: 0, "none": 0, "read": 1, "write": 2}
REFERENCE_SCOPES = ("secrets", "vars", "env", "githubToken")
TRIGGER_POSITIVE_FILTERS = {"branches", "tags", "paths"}
TRIGGER_NEGATIVE_FILTERS = {"branches-ignore", "tags-ignore", "paths-ignore"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def digest(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def stable_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def indexed(items: Iterable[dict[str, Any]], key: str, label: str) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        require(isinstance(item, dict), f"{label}: entry must be an object")
        identity = item.get(key)
        require(isinstance(identity, str) and identity, f"{label}: entry lacks {key}")
        require(identity not in result, f"{label}: duplicate {key}: {identity}")
        result[identity] = item
    return result


def change(
    direction: str,
    category: str,
    workflow: str,
    *,
    job: str | None = None,
    key: str | None = None,
    before: Any = None,
    after: Any = None,
) -> dict[str, Any]:
    require(direction in {"expansion", "reduction"}, f"invalid change direction: {direction}")
    entry: dict[str, Any] = {
        "direction": direction,
        "category": category,
        "workflow": workflow,
        "before": before,
        "after": after,
    }
    if job is not None:
        entry["job"] = job
    if key is not None:
        entry["key"] = key
    return entry


def append_set_diff(
    expansions: list[dict[str, Any]],
    reductions: list[dict[str, Any]],
    category: str,
    workflow: str,
    base_values: Iterable[Any],
    candidate_values: Iterable[Any],
    *,
    job: str | None = None,
    key: str | None = None,
) -> None:
    base_map = {stable_key(value): value for value in base_values}
    candidate_map = {stable_key(value): value for value in candidate_values}
    for identity in sorted(candidate_map.keys() - base_map.keys()):
        expansions.append(change(
            "expansion", category, workflow, job=job, key=key,
            before=None, after=candidate_map[identity],
        ))
    for identity in sorted(base_map.keys() - candidate_map.keys()):
        reductions.append(change(
            "reduction", category, workflow, job=job, key=key,
            before=base_map[identity], after=None,
        ))


def compare_permissions(
    expansions: list[dict[str, Any]],
    reductions: list[dict[str, Any]],
    workflow: str,
    base: dict[str, str],
    candidate: dict[str, str],
    *,
    job: str | None = None,
    category: str = "permissions",
) -> None:
    require(isinstance(base, dict) and isinstance(candidate, dict), f"{workflow}: permissions must be objects")
    for permission in sorted(set(base) | set(candidate)):
        before = base.get(permission)
        after = candidate.get(permission)
        require(before in PERMISSION_LEVEL and after in PERMISSION_LEVEL,
                f"{workflow}: unsupported permission level for {permission}: {before!r} -> {after!r}")
        before_rank = PERMISSION_LEVEL[before]
        after_rank = PERMISSION_LEVEL[after]
        if after_rank > before_rank:
            expansions.append(change(
                "expansion", category, workflow, job=job, key=permission,
                before=before, after=after,
            ))
        elif after_rank < before_rank:
            reductions.append(change(
                "reduction", category, workflow, job=job, key=permission,
                before=before, after=after,
            ))


def list_value(value: Any, label: str) -> list[str]:
    require(isinstance(value, list) and all(isinstance(item, str) for item in value),
            f"{label}: trigger filter must be a string list")
    require(len(value) == len(set(value)), f"{label}: trigger filter contains duplicates")
    return value


def compare_trigger_filter(
    expansions: list[dict[str, Any]],
    reductions: list[dict[str, Any]],
    workflow: str,
    event: str,
    key: str,
    before: Any,
    after: Any,
) -> None:
    label = f"{workflow}/{event}/{key}"
    if key in TRIGGER_POSITIVE_FILTERS:
        # No positive filter means unbounded. Adding a positive filter narrows; removing one broadens.
        if before is None and after is not None:
            reductions.append(change("reduction", "trigger-filter", workflow, key=f"{event}.{key}", before=None,
                                     after=list_value(after, label)))
            return
        if before is not None and after is None:
            expansions.append(change("expansion", "trigger-filter", workflow, key=f"{event}.{key}",
                                     before=list_value(before, label), after=None))
            return
        if before is None and after is None:
            return
        before_set = set(list_value(before, label))
        after_set = set(list_value(after, label))
        # Exact set inclusion is provable. Pattern-language subset relations beyond identity are intentionally
        # not guessed: a replacement yields both an addition and a removal and therefore fails closed.
        for value in sorted(after_set - before_set):
            expansions.append(change("expansion", "trigger-filter", workflow, key=f"{event}.{key}",
                                     before=None, after=value))
        for value in sorted(before_set - after_set):
            reductions.append(change("reduction", "trigger-filter", workflow, key=f"{event}.{key}",
                                     before=value, after=None))
        return
    if key in TRIGGER_NEGATIVE_FILTERS:
        # More ignored identities narrows authority; removing ignores broadens it.
        before_set = set() if before is None else set(list_value(before, label))
        after_set = set() if after is None else set(list_value(after, label))
        for value in sorted(before_set - after_set):
            expansions.append(change("expansion", "trigger-filter", workflow, key=f"{event}.{key}",
                                     before=value, after=None))
        for value in sorted(after_set - before_set):
            reductions.append(change("reduction", "trigger-filter", workflow, key=f"{event}.{key}",
                                     before=None, after=value))
        return
    # Schedules and other scalar/list trigger details are capabilities. Exact additions/removals are safe;
    # an unclassified replacement is represented in both directions rather than silently accepted.
    if before == after:
        return
    if isinstance(before, list) and isinstance(after, list):
        append_set_diff(expansions, reductions, "trigger-detail", workflow, before, after,
                        key=f"{event}.{key}")
        return
    expansions.append(change("expansion", "trigger-detail", workflow, key=f"{event}.{key}",
                             before=before, after=after))
    reductions.append(change("reduction", "trigger-detail", workflow, key=f"{event}.{key}",
                             before=before, after=after))


def compare_triggers(
    expansions: list[dict[str, Any]], reductions: list[dict[str, Any]],
    workflow: str, base: dict[str, Any], candidate: dict[str, Any],
) -> None:
    require(isinstance(base, dict) and isinstance(candidate, dict), f"{workflow}: triggers must be objects")
    for event in sorted(candidate.keys() - base.keys()):
        expansions.append(change("expansion", "trigger-event", workflow, key=event,
                                 before=None, after=candidate[event]))
    for event in sorted(base.keys() - candidate.keys()):
        reductions.append(change("reduction", "trigger-event", workflow, key=event,
                                 before=base[event], after=None))
    for event in sorted(base.keys() & candidate.keys()):
        before_spec = base[event]
        after_spec = candidate[event]
        require(isinstance(before_spec, dict) and isinstance(after_spec, dict),
                f"{workflow}/{event}: trigger event details must be objects")
        for key in sorted(set(before_spec) | set(after_spec)):
            compare_trigger_filter(expansions, reductions, workflow, event, key,
                                   before_spec.get(key), after_spec.get(key))


def compare_references(
    expansions: list[dict[str, Any]], reductions: list[dict[str, Any]],
    workflow: str, base: dict[str, Any], candidate: dict[str, Any], *, job: str | None = None,
) -> None:
    require(set(base) == set(REFERENCE_SCOPES) and set(candidate) == set(REFERENCE_SCOPES),
            f"{workflow}: reference scopes changed")
    for scope in REFERENCE_SCOPES:
        append_set_diff(expansions, reductions, "reference", workflow,
                        list_value(base[scope], f"{workflow}/{scope}"),
                        list_value(candidate[scope], f"{workflow}/{scope}"),
                        job=job, key=scope)


def compare_job(
    expansions: list[dict[str, Any]], reductions: list[dict[str, Any]],
    workflow: str, base: dict[str, Any], candidate: dict[str, Any],
) -> None:
    job = base["id"]
    require(candidate.get("id") == job, f"{workflow}: job identity mismatch")
    compare_permissions(expansions, reductions, workflow, base["permissions"], candidate["permissions"],
                        job=job, category="job-permission")
    if bool(candidate["oidc"]) and not bool(base["oidc"]):
        expansions.append(change("expansion", "oidc", workflow, job=job, before=False, after=True))
    elif bool(base["oidc"]) and not bool(candidate["oidc"]):
        reductions.append(change("reduction", "oidc", workflow, job=job, before=True, after=False))
    compare_references(expansions, reductions, workflow, base["references"], candidate["references"], job=job)
    for category, field in (
        ("action", "actions"),
        ("api-surface", "apiSurfaces"),
        ("artifact", "artifacts"),
        ("mutation", "mutations"),
    ):
        append_set_diff(expansions, reductions, category, workflow, base[field], candidate[field], job=job)

    before_needs = set(list_value(base["needs"], f"{workflow}/{job}/needs"))
    after_needs = set(list_value(candidate["needs"], f"{workflow}/{job}/needs"))
    # Removing a prerequisite can make authority reachable in more states; adding one only restricts it.
    for dependency in sorted(before_needs - after_needs):
        expansions.append(change("expansion", "job-dependency", workflow, job=job,
                                 key=dependency, before=dependency, after=None))
    for dependency in sorted(after_needs - before_needs):
        reductions.append(change("reduction", "job-dependency", workflow, job=job,
                                 key=dependency, before=None, after=dependency))

    if base.get("name") != candidate.get("name"):
        # Job names are required-check / audit identities. A rename retires one identity and introduces another.
        expansions.append(change("expansion", "job-name", workflow, job=job,
                                 before=base.get("name"), after=candidate.get("name")))
        reductions.append(change("reduction", "job-name", workflow, job=job,
                                 before=base.get("name"), after=candidate.get("name")))


def compare_workflow(
    expansions: list[dict[str, Any]], reductions: list[dict[str, Any]],
    base: dict[str, Any], candidate: dict[str, Any],
) -> None:
    workflow = base["id"]
    require(candidate.get("id") == workflow, f"workflow identity mismatch: {workflow}")
    if base.get("path") != candidate.get("path") or base.get("name") != candidate.get("name"):
        expansions.append(change("expansion", "workflow-identity", workflow,
                                 before={"path": base.get("path"), "name": base.get("name")},
                                 after={"path": candidate.get("path"), "name": candidate.get("name")}))
        reductions.append(change("reduction", "workflow-identity", workflow,
                                 before={"path": base.get("path"), "name": base.get("name")},
                                 after={"path": candidate.get("path"), "name": candidate.get("name")}))
    compare_triggers(expansions, reductions, workflow, base["triggers"], candidate["triggers"])
    compare_permissions(expansions, reductions, workflow,
                        base["workflowPermissions"], candidate["workflowPermissions"],
                        category="workflow-permission")
    compare_references(expansions, reductions, workflow, base["references"], candidate["references"])

    base_jobs = indexed(base["jobs"], "id", f"{workflow} base jobs")
    candidate_jobs = indexed(candidate["jobs"], "id", f"{workflow} candidate jobs")
    for job in sorted(candidate_jobs.keys() - base_jobs.keys()):
        expansions.append(change("expansion", "job", workflow, job=job,
                                 before=None, after=candidate_jobs[job]))
    for job in sorted(base_jobs.keys() - candidate_jobs.keys()):
        reductions.append(change("reduction", "job", workflow, job=job,
                                 before=base_jobs[job], after=None))
    for job in sorted(base_jobs.keys() & candidate_jobs.keys()):
        compare_job(expansions, reductions, workflow, base_jobs[job], candidate_jobs[job])


def validate_bom_shape(bom: Any, label: str) -> dict[str, Any]:
    require(isinstance(bom, dict), f"{label}: BOM root must be an object")
    expected = {"schemaVersion", "bomId", "repository", "automationPolicyId", "workflows"}
    require(set(bom) == expected, f"{label}: BOM root keys changed: {sorted(bom)}")
    require(bom["schemaVersion"] == 1 and bom["bomId"] == "workflow-capability-bom-v1",
            f"{label}: unsupported BOM schema/identity")
    require(isinstance(bom["repository"], str) and bom["repository"], f"{label}: repository identity missing")
    require(isinstance(bom["automationPolicyId"], str) and bom["automationPolicyId"],
            f"{label}: automation policy identity missing")
    require(isinstance(bom["workflows"], list), f"{label}: workflows must be a list")
    indexed(bom["workflows"], "id", f"{label} workflows")
    return bom


def semantic_diff(base: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    base = validate_bom_shape(base, "base")
    candidate = validate_bom_shape(candidate, "candidate")
    require(base["repository"] == candidate["repository"], "BOM repository identity changed")
    require(base["automationPolicyId"] == candidate["automationPolicyId"],
            "BOM automation policy identity changed")

    expansions: list[dict[str, Any]] = []
    reductions: list[dict[str, Any]] = []
    base_workflows = indexed(base["workflows"], "id", "base workflows")
    candidate_workflows = indexed(candidate["workflows"], "id", "candidate workflows")
    for workflow in sorted(candidate_workflows.keys() - base_workflows.keys()):
        expansions.append(change("expansion", "workflow", workflow,
                                 before=None, after=candidate_workflows[workflow]))
    for workflow in sorted(base_workflows.keys() - candidate_workflows.keys()):
        reductions.append(change("reduction", "workflow", workflow,
                                 before=base_workflows[workflow], after=None))
    for workflow in sorted(base_workflows.keys() & candidate_workflows.keys()):
        compare_workflow(expansions, reductions, base_workflows[workflow], candidate_workflows[workflow])

    expansions.sort(key=stable_key)
    reductions.sort(key=stable_key)
    return {
        "schemaVersion": SCHEMA_VERSION,
        "diffId": DIFF_ID,
        "repository": base["repository"],
        "baseBomSha256": digest(base),
        "candidateBomSha256": digest(candidate),
        "expansionSha256": digest(expansions),
        "hasExpansion": bool(expansions),
        "expansions": expansions,
        "reductions": reductions,
    }


def fixture() -> dict[str, Any]:
    return {
        "schemaVersion": 1,
        "bomId": "workflow-capability-bom-v1",
        "repository": "portyu9/portyu9",
        "automationPolicyId": "automation-policy-v1",
        "workflows": [{
            "id": "quality",
            "name": "Quality",
            "path": ".github/workflows/quality.yml",
            "triggers": {"pull_request": {"paths": ["scripts/**", ".github/**"]}},
            "workflowPermissions": {"contents": "read"},
            "references": {"secrets": [], "vars": [], "env": ["PYTHON_VERSION"], "githubToken": []},
            "jobs": [{
                "id": "validate",
                "name": "validate-contracts",
                "needs": ["plan"],
                "permissions": {"contents": "read"},
                "oidc": False,
                "references": {"secrets": [], "vars": [], "env": ["PYTHON_VERSION"], "githubToken": []},
                "actions": [{"kind": "remote", "repository": "actions/checkout", "path": "", "ref": "a" * 40,
                             "step": "Checkout"}],
                "apiSurfaces": [],
                "artifacts": [],
                "mutations": [],
            }],
        }],
    }


def expect_expansion(mutator, category: str) -> None:
    base = fixture()
    candidate = copy.deepcopy(base)
    mutator(candidate)
    result = semantic_diff(base, candidate)
    require(result["hasExpansion"], f"self-test missed expansion: {category}")
    require(any(entry["category"] == category for entry in result["expansions"]),
            f"self-test expansion used wrong category: {category}: {result['expansions']!r}")


def expect_reduction_only(mutator, category: str) -> None:
    base = fixture()
    candidate = copy.deepcopy(base)
    mutator(candidate)
    result = semantic_diff(base, candidate)
    require(not result["hasExpansion"], f"self-test misclassified restriction as expansion: {category}")
    require(any(entry["category"] == category for entry in result["reductions"]),
            f"self-test missed reduction: {category}: {result['reductions']!r}")


def self_test() -> None:
    same = semantic_diff(fixture(), copy.deepcopy(fixture()))
    require(not same["hasExpansion"] and not same["expansions"] and not same["reductions"],
            "identical BOMs produced semantic drift")

    expect_expansion(lambda value: value["workflows"].append({
        **copy.deepcopy(value["workflows"][0]), "id": "new", "path": ".github/workflows/new.yml"
    }), "workflow")
    expect_expansion(lambda value: value["workflows"][0]["triggers"].__setitem__("workflow_dispatch", {}),
                     "trigger-event")
    expect_expansion(lambda value: value["workflows"][0]["triggers"]["pull_request"]["paths"].append("README.md"),
                     "trigger-filter")
    expect_expansion(lambda value: value["workflows"][0]["jobs"][0]["permissions"].__setitem__("contents", "write"),
                     "job-permission")
    expect_expansion(lambda value: value["workflows"][0]["jobs"][0]["actions"].append({
        "kind": "remote", "repository": "actions/attest", "path": "", "ref": "b" * 40, "step": "Attest"
    }), "action")
    expect_expansion(lambda value: value["workflows"][0]["jobs"][0].__setitem__("oidc", True), "oidc")
    expect_expansion(lambda value: value["workflows"][0]["jobs"][0]["apiSurfaces"].append({
        "client": "gh-api", "endpoint": "repos/x/y/git/refs", "method": "POST", "mutating": True,
        "step": "Create ref"
    }), "api-surface")
    expect_expansion(lambda value: value["workflows"][0]["jobs"][0]["mutations"].append({
        "class": "git-ref", "method": "POST", "target": "repos/x/y/git/refs", "step": "Create ref"
    }), "mutation")
    expect_expansion(lambda value: value["workflows"][0]["jobs"][0]["artifacts"].append({
        "operation": "upload", "name": "egress", "path": "out.json", "step": "Upload"
    }), "artifact")
    expect_expansion(lambda value: value["workflows"][0]["jobs"][0]["references"]["secrets"].append("TOKEN"),
                     "reference")
    expect_expansion(lambda value: value["workflows"][0]["jobs"][0].__setitem__("needs", []),
                     "job-dependency")

    expect_reduction_only(lambda value: value["workflows"][0]["triggers"]["pull_request"]["paths"].remove(".github/**"),
                          "trigger-filter")
    expect_reduction_only(lambda value: value["workflows"][0]["jobs"][0]["permissions"].__setitem__("contents", "none"),
                          "job-permission")
    expect_reduction_only(lambda value: value["workflows"][0]["jobs"][0]["actions"].clear(), "action")
    expect_reduction_only(lambda value: value["workflows"][0]["jobs"][0]["needs"].append("review"),
                          "job-dependency")
    expect_reduction_only(lambda value: value["workflows"][0]["jobs"][0]["references"]["env"].remove("PYTHON_VERSION"),
                          "reference")

    mixed_base = fixture()
    mixed_candidate = copy.deepcopy(mixed_base)
    mixed_candidate["workflows"][0]["jobs"][0]["actions"][0]["ref"] = "c" * 40
    mixed = semantic_diff(mixed_base, mixed_candidate)
    require(mixed["hasExpansion"] and len(mixed["expansions"]) == 1 and len(mixed["reductions"]) == 1,
            "action identity replacement must be expansion + reduction")
    require(mixed["expansionSha256"] == digest(mixed["expansions"]),
            "expansion digest is not canonical")


if __name__ == "__main__":
    self_test()
    print("Workflow Capability semantic diff self-test passed.")
