#!/usr/bin/env python3
"""Compile the reviewed GitHub Actions workflow subset into a capability BOM.

This module is deliberately descriptive: it derives capabilities from workflow source and
from the canonical Automation Policy IR. It grants no authority and performs no network
access. The workflow source-shape gate owns the YAML subset; this compiler fails closed on
capability-bearing forms outside the subset it understands.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any

import automation_policy
import workflow_authority_contract_core as authority

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SCHEMA_VERSION = 1
BOM_ID = "workflow-capability-bom-v1"
REMOTE_ACTION = re.compile(
    r"^(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?P<subpath>/[^@]+)?@(?P<ref>[0-9a-f]{40})$"
)
JOB_KEY = re.compile(r"^  (?P<job>[A-Za-z0-9_-]+):\s*$")
STEP_KEY = re.compile(r"^      - name:\s*(?P<name>.+?)\s*$")
USES_KEY = re.compile(r"^        uses:\s*(?P<uses>\S+)\s*(?:#.*)?$")
RUN_BLOCK = re.compile(r"^        run:\s*[|>]\s*$")
WITH_BLOCK = re.compile(r"^        with:\s*$")
WITH_ENTRY = re.compile(r"^          (?P<key>[A-Za-z0-9_.-]+):\s*(?P<value>.*?)\s*$")
TOP_NAME = re.compile(r"^name:\s*(?P<name>.+?)\s*$", re.M)
EXPR_REF = re.compile(r"\b(?P<scope>secrets|vars|env)\.(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b")
GITHUB_TOKEN = re.compile(r"\bgithub\.token\b")
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
FORBIDDEN_NETWORK = re.compile(r"(^|[;&|()\s])(curl|wget)(?:\s|$)")
GIT_NETWORK = re.compile(r"(^|[;&|()\s])git\s+(push|fetch|clone)(?:\s|$)")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def workflow_sources(policy: dict[str, Any]) -> list[tuple[str, str, Path]]:
    specs: list[tuple[str, str, Path]] = []
    for workflow_id, workflow in policy["workflows"].items():
        relative = workflow["path"]
        require(isinstance(relative, str), f"workflow path is malformed: {workflow_id}")
        path = ROOT / relative
        require(path.is_file() and not path.is_symlink(), f"workflow source is missing or aliased: {relative}")
        specs.append((relative, workflow_id, path))
    specs.sort()
    observed = sorted(
        path.relative_to(ROOT).as_posix()
        for path in {*WORKFLOWS.glob("*.yml"), *WORKFLOWS.glob("*.yaml")}
    )
    expected = [relative for relative, _, _ in specs]
    require(observed == expected,
            f"workflow capability BOM inventory changed: expected={expected} observed={observed}")
    return specs


def parse_trigger_details(text: str, label: str) -> dict[str, Any]:
    lines = text.splitlines()
    starts = [i for i, line in enumerate(lines) if line == "on:"]
    require(len(starts) == 1, f"{label}: expected one mapping-style on block")
    result: dict[str, Any] = {}
    current_event: str | None = None
    current_key: str | None = None
    for line_number, line in enumerate(lines[starts[0] + 1:], start=starts[0] + 2):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            break
        if indent == 2:
            match = re.fullmatch(r"  ([A-Za-z0-9_-]+):\s*", line)
            require(match is not None, f"{label}:{line_number}: unsupported trigger event syntax")
            current_event = match.group(1)
            require(current_event not in result, f"{label}:{line_number}: duplicate trigger event")
            result[current_event] = {}
            current_key = None
            continue
        require(current_event is not None, f"{label}:{line_number}: trigger detail precedes event")
        if indent == 4:
            cron = re.fullmatch(r"    - cron:\s*(.+?)\s*", line)
            if cron:
                require(current_event == "schedule", f"{label}:{line_number}: cron outside schedule")
                result[current_event].setdefault("cron", []).append(unquote(cron.group(1)))
                current_key = None
                continue
            mapping = re.fullmatch(r"    ([A-Za-z0-9_-]+):\s*(.*?)\s*", line)
            require(mapping is not None, f"{label}:{line_number}: unsupported trigger mapping")
            current_key, scalar = mapping.groups()
            require(current_key not in result[current_event],
                    f"{label}:{line_number}: duplicate trigger key: {current_event}.{current_key}")
            if scalar:
                result[current_event][current_key] = unquote(scalar)
                current_key = None
            else:
                result[current_event][current_key] = []
            continue
        if indent == 6:
            item = re.fullmatch(r"      -\s+(.+?)\s*", line)
            require(item is not None and current_key is not None,
                    f"{label}:{line_number}: unsupported trigger list syntax")
            value = result[current_event][current_key]
            require(isinstance(value, list), f"{label}:{line_number}: trigger list parent is not a list")
            value.append(unquote(item.group(1)))
            continue
        raise ValueError(f"{label}:{line_number}: unsupported trigger capability syntax")
    require(result, f"{label}: empty trigger detail set")
    return {key: result[key] for key in sorted(result)}


def effective_permissions(
    permissions: dict[str, dict[str, str]], jobs: list[str], label: str
) -> dict[str, dict[str, str]]:
    workflow_permissions = permissions.get(authority.WORKFLOW_SCOPE)
    require(workflow_permissions is not None, f"{label}: workflow-level permissions are required")
    result: dict[str, dict[str, str]] = {}
    for job in jobs:
        selected = permissions.get(job, workflow_permissions)
        result[job] = {key: selected[key] for key in sorted(selected)}
    return result


def normalize_shell_command(lines: list[str], start: int) -> tuple[str, int]:
    parts: list[str] = []
    index = start
    while index < len(lines):
        stripped = lines[index].strip()
        if not stripped:
            break
        continuation = stripped.endswith("\\")
        if continuation:
            stripped = stripped[:-1].rstrip()
        parts.append(stripped)
        index += 1
        if not continuation:
            break
    return " ".join(parts), index


def api_surface(command: str, *, workflow: str, job: str, step: str) -> dict[str, Any]:
    position = command.find("gh api ")
    require(position >= 0, "internal gh api parser misuse")
    fragment = command[position:]
    method_match = re.search(r"(?:^|\s)(?:-X|--method)\s+([A-Za-z]+)(?:\s|$)", fragment)
    method = method_match.group(1).upper() if method_match else "GET"
    tokens = re.findall(r"(?:'[^']*'|\"[^\"]*\"|\S+)", fragment[len("gh api "):])
    endpoint = next(
        (unquote(token) for token in tokens
         if not token.startswith("-") and token.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}),
        None,
    )
    require(endpoint is not None, f"{workflow}/{job}/{step}: gh api endpoint is not statically visible")
    mutation = method in MUTATING_METHODS
    return {
        "client": "gh-api",
        "command": fragment,
        "endpoint": endpoint,
        "method": method,
        "mutating": mutation,
    }


def mutation_class(surface: dict[str, Any]) -> str:
    endpoint = surface["endpoint"]
    method = surface["method"]
    if "/actions/workflows/" in endpoint and "/dispatches" in endpoint:
        return "workflow-dispatch"
    if "/actions/runs/" in endpoint and endpoint.rstrip("/").endswith("/approve"):
        return "workflow-run-approval"
    if "/git/refs" in endpoint:
        return "git-ref"
    if "/pulls" in endpoint and endpoint.rstrip("/").endswith("/merge"):
        return "pull-request-merge"
    if "/pulls" in endpoint:
        return "pull-request"
    if "/issues" in endpoint:
        return "issue-or-pr-metadata"
    return f"github-api-{method.lower()}"


def compile_steps(text: str, workflow: str, jobs: list[str]) -> dict[str, dict[str, Any]]:
    lines = text.splitlines()
    compiled: dict[str, dict[str, Any]] = {
        job: {"actions": [], "apiSurfaces": [], "artifacts": [], "mutations": []} for job in jobs
    }
    current_job: str | None = None
    current_step = ""
    index = 0
    while index < len(lines):
        line = lines[index]
        job_match = JOB_KEY.fullmatch(line)
        if job_match:
            current_job = job_match.group("job")
            current_step = ""
            index += 1
            continue
        if current_job is None:
            index += 1
            continue
        step_match = STEP_KEY.fullmatch(line)
        if step_match:
            current_step = unquote(step_match.group("name"))
            index += 1
            continue
        uses_match = USES_KEY.fullmatch(line)
        if uses_match:
            require(current_step, f"{workflow}/{current_job}: uses step has no explicit name")
            uses = uses_match.group("uses")
            with_values: dict[str, str] = {}
            cursor = index + 1
            while cursor < len(lines):
                if WITH_BLOCK.fullmatch(lines[cursor]):
                    cursor += 1
                    while cursor < len(lines):
                        entry = WITH_ENTRY.fullmatch(lines[cursor])
                        if entry is None:
                            break
                        key = entry.group("key")
                        require(key not in with_values,
                                f"{workflow}/{current_job}/{current_step}: duplicate with key: {key}")
                        with_values[key] = unquote(entry.group("value"))
                        cursor += 1
                    break
                if lines[cursor].strip() and len(lines[cursor]) - len(lines[cursor].lstrip(" ")) <= 8:
                    break
                cursor += 1

            action: dict[str, Any] = {"step": current_step, "uses": uses}
            remote = REMOTE_ACTION.fullmatch(uses)
            if remote:
                action.update({
                    "kind": "remote",
                    "repository": remote.group("repository"),
                    "path": (remote.group("subpath") or "").lstrip("/"),
                    "ref": remote.group("ref"),
                })
            elif uses.startswith("./"):
                require("@" not in uses, f"{workflow}/{current_job}/{current_step}: malformed local action")
                action.update({"kind": "local", "path": uses})
            else:
                raise ValueError(
                    f"{workflow}/{current_job}/{current_step}: external action is not immutable: {uses}"
                )
            compiled[current_job]["actions"].append(action)

            repository = action.get("repository")
            if repository in {"actions/upload-artifact", "actions/download-artifact"}:
                operation = "upload" if repository == "actions/upload-artifact" else "download"
                artifact: dict[str, Any] = {
                    "operation": operation,
                    "step": current_step,
                    "name": with_values.get("name", ""),
                }
                for key in ("path", "retention-days", "if-no-files-found", "digest-mismatch"):
                    if key in with_values:
                        artifact[key] = with_values[key]
                require(artifact["name"],
                        f"{workflow}/{current_job}/{current_step}: artifact action must name its artifact")
                compiled[current_job]["artifacts"].append(artifact)
            if repository == "actions/attest-build-provenance":
                compiled[current_job]["mutations"].append({
                    "class": "attestation",
                    "step": current_step,
                    "target": with_values.get("subject-path") or with_values.get("subject-digest") or "attestation-subject",
                })
            index += 1
            continue

        if RUN_BLOCK.fullmatch(line):
            require(current_step, f"{workflow}/{current_job}: run step has no explicit name")
            block: list[str] = []
            cursor = index + 1
            while cursor < len(lines):
                candidate = lines[cursor]
                if candidate.strip() and len(candidate) - len(candidate.lstrip(" ")) <= 8:
                    break
                block.append(candidate[10:] if candidate.startswith("          ") else candidate.lstrip())
                cursor += 1
            shell_index = 0
            while shell_index < len(block):
                shell_line = block[shell_index]
                require(FORBIDDEN_NETWORK.search(shell_line) is None,
                        f"{workflow}/{current_job}/{current_step}: unclassified network client: {shell_line.strip()}")
                if "gh api " in shell_line:
                    command, next_index = normalize_shell_command(block, shell_index)
                    surface = api_surface(command, workflow=workflow, job=current_job, step=current_step)
                    surface["step"] = current_step
                    compiled[current_job]["apiSurfaces"].append(surface)
                    if surface["mutating"]:
                        compiled[current_job]["mutations"].append({
                            "class": mutation_class(surface),
                            "step": current_step,
                            "target": surface["endpoint"],
                            "method": surface["method"],
                        })
                    shell_index = next_index
                    continue
                network = GIT_NETWORK.search(shell_line)
                if network:
                    command, next_index = normalize_shell_command(block, shell_index)
                    operation = network.group(2)
                    compiled[current_job]["apiSurfaces"].append({
                        "client": "git",
                        "command": command,
                        "operation": operation,
                        "mutating": operation == "push",
                        "step": current_step,
                    })
                    if operation == "push":
                        compiled[current_job]["mutations"].append({
                            "class": "git-ref-push",
                            "step": current_step,
                            "target": command,
                        })
                    shell_index = next_index
                    continue
                shell_index += 1
            index = cursor
            continue
        index += 1

    for job in jobs:
        for key in ("actions", "apiSurfaces", "artifacts", "mutations"):
            compiled[job][key].sort(key=lambda value: canonical_json(value))
    return compiled


def expression_references(text: str) -> dict[str, list[str]]:
    result = {"secrets": set(), "vars": set(), "env": set(), "githubToken": set()}
    for match in EXPR_REF.finditer(text):
        result[match.group("scope")].add(match.group("name"))
    if GITHUB_TOKEN.search(text):
        result["githubToken"].add("github.token")
    return {key: sorted(values) for key, values in result.items()}


def compile_bom(root: Path = ROOT) -> dict[str, Any]:
    require(root == ROOT, "workflow capability compiler root substitution is not supported")
    policy = automation_policy.load_policy()
    policy_specs = authority.policy_specs(policy)
    workflows: list[dict[str, Any]] = []
    for relative, workflow_id, path in workflow_sources(policy):
        text = path.read_text(encoding="utf-8")
        filename = path.name
        require(filename in policy_specs, f"workflow missing from policy specs: {filename}")
        authority.validate_workflow_text(filename, text, policy_specs[filename])
        names, needs = authority.parse_job_metadata(text, filename)
        permissions = authority.parse_permissions(text, filename)
        jobs = sorted(names)
        effective = effective_permissions(permissions, jobs, filename)
        compiled_steps = compile_steps(text, relative, jobs)
        refs = expression_references(text)
        top_name = TOP_NAME.search(text)
        require(top_name is not None, f"{filename}: workflow name is missing")
        job_entries: list[dict[str, Any]] = []
        for job in jobs:
            entry = {
                "id": job,
                "name": names[job],
                "needs": needs[job],
                "permissions": effective[job],
                "oidc": effective[job].get("id-token") == "write",
                **compiled_steps[job],
            }
            job_entries.append(entry)
        workflows.append({
            "id": workflow_id,
            "name": unquote(top_name.group("name")),
            "path": relative,
            "triggers": parse_trigger_details(text, filename),
            "workflowPermissions": {
                key: permissions[authority.WORKFLOW_SCOPE][key]
                for key in sorted(permissions[authority.WORKFLOW_SCOPE])
            },
            "jobs": job_entries,
            "references": refs,
        })
    return {
        "schemaVersion": SCHEMA_VERSION,
        "bomId": BOM_ID,
        "repository": policy["repository"],
        "automationPolicyId": policy["policyId"],
        "workflows": workflows,
    }


def self_test() -> None:
    require(unquote('"main"') == "main" and unquote("'main'") == "main", "scalar unquote failed")
    fixture = (
        "name: Fixture\n\n"
        "on:\n"
        "  push:\n"
        "    branches:\n"
        "      - main\n"
        "  workflow_dispatch:\n\n"
    )
    parsed = parse_trigger_details(fixture, "fixture.yml")
    require(parsed == {"push": {"branches": ["main"]}, "workflow_dispatch": {}},
            f"trigger parser self-test drifted: {parsed!r}")
    action = REMOTE_ACTION.fullmatch(
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    )
    require(action is not None and action.group("repository") == "actions/checkout",
            "immutable action parser self-test failed")
    bad = REMOTE_ACTION.fullmatch("actions/checkout@main")
    require(bad is None, "mutable action ref self-test was accepted")
    refs = expression_references("${{ secrets.ONE }} ${{ vars.TWO }} ${{ env.THREE }} ${{ github.token }}")
    require(refs == {
        "secrets": ["ONE"], "vars": ["TWO"], "env": ["THREE"], "githubToken": ["github.token"]
    }, f"expression reference self-test drifted: {refs!r}")


if __name__ == "__main__":
    self_test()
    print(canonical_json(compile_bom()), end="")
