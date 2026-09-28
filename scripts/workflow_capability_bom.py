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
BLOCK_SCALAR = re.compile(r"^[|>](?:[+-]?[1-9]?|[1-9][+-]?)?$")
TOP_NAME = re.compile(r"^name:\s*(?P<name>.+?)\s*$", re.M)
EXPR_REF = re.compile(r"\b(?P<scope>secrets|vars|env)\.(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b")
GITHUB_TOKEN = re.compile(r"\bgithub\.token\b")
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
FORBIDDEN_NETWORK = re.compile(r"(^|[;&|()\s])(curl|wget)(?:\s|$)")
GH_API_VALUE_OPTIONS = {
    "-X", "--method", "-H", "--header", "-f", "--raw-field", "-F", "--field",
    "--input", "--jq", "-q", "--cache", "--hostname", "--preview",
}
GH_API_FLAG_OPTIONS = {"-i", "--include", "--paginate", "--slurp", "--silent", "--verbose"}
GRAPHQL_QUERY_FIELD = re.compile(
    r"(?:^|\s)(?:-f|--raw-field|-F|--field)\s+query=(?:'|\")?(?P<operation>query|mutation)\b"
)
SHELL_CONTROL = {"|", "||", "&&", ";"}
GIT_GLOBAL_VALUE_OPTIONS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path"}
GIT_NETWORK_OPERATIONS = {"push", "fetch", "clone", "ls-remote"}
GIT_OPERATION_FLAG_OPTIONS = {
    "push": {
        "-f", "--force", "--force-with-lease", "--atomic", "--dry-run", "--porcelain",
        "-q", "--quiet", "-v", "--verbose", "--follow-tags", "--no-verify",
    },
    "fetch": {
        "-f", "--force", "-k", "--keep", "-p", "--prune", "--prune-tags", "--tags",
        "--no-tags", "--dry-run", "-q", "--quiet", "-v", "--verbose",
    },
    "clone": {
        "--bare", "--mirror", "--single-branch", "--no-single-branch", "--no-tags",
        "--recurse-submodules", "-q", "--quiet", "-v", "--verbose",
    },
    "ls-remote": {"--exit-code", "--heads", "--tags", "--refs", "-q", "--quiet"},
}
GIT_OPERATION_VALUE_OPTIONS = {
    "push": {"--repo"},
    "fetch": {"--depth", "--deepen", "--shallow-since", "--shallow-exclude", "--refmap", "--upload-pack"},
    "clone": {"-b", "--branch", "-o", "--origin", "--depth", "--reference", "--separate-git-dir"},
    "ls-remote": {"--sort", "--upload-pack"},
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def indentation(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def unquote(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def shell_tokens(value: str) -> list[str]:
    return re.findall(r"(?:'[^']*'|\"[^\"]*\"|\S+)", value)


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
        indent = indentation(line)
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


def parse_with_values(
    lines: list[str], start: int, *, workflow: str, job: str, step: str
) -> dict[str, str]:
    values: dict[str, str] = {}
    cursor = start
    while cursor < len(lines):
        line = lines[cursor]
        if line.strip() and indentation(line) <= 8:
            break
        if not line.strip():
            cursor += 1
            continue
        entry = WITH_ENTRY.fullmatch(line)
        require(entry is not None,
                f"{workflow}/{job}/{step}: unsupported with syntax: {line.strip()}")
        key = entry.group("key")
        require(key not in values, f"{workflow}/{job}/{step}: duplicate with key: {key}")
        raw = entry.group("value")
        if BLOCK_SCALAR.fullmatch(raw):
            style = raw[0]
            cursor += 1
            payload: list[str] = []
            while cursor < len(lines):
                candidate = lines[cursor]
                if candidate.strip() and indentation(candidate) <= 10:
                    break
                if not candidate.strip():
                    payload.append("")
                    cursor += 1
                    continue
                require(indentation(candidate) >= 12,
                        f"{workflow}/{job}/{step}: malformed with block scalar for {key}")
                payload.append(candidate[12:])
                cursor += 1
            while payload and payload[-1] == "":
                payload.pop()
            values[key] = ("\n" if style == "|" else " ").join(payload)
            continue
        values[key] = unquote(raw)
        cursor += 1
    return values


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
    fragment = command[position + len("gh api "):]
    tokens = shell_tokens(fragment)
    method = "GET"
    endpoint: str | None = None
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if endpoint is not None and (
            token in SHELL_CONTROL or re.match(r"^\d*[<>]", token) is not None
        ):
            break
        if token in {"-X", "--method"}:
            require(index + 1 < len(tokens), f"{workflow}/{job}/{step}: gh api method value is missing")
            method = unquote(tokens[index + 1]).upper().rstrip(")\"")
            require(method in {"GET", "POST", "PUT", "PATCH", "DELETE"},
                    f"{workflow}/{job}/{step}: unsupported gh api method: {method}")
            index += 2
            continue
        if token.startswith("--method="):
            method = unquote(token.split("=", 1)[1]).upper().rstrip(")\"")
            require(method in {"GET", "POST", "PUT", "PATCH", "DELETE"},
                    f"{workflow}/{job}/{step}: unsupported gh api method: {method}")
            index += 1
            continue
        if token in GH_API_VALUE_OPTIONS:
            require(index + 1 < len(tokens),
                    f"{workflow}/{job}/{step}: gh api option value is missing: {token}")
            index += 2
            continue
        if any(token.startswith(option + "=") for option in GH_API_VALUE_OPTIONS if option.startswith("--")):
            index += 1
            continue
        if token in GH_API_FLAG_OPTIONS:
            index += 1
            continue
        require(not token.startswith("-"),
                f"{workflow}/{job}/{step}: unclassified gh api option: {token}")
        if endpoint is None:
            endpoint = unquote(token).rstrip(")\"")
        index += 1
    require(endpoint is not None and endpoint,
            f"{workflow}/{job}/{step}: gh api endpoint is not statically visible")

    if endpoint == "graphql":
        require(method in {"GET", "POST"},
                f"{workflow}/{job}/{step}: GraphQL transport method must be POST/default")
        operations = [match.group("operation") for match in GRAPHQL_QUERY_FIELD.finditer(fragment)]
        require(len(operations) == 1,
                f"{workflow}/{job}/{step}: GraphQL query operation must be statically visible exactly once")
        operation = operations[0]
        return {
            "client": "gh-api",
            "endpoint": endpoint,
            "graphqlOperation": operation,
            "method": "POST",
            "mutating": operation == "mutation",
        }

    return {
        "client": "gh-api",
        "endpoint": endpoint,
        "method": method,
        "mutating": method in MUTATING_METHODS,
    }


def mutation_class(surface: dict[str, Any]) -> str:
    endpoint = surface["endpoint"]
    method = surface["method"]
    if endpoint == "graphql":
        require(surface.get("graphqlOperation") == "mutation", "non-mutating GraphQL surface reached mutation classifier")
        return "graphql-mutation"
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


def git_surface(command: str, *, workflow: str, job: str, step: str) -> dict[str, Any] | None:
    position = command.find("git ")
    if position < 0:
        return None
    tokens = shell_tokens(command[position + len("git "):])
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token in GIT_GLOBAL_VALUE_OPTIONS:
            require(index + 1 < len(tokens),
                    f"{workflow}/{job}/{step}: git global option value is missing: {token}")
            index += 2
            continue
        if any(token.startswith(option + "=") for option in GIT_GLOBAL_VALUE_OPTIONS if option.startswith("--")):
            index += 1
            continue
        if token.startswith("-"):
            return None
        operation = token.rstrip(")\"")
        break
    else:
        return None
    if operation not in GIT_NETWORK_OPERATIONS:
        return None

    flag_options = GIT_OPERATION_FLAG_OPTIONS[operation]
    value_options = GIT_OPERATION_VALUE_OPTIONS[operation]
    positional: list[str] = []
    index += 1
    while index < len(tokens):
        token = unquote(tokens[index]).rstrip(")\"")
        if token in SHELL_CONTROL or re.match(r"^\d*[<>]", token) is not None:
            break
        if token in flag_options:
            index += 1
            continue
        if token in value_options:
            require(index + 1 < len(tokens),
                    f"{workflow}/{job}/{step}: git {operation} option value is missing: {token}")
            index += 2
            continue
        if any(token.startswith(option + "=") for option in value_options if option.startswith("--")):
            index += 1
            continue
        require(not token.startswith("-"),
                f"{workflow}/{job}/{step}: unclassified git {operation} option: {token}")
        positional.append(token)
        index += 1

    require(positional, f"{workflow}/{job}/{step}: git {operation} remote is not statically visible")
    surface: dict[str, Any] = {
        "client": "git",
        "operation": operation,
        "mutating": operation == "push",
        "remote": positional[0],
    }
    if len(positional) > 1:
        surface["targets"] = positional[1:]
    return surface


def job_blocks(text: str, jobs: list[str], label: str) -> dict[str, str]:
    lines = text.splitlines(keepends=True)
    jobs_roots = [index for index, line in enumerate(lines) if line.rstrip("\n") == "jobs:"]
    require(len(jobs_roots) == 1, f"{label}: workflow must contain exactly one jobs block")
    starts: list[tuple[int, str]] = []
    for index in range(jobs_roots[0] + 1, len(lines)):
        line = lines[index]
        if line.strip() and indentation(line) == 0:
            break
        match = JOB_KEY.fullmatch(line.rstrip("\n"))
        if match:
            starts.append((index, match.group("job")))
    observed = [job for _, job in starts]
    require(set(observed) == set(jobs) and len(observed) == len(jobs),
            f"{label}: job block inventory changed: expected={sorted(jobs)} observed={observed}")
    blocks: dict[str, str] = {}
    for offset, (start, job) in enumerate(starts):
        end = starts[offset + 1][0] if offset + 1 < len(starts) else len(lines)
        blocks[job] = "".join(lines[start:end])
    return blocks


def expression_references(text: str) -> dict[str, list[str]]:
    result: dict[str, set[str]] = {"secrets": set(), "vars": set(), "env": set(), "githubToken": set()}
    for match in EXPR_REF.finditer(text):
        result[match.group("scope")].add(match.group("name"))
    if GITHUB_TOKEN.search(text):
        result["githubToken"].add("github.token")
    return {key: sorted(values) for key, values in result.items()}


def validate_job_authority(filename: str, entry: dict[str, Any]) -> None:
    for action in entry["actions"]:
        if action.get("repository") in {"actions/attest", "actions/attest-build-provenance"}:
            require(entry["oidc"] and entry["permissions"].get("attestations") == "write",
                    f"{filename}/{entry['id']}: attestation action lacks exact OIDC/attestations write authority")
    write_permissions = sorted(
        permission for permission, level in entry["permissions"].items() if level == "write"
    )
    if write_permissions:
        require(entry["mutations"],
                f"{filename}/{entry['id']}: write permissions lack a classified mutation: {write_permissions}")


def compile_steps(text: str, workflow: str, jobs: list[str]) -> dict[str, dict[str, Any]]:
    lines = text.splitlines()
    compiled: dict[str, dict[str, Any]] = {
        job: {"actions": [], "apiSurfaces": [], "artifacts": [], "mutations": []} for job in jobs
    }
    current_job: str | None = None
    current_step = ""
    in_jobs = False
    index = 0
    while index < len(lines):
        line = lines[index]
        if line == "jobs:":
            in_jobs = True
            current_job = None
            index += 1
            continue
        if in_jobs and line.strip() and indentation(line) == 0:
            break
        if not in_jobs:
            index += 1
            continue
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
                    with_values = parse_with_values(
                        lines, cursor + 1, workflow=workflow, job=current_job, step=current_step
                    )
                    break
                if lines[cursor].strip() and indentation(lines[cursor]) <= 8:
                    break
                cursor += 1

            remote = REMOTE_ACTION.fullmatch(uses)
            if remote:
                action: dict[str, Any] = {
                    "kind": "remote",
                    "repository": remote.group("repository"),
                    "path": (remote.group("subpath") or "").lstrip("/"),
                    "ref": remote.group("ref"),
                    "step": current_step,
                }
            elif uses.startswith("./"):
                require("@" not in uses, f"{workflow}/{current_job}/{current_step}: malformed local action")
                action = {"kind": "local", "path": uses, "step": current_step}
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
                require(artifact.get("path"),
                        f"{workflow}/{current_job}/{current_step}: artifact action must expose its path")
                compiled[current_job]["artifacts"].append(artifact)
            if repository in {"actions/attest", "actions/attest-build-provenance"}:
                target = with_values.get("subject-path") or with_values.get("subject-digest")
                require(target,
                        f"{workflow}/{current_job}/{current_step}: attestation subject is not statically visible")
                compiled[current_job]["mutations"].append({
                    "class": "attestation",
                    "step": current_step,
                    "target": target,
                })
            if repository == "github/codeql-action" and action.get("path") == "analyze":
                compiled[current_job]["mutations"].append({
                    "class": "code-scanning-results-upload",
                    "step": current_step,
                    "target": "repository-code-scanning",
                })
            index += 1
            continue

        if RUN_BLOCK.fullmatch(line):
            require(current_step, f"{workflow}/{current_job}: run step has no explicit name")
            block: list[str] = []
            cursor = index + 1
            while cursor < len(lines):
                candidate = lines[cursor]
                if candidate.strip() and indentation(candidate) <= 8:
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
                git = git_surface(shell_line, workflow=workflow, job=current_job, step=current_step)
                if git is not None:
                    git["step"] = current_step
                    compiled[current_job]["apiSurfaces"].append(git)
                    if git["mutating"]:
                        remote = git.get("remote", "")
                        targets = git.get("targets", [])
                        require(remote and targets,
                                f"{workflow}/{current_job}/{current_step}: git push target is not statically visible")
                        compiled[current_job]["mutations"].append({
                            "class": "git-ref-push",
                            "step": current_step,
                            "target": f"{remote} {' '.join(targets)}",
                        })
                shell_index += 1
            index = cursor
            continue
        index += 1

    for job in jobs:
        for key in ("actions", "apiSurfaces", "artifacts", "mutations"):
            compiled[job][key].sort(key=lambda value: canonical_json(value))
    return compiled


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
        blocks = job_blocks(text, jobs, filename)
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
                "references": expression_references(blocks[job]),
                **compiled_steps[job],
            }
            validate_job_authority(filename, entry)
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
            "references": expression_references(text),
        })
    return {
        "schemaVersion": SCHEMA_VERSION,
        "bomId": BOM_ID,
        "repository": policy["repository"],
        "automationPolicyId": policy["policyId"],
        "workflows": workflows,
    }


def expect_failure(callback, fragment: str) -> None:
    try:
        callback()
    except ValueError as exc:
        require(fragment in str(exc), f"capability BOM self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"capability BOM self-test accepted forbidden input: {fragment}")


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
    require(REMOTE_ACTION.fullmatch("actions/checkout@main") is None,
            "mutable action ref self-test was accepted")

    with_lines = [
        "          name: receipt",
        "          path: |",
        "            receipt.json",
        "            receipt.sha256",
        "          retention-days: 1",
    ]
    values = parse_with_values(with_lines, 0, workflow="fixture.yml", job="job", step="artifact")
    require(values["path"] == "receipt.json\nreceipt.sha256" and values["retention-days"] == "1",
            f"with block scalar self-test drifted: {values!r}")

    gh = api_surface(
        'gh api -H \'Accept: application/vnd.github+json\' "repos/${GITHUB_REPOSITORY}/commits/${HEAD_SHA}/check-runs" --jq .total_count | tr -d \'\\n\'',
        workflow="fixture.yml", job="job", step="api",
    )
    require(gh["endpoint"] == "repos/${GITHUB_REPOSITORY}/commits/${HEAD_SHA}/check-runs" and gh["method"] == "GET",
            f"gh api option parser self-test drifted: {gh!r}")
    post = api_surface(
        'gh api --include --method POST "repos/${GITHUB_REPOSITORY}/actions/workflows/x.yml/dispatches" -f ref=main)',
        workflow="fixture.yml", job="job", step="api",
    )
    require(post["method"] == "POST" and post["mutating"], f"gh api method self-test drifted: {post!r}")
    graphql_query = api_surface(
        "gh api graphql -f query='query($owner:String!){viewer{login}}' -f owner=x",
        workflow="fixture.yml", job="job", step="graphql-read",
    )
    require(graphql_query == {
        "client": "gh-api", "endpoint": "graphql", "graphqlOperation": "query",
        "method": "POST", "mutating": False,
    }, f"GraphQL read classification self-test drifted: {graphql_query!r}")
    graphql_mutation = api_surface(
        "gh api graphql -f query='mutation($id:ID!){enablePullRequestAutoMerge(input:{pullRequestId:$id}){clientMutationId}}' -f id=x",
        workflow="fixture.yml", job="job", step="graphql-write",
    )
    require(graphql_mutation["method"] == "POST" and graphql_mutation["mutating"]
            and graphql_mutation["graphqlOperation"] == "mutation"
            and mutation_class(graphql_mutation) == "graphql-mutation",
            f"GraphQL mutation classification self-test drifted: {graphql_mutation!r}")
    expect_failure(
        lambda: api_surface("gh api graphql -f query=$DYNAMIC", workflow="fixture.yml", job="job", step="api"),
        "GraphQL query operation must be statically visible exactly once",
    )
    expect_failure(
        lambda: api_surface("gh api graphql -f query='mutation{x}' -f query='query{x}'", workflow="fixture.yml", job="job", step="api"),
        "GraphQL query operation must be statically visible exactly once",
    )
    expect_failure(
        lambda: api_surface("gh api --unknown value repos/x", workflow="fixture.yml", job="job", step="api"),
        "unclassified gh api option",
    )

    git = git_surface(
        'git -C artifacts -c "http.https://github.com/.extraheader=AUTHORIZATION: basic x" push origin HEAD:generated',
        workflow="fixture.yml", job="job", step="publish",
    )
    require(git is not None and git["operation"] == "push" and git.get("remote") == "origin"
            and git.get("targets") == ["HEAD:generated"] and git["mutating"],
            f"git push parser self-test drifted: {git!r}")
    fetch = git_surface(
        "git -C published fetch -q ../candidate.bundle refs/heads/generated:refs/heads/generated",
        workflow="fixture.yml", job="job", step="fetch",
    )
    require(fetch is not None and fetch.get("remote") == "../candidate.bundle"
            and fetch.get("targets") == ["refs/heads/generated:refs/heads/generated"],
            f"git fetch parser self-test drifted: {fetch!r}")
    ls_remote = git_surface(
        "git -C published ls-remote --exit-code origin refs/heads/generated",
        workflow="fixture.yml", job="job", step="ls-remote",
    )
    require(ls_remote is not None and ls_remote.get("remote") == "origin"
            and ls_remote.get("targets") == ["refs/heads/generated"],
            f"git ls-remote parser self-test drifted: {ls_remote!r}")
    expect_failure(
        lambda: git_surface("git fetch --mystery origin main", workflow="fixture.yml", job="job", step="fetch"),
        "unclassified git fetch option",
    )

    refs = expression_references("${{ secrets.ONE }} ${{ vars.TWO }} ${{ env.THREE }} ${{ github.token }}")
    require(refs == {
        "secrets": ["ONE"], "vars": ["TWO"], "env": ["THREE"], "githubToken": ["github.token"]
    }, f"expression reference self-test drifted: {refs!r}")

    network_fixture = (
        "jobs:\n"
        "  job:\n"
        "    name: job\n"
        "    steps:\n"
        "      - name: Bad network\n"
        "        run: |\n"
        "          curl https://example.invalid\n"
    )
    expect_failure(lambda: compile_steps(network_fixture, "fixture.yml", ["job"]), "unclassified network client")

    artifact_fixture = (
        "jobs:\n"
        "  job:\n"
        "    name: job\n"
        "    steps:\n"
        "      - name: Missing artifact path\n"
        "        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a\n"
        "        with:\n"
        "          name: fixture\n"
    )
    expect_failure(lambda: compile_steps(artifact_fixture, "fixture.yml", ["job"]),
                   "artifact action must expose its path")

    expect_failure(
        lambda: validate_job_authority("fixture.yml", {
            "id": "write-job", "actions": [], "permissions": {"contents": "write"},
            "oidc": False, "mutations": [],
        }),
        "write permissions lack a classified mutation",
    )
    expect_failure(
        lambda: validate_job_authority("fixture.yml", {
            "id": "attest-job",
            "actions": [{"repository": "actions/attest"}],
            "permissions": {"attestations": "write"}, "oidc": False,
            "mutations": [{"class": "attestation"}],
        }),
        "attestation action lacks exact OIDC/attestations write authority",
    )


if __name__ == "__main__":
    self_test()
    print(canonical_json(compile_bom()), end="")
