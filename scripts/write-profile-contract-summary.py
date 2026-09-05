#!/usr/bin/env python3
"""Write a read-only Profile Quality assurance summary to GITHUB_STEP_SUMMARY.

The summary is intentionally informational: it reads already-generated/validated
artifacts and version-controlled contracts, performs no network calls, and grants no
additional workflow authority. Existing validators remain the enforcement boundary.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import sys
import tempfile
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
SCHEMA = ROOT / ".github" / "attestation" / "profile-evidence-v2.schema.json"
AUTHORITY = ROOT / "scripts" / "validate-workflow-authority-contract.py"
BUILDER = ROOT / "scripts" / "build-profile-evidence-attestation.py"
SHA40 = re.compile(r"^[0-9a-f]{40}$")
EVIDENCE_ID = re.compile(r"^SF1-[0-9A-F]{16}$")
PORTFOLIO_ID = re.compile(r"^PL1-[0-9A-F]{16}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
USES = re.compile(r"^\s*(?:-\s*)?uses\s*:\s*([^#]+?)\s*(?:#\s*(v\d+\.\d+\.\d+))?\s*$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def source_head(env: dict[str, str]) -> str:
    event_path = env.get("GITHUB_EVENT_PATH", "").strip()
    if event_path:
        path = Path(event_path)
        if path.is_file():
            payload = json.loads(path.read_text(encoding="utf-8"))
            pull_request = payload.get("pull_request")
            if isinstance(pull_request, dict):
                head = pull_request.get("head")
                if isinstance(head, dict) and isinstance(head.get("sha"), str):
                    sha = head["sha"]
                    require(SHA40.fullmatch(sha) is not None, "pull request head SHA is malformed")
                    return sha
    sha = env.get("GITHUB_SHA", "").strip()
    require(SHA40.fullmatch(sha) is not None, "GITHUB_SHA is missing or malformed")
    return sha


def action_identities() -> list[tuple[str, str, str]]:
    observed: dict[tuple[str, str], str] = {}
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        for line in path.read_text(encoding="utf-8").splitlines():
            match = USES.match(line)
            if not match:
                continue
            value, tag = match.groups()
            value = value.strip().strip("'\"")
            if value.startswith("./"):
                continue
            if "@" not in value:
                continue
            action, sha = value.rsplit("@", 1)
            parts = action.split("/")
            if len(parts) < 2 or SHA40.fullmatch(sha) is None:
                continue
            repository = "/".join(parts[:2])
            label = tag or "unlabeled"
            key = (repository, label)
            prior = observed.get(key)
            require(prior in {None, sha}, f"conflicting action identity for {repository}@{label}")
            observed[key] = sha
    return [(repo, tag, sha) for (repo, tag), sha in sorted(observed.items())]


def privileged_authority() -> list[tuple[str, str, str]]:
    namespace = runpy.run_path(str(AUTHORITY))
    expected = namespace.get("EXPECTED")
    require(isinstance(expected, dict), "workflow authority manifest is unavailable")
    rows: list[tuple[str, str, str]] = []
    for workflow, spec in sorted(expected.items()):
        require(isinstance(spec, dict), f"authority manifest entry is invalid: {workflow}")
        permissions = spec.get("permissions")
        require(isinstance(permissions, dict), f"authority permissions are invalid: {workflow}")
        for scope, grants in sorted(permissions.items()):
            require(isinstance(grants, dict), f"authority grant is invalid: {workflow}/{scope}")
            writes = [f"{name}:write" for name, value in sorted(grants.items()) if value == "write"]
            if writes:
                rows.append((workflow, str(scope), ", ".join(writes)))
    return rows


def attestation_contract() -> dict[str, Any]:
    schema_bytes = SCHEMA.read_bytes()
    schema = json.loads(schema_bytes.decode("utf-8"))
    namespace = runpy.run_path(str(BUILDER))
    published_paths = namespace.get("PUBLISHED_PATHS")
    require(isinstance(published_paths, tuple), "attestation published-path inventory is unavailable")
    digest = f"sha256:{hashlib.sha256(schema_bytes).hexdigest()}"
    return {
        "predicate_type": schema.get("$id"),
        "schema_version": schema.get("properties", {}).get("schemaVersion", {}).get("const"),
        "schema_digest": digest,
        "subject_count": len(published_paths),
    }


def signal_field_identity(directory: Path) -> tuple[str, str]:
    path = directory / "signal-field-wide-light.svg"
    require(path.is_file(), f"Signal Field summary subject is missing: {path}")
    match = SVG_OPEN.search(path.read_text(encoding="utf-8"))
    require(match is not None, "Signal Field SVG root is missing")
    attrs = dict(ATTR.findall(match.group(0)))
    evidence_id = attrs.get("data-evidence-id", "")
    digest = attrs.get("data-evidence-digest", "")
    require(EVIDENCE_ID.fullmatch(evidence_id) is not None, "Signal Field Evidence ID is malformed")
    require(DIGEST.fullmatch(digest) is not None, "Signal Field evidence digest is malformed")
    return evidence_id, digest


def portfolio_identity(directory: Path) -> tuple[str, str, int, dict[str, int]]:
    path = directory / "portfolio-evidence-ledger.json"
    require(path.is_file(), f"Portfolio Evidence Ledger is missing: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    evidence_id = payload.get("evidence_id")
    digest = payload.get("evidence_digest")
    count = payload.get("system_count")
    summary = payload.get("signal_summary")
    require(isinstance(evidence_id, str) and PORTFOLIO_ID.fullmatch(evidence_id) is not None, "Portfolio Evidence ID is malformed")
    require(isinstance(digest, str) and DIGEST.fullmatch(digest) is not None, "Portfolio evidence digest is malformed")
    require(count == 13, "Portfolio system count changed")
    require(isinstance(summary, dict), "Portfolio signal summary is missing")
    return evidence_id, digest, count, {str(k): int(v) for k, v in summary.items()}


def spotlight_snapshot(directory: Path) -> tuple[str, str, list[str]]:
    path = directory / "spotlight-manifest.json"
    require(path.is_file(), f"Engineering Spotlight manifest is missing: {path}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    version = payload.get("version")
    date = payload.get("selection_date_utc")
    slots = payload.get("slots")
    require(isinstance(version, str) and version, "Spotlight version is missing")
    require(isinstance(date, str) and date, "Spotlight selection date is missing")
    require(isinstance(slots, list) and len(slots) == 3, "Spotlight must contain three slots")
    repositories: list[str] = []
    for slot in slots:
        require(isinstance(slot, dict) and isinstance(slot.get("repository"), str), "Spotlight repository is missing")
        repositories.append(str(slot["repository"]))
    return version, date, repositories


def render_summary(env: dict[str, str], signal_dir: Path, spotlight_dir: Path, ledger_dir: Path) -> str:
    head = source_head(env)
    signal_id, signal_digest = signal_field_identity(signal_dir)
    portfolio_id, portfolio_digest, system_count, signal_summary = portfolio_identity(ledger_dir)
    spotlight_version, spotlight_date, repositories = spotlight_snapshot(spotlight_dir)
    attestation = attestation_contract()
    actions = action_identities()
    authority = privileged_authority()

    lines = [
        "# Profile Quality · read-only contract summary",
        "",
        f"- **Source head:** `{head}`",
        "- **Profile Quality authority:** `contents: read` only in both required jobs",
        f"- **Attestation predicate:** `{attestation['predicate_type']}` · schema v{attestation['schema_version']} · `{attestation['schema_digest']}` · {attestation['subject_count']} subjects",
        "",
        "## Validated evidence snapshot",
        "",
        "| Surface | Contract / scope | Identity |",
        "| --- | --- | --- |",
        f"| Signal Field | `signal-field-evidence-v1` | `{signal_id}` · `{signal_digest}` |",
        f"| Portfolio Evidence Ledger | `portfolio-evidence-ledger-v1` · {system_count} systems · `{json.dumps(signal_summary, sort_keys=True, separators=(',', ':'))}` | `{portfolio_id}` · `{portfolio_digest}` |",
        f"| Engineering Spotlight | `{spotlight_version}` · selection `{spotlight_date}` | " + " · ".join(f"`{repo}`" for repo in repositories) + " |",
        "",
        "## Immutable external Action identities",
        "",
        "| Repository | Reviewed release | Executable commit |",
        "| --- | --- | --- |",
    ]
    lines.extend(f"| `{repo}` | `{tag}` | `{sha}` |" for repo, tag, sha in actions)
    lines.extend([
        "",
        "## Reviewed write-capable authority boundaries",
        "",
        "| Workflow | Scope | Additional write authority |",
        "| --- | --- | --- |",
    ])
    lines.extend(f"| `{workflow}` | `{scope}` | `{grants}` |" for workflow, scope, grants in authority)
    lines.extend([
        "",
        "> This summary is generated from already-validated source and live integration evidence. It is informational and receives no repository-write, PR-write, OIDC, attestation, Actions-mutation, or security-event authority.",
        "",
    ])
    return "\n".join(lines)


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        signal = root / "signal"
        spotlight = root / "spotlight"
        ledger = root / "ledger"
        signal.mkdir()
        spotlight.mkdir()
        ledger.mkdir()
        (signal / "signal-field-wide-light.svg").write_text(
            '<svg data-evidence-id="SF1-0123456789ABCDEF" '
            f'data-evidence-digest="sha256:{"a" * 64}"></svg>',
            encoding="utf-8",
        )
        (ledger / "portfolio-evidence-ledger.json").write_text(
            json.dumps(
                {
                    "evidence_id": "PL1-0123456789ABCDEF",
                    "evidence_digest": f"sha256:{'b' * 64}",
                    "system_count": 13,
                    "signal_summary": {"PASSING": 25},
                }
            ),
            encoding="utf-8",
        )
        (spotlight / "spotlight-manifest.json").write_text(
            json.dumps(
                {
                    "version": "engineering-spotlight-v2.1",
                    "selection_date_utc": "2026-09-05",
                    "slots": [
                        {"repository": "portyu9/a"},
                        {"repository": "portyu9/b"},
                        {"repository": "portyu9/c"},
                    ],
                }
            ),
            encoding="utf-8",
        )
        event = root / "event.json"
        event.write_text(json.dumps({"pull_request": {"head": {"sha": "c" * 40}}}), encoding="utf-8")
        text = render_summary({"GITHUB_EVENT_PATH": str(event), "GITHUB_SHA": "d" * 40}, signal, spotlight, ledger)
        for phrase in (
            "read-only contract summary",
            "profile-evidence-v2.schema.json",
            "schema v2",
            "sha256:",
            "SF1-0123456789ABCDEF",
            "PL1-0123456789ABCDEF",
            "PASSING",
            "engineering-spotlight-v2.1",
            "Reviewed write-capable authority boundaries",
            "Immutable external Action identities",
            "`" + "c" * 40 + "`",
        ):
            require(phrase in text, f"summary self-test is missing: {phrase}")
    print("Profile Quality read-only contract summary self-test passed")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 1:
            raise ValueError("usage: write-profile-contract-summary.py | --self-test")
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
        require(bool(summary_path), "GITHUB_STEP_SUMMARY is unavailable")
        signal_dir = Path(os.environ.get("SIGNAL_FIELD_DIR", "roundtrip-signal-field"))
        spotlight_dir = Path(os.environ.get("SPOTLIGHT_DIR", "integration-engineering-spotlight"))
        ledger_dir = Path(os.environ.get("PORTFOLIO_LEDGER_DIR", "integration-portfolio-evidence"))
        text = render_summary(dict(os.environ), signal_dir, spotlight_dir, ledger_dir)
        Path(summary_path).write_text(text, encoding="utf-8")
        print(f"wrote read-only Profile Quality contract summary: {summary_path}")
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
