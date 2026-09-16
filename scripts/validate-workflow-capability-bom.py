#!/usr/bin/env python3
"""Temporary read-only diagnostic: emit canonical BOM extensions and exact authorization tuple."""
from __future__ import annotations

import base64
import gzip
import json
from pathlib import Path
import sys
import tempfile
import urllib.error
import urllib.request

import trusted_workflow_capability
import workflow_capability_admission
import workflow_capability_bom as compiler
import workflow_capability_diff
import workflow_capability_tcb

ROOT = Path(__file__).resolve().parents[1]
BASE_SHA = "d9222d2732ffc3d97de21b479042466b3675ba78"
RAW_ROOT = f"https://raw.githubusercontent.com/portyu9/portyu9/{BASE_SHA}/"
BASE_BOMS = (
    ".github/workflow-capability-bom-v1.json",
    ".github/workflow-capability-bom-v1-capability-admission.json",
    ".github/workflow-capability-bom-v1-codeql-autofix.json",
)


def fetch(path: str) -> bytes | None:
    request = urllib.request.Request(RAW_ROOT + path, headers={"User-Agent": "portyu9-read-only-auth-diagnostic"})
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def base_bom() -> dict[str, object]:
    parts = []
    for path in BASE_BOMS:
        raw = fetch(path)
        if raw is None:
            raise ValueError(f"missing trusted base BOM: {path}")
        parts.append(json.loads(raw.decode("utf-8")))
    base, admission, autofix = parts
    workflows = list(base["workflows"]) + list(admission["workflows"]) + list(autofix["workflows"])
    workflows.sort(key=lambda workflow: workflow["path"])
    combined = {key: base[key] for key in base if key != "workflows"}
    combined["workflows"] = workflows
    return combined


def emit_part(candidate: dict[str, object], workflow_id: str) -> None:
    workflows = candidate["workflows"]
    if not isinstance(workflows, list):
        raise ValueError("candidate workflows must be a list")
    matches = [workflow for workflow in workflows if isinstance(workflow, dict) and workflow.get("id") == workflow_id]
    if len(matches) != 1:
        raise ValueError(f"expected one workflow: {workflow_id}")
    part = {key: candidate[key] for key in candidate if key != "workflows"}
    part["workflows"] = matches
    raw = compiler.canonical_json(part).encode("utf-8")
    packed = gzip.compress(raw, mtime=0)
    print(f"BOM_DIAG {workflow_id} {len(raw)} {base64.b64encode(packed).decode('ascii')}")


def main() -> int:
    base = base_bom()
    candidate = trusted_workflow_capability.compile_repository(ROOT)
    emit_part(candidate, "capability-admission")
    emit_part(candidate, "codeql-autofix")

    diff = workflow_capability_diff.semantic_diff(base, candidate)
    diff = workflow_capability_admission.protect_trusted_control(base, candidate, diff)

    candidate_protected = workflow_capability_tcb.protected_files(ROOT)
    with tempfile.TemporaryDirectory(prefix="trusted-base-tcb-") as temp:
        base_root = Path(temp)
        for path in candidate_protected:
            raw = fetch(path)
            if raw is None:
                continue
            target = base_root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        source_expansions = workflow_capability_tcb.source_expansions(base_root, ROOT, BASE_SHA)

    diff = workflow_capability_admission.with_expansions(diff, source_expansions)
    tcb_hashes = sorted({
        item["after"]["candidateTcbSha256"]
        for item in source_expansions
        if isinstance(item.get("after"), dict) and item["after"].get("candidateTcbSha256")
    })
    if len(tcb_hashes) != 1:
        raise ValueError(f"expected one candidate TCB digest, got {len(tcb_hashes)}")
    source_keys = sorted(item["key"] for item in source_expansions)
    result = {
        "baseBomSha256": diff["baseBomSha256"],
        "candidateBomSha256": diff["candidateBomSha256"],
        "expansionSha256": diff["expansionSha256"],
        "expansionCount": len(diff["expansions"]),
        "reductionCount": len(diff["reductions"]),
        "candidateTcbSha256": tcb_hashes[0],
        "trustedSourceKeys": source_keys,
    }
    print("AUTH_TUPLE " + compiler.canonical_json(result).strip())
    print("ERROR: intentional authorization diagnostic failure", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
