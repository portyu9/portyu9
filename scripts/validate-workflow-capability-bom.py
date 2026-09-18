#!/usr/bin/env python3
"""Diagnostic: emit canonical GitHub-native bot user-approval capability entry."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

MAIN_SHA = "f5ff387cc304c282351d8fdea101c625c3a320dd"
CANDIDATE_SHA = "ef2ddc639b833aca405f9f9147bea9b92ed28ce5"
CANDIDATE_TREE_SHA = "2122bee4fc6df654998e754a49647711191dd457"

EVALUATOR = r"""
from pathlib import Path
import json
import sys
import workflow_capability_admission as admission
import workflow_capability_diff as capability_diff
import workflow_capability_snapshot as snapshot
import trusted_workflow_capability

candidate_root = Path(sys.argv[1]).resolve()
candidate_tree_sha = sys.argv[2]
base = snapshot.load_combined()
candidate = trusted_workflow_capability.compile_repository(candidate_root)
entry = [item for item in candidate["workflows"] if item["id"] == "bot-pr-user-approval"]
if len(entry) != 1:
    raise SystemExit(f"expected one bot-pr-user-approval entry, got {len(entry)}")
print("CANONICAL_BOT_PR_USER_APPROVAL=" + json.dumps(entry[0], sort_keys=True, separators=(",", ":")))
diff = capability_diff.semantic_diff(base, candidate)
diff = admission.protect_trusted_control(base, candidate, diff)
diff = admission.protect_trusted_sources(candidate_root, candidate_tree_sha, diff)
print("TRUSTED_BASE_BOM_SHA256=" + diff["baseBomSha256"])
print("TRUSTED_CANDIDATE_BOM_SHA256=" + diff["candidateBomSha256"])
print("TRUSTED_EXPANSION_SHA256=" + diff["expansionSha256"])
print("TRUSTED_EXPANSION_COUNT=" + str(len(diff["expansions"])))
print("TRUSTED_REDUCTION_COUNT=" + str(len(diff["reductions"])))
"""

def run(*args: str, cwd: Path | None = None, env: dict[str, str] | None = None) -> None:
    subprocess.run(args, cwd=cwd, env=env, check=True)

def main() -> int:
    with tempfile.TemporaryDirectory(prefix="bot-pr-user-approval-bom-") as tmp:
        root = Path(tmp)
        trusted = root / "trusted"
        candidate = root / "candidate"
        run("git", "fetch", "--no-tags", "--depth=1", "origin", MAIN_SHA, CANDIDATE_SHA)
        run("git", "worktree", "add", "--detach", str(trusted), MAIN_SHA)
        run("git", "worktree", "add", "--detach", str(candidate), CANDIDATE_SHA)
        actual_tree = subprocess.check_output(["git", "-C", str(candidate), "rev-parse", "HEAD^{tree}"], text=True).strip()
        if actual_tree != CANDIDATE_TREE_SHA:
            raise ValueError(f"candidate tree mismatch: {actual_tree}")
        env = dict(os.environ)
        env["PYTHONPATH"] = str(trusted / "scripts")
        run(sys.executable, "-c", EVALUATOR, str(candidate), CANDIDATE_TREE_SHA, cwd=trusted, env=env)
    print("ERROR: diagnostic intentionally stops after canonical capability emission", file=sys.stderr)
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
