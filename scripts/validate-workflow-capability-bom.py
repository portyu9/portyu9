#!/usr/bin/env python3
"""Diagnostic: emit authoritative full-PR binder capability tuple."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile

MAIN_SHA = "14767b3183532cb7aa55a824e78c86cdf7f364d4"
CANDIDATE_SHA = "66cb718a5d44db7a05ee4ea435b599b13124b798"
CANDIDATE_TREE_SHA = "fcfe96b27b69bf4366add5892d843b4203bec3f4"

EVALUATOR = r"""
from pathlib import Path
import sys
import workflow_capability_admission as admission
import workflow_capability_diff as capability_diff
import workflow_capability_snapshot as snapshot
import trusted_workflow_capability

candidate_root = Path(sys.argv[1]).resolve()
candidate_tree_sha = sys.argv[2]
base = snapshot.load_combined()
candidate = trusted_workflow_capability.compile_repository(candidate_root)
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
    with tempfile.TemporaryDirectory(prefix="dependabot-binder-tuple-") as tmp:
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
    print("ERROR: diagnostic intentionally stops after authoritative tuple emission", file=sys.stderr)
    return 1

if __name__ == "__main__":
    raise SystemExit(main())
