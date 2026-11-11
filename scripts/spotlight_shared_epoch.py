#!/usr/bin/env python3
"""Classify signed Profile Stats→Spotlight publication epochs without granting stale authority.

A superseded epoch is an authenticated read-only no-op, never an authorization.
Malformed or unrelated epochs fail closed; a current exact pair follows the
existing independent check, review, lease and protected merge paths.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import subprocess
import sys

SHA40 = re.compile(r"[0-9a-f]{40}\Z")
BOT_ACTOR = "github-actions[bot]"


def require(value: bool, message: str) -> None:
    if not value:
        raise ValueError(f"Spotlight shared publication epoch: {message}")


def validate_sha(value: str, label: str) -> str:
    require(isinstance(value, str) and SHA40.fullmatch(value) is not None,
            f"{label} is not a canonical SHA-40")
    return value


def classify(*, current_main: str, current_generated: str,
             upstream_main: str, upstream_generated: str,
             accepted_main_history: set[str], generated_history: set[str],
             event: str, actor: str, ref: str) -> str:
    """Pure fail-closed state transition: current | unbound | superseded."""
    current_main = validate_sha(current_main, "current main")
    current_generated = validate_sha(current_generated, "current generated")
    require(ref == "refs/heads/main", "the workflow is not bound to main")
    require(current_main in accepted_main_history, "current main history is incomplete")
    require(current_generated in generated_history, "generated history is incomplete")

    if not upstream_main and not upstream_generated:
        return "unbound"
    require(event == "workflow_dispatch", "bound pair requires a workflow dispatch")
    upstream_main = validate_sha(upstream_main, "upstream main")
    upstream_generated = validate_sha(upstream_generated, "upstream generated")
    if upstream_main == current_main and upstream_generated == current_generated:
        return "current"

    # Only the official publication workflow's Actions actor can safely
    # suppress a stale callback. No stale input is used for plan, lease or write.
    require(actor == BOT_ACTOR, "superseded dispatch actor is not the publication bot")
    require(upstream_main in accepted_main_history,
            "upstream main is not in accepted first-parent history")
    require(upstream_generated in generated_history,
            "upstream generated is not in accepted first-parent history")
    return "superseded"


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(["git", "-C", str(repo), *args],
                          text=True, capture_output=True, check=False, timeout=20)
    require(proc.returncode == 0 and bool(proc.stdout.strip()),
            "trusted Git publication ancestry lookup failed")
    return proc.stdout.strip()


def first_parent_history(repo: Path, head: str) -> set[str]:
    require(git(repo, "rev-parse", "--is-shallow-repository") == "false",
            "trusted history is shallow and cannot prove first-parent lineage")
    history = git(repo, "rev-list", "--first-parent", head).splitlines()
    require(len(history) == len(set(history)) and bool(history) and history[0] == head,
            "trusted first-parent history is ambiguous")
    require(all(SHA40.fullmatch(item) is not None for item in history),
            "trusted first-parent history contains invalid Git objects")
    return set(history)


def self_test() -> None:
    m0, m1, m2, g0, g1 = ("1" * 40, "2" * 40, "3" * 40,
                         "a" * 40, "b" * 40)
    base = dict(current_main=m2, current_generated=g1,
                accepted_main_history={m0, m1, m2},
                generated_history={g0, g1},
                event="workflow_dispatch", actor=BOT_ACTOR, ref="refs/heads/main")
    def expect(label: str, expected: str, **overrides: object) -> None:
        data = {**base, "upstream_main": m2, "upstream_generated": g1, **overrides}
        require(classify(**data) == expected, f"{label} classification regressed")
    def reject(label: str, **overrides: object) -> None:
        try:
            classify(**{**base, "upstream_main": m2,
                        "upstream_generated": g1, **overrides})
        except ValueError:
            return
        raise ValueError(f"{label} was admitted unexpectedly")

    expect("current exact", "current")
    expect("missing optional pair", "unbound", upstream_main="", upstream_generated="",
           event="push", actor="portyu9")
    expect("valid main advance", "superseded", upstream_main=m1)
    expect("valid generated advance", "superseded", upstream_generated=g0)
    expect("both advanced", "superseded", upstream_main=m0, upstream_generated=g0)
    # A concurrent current-main push/schedule run is never classified as stale.
    expect("independent current-main event", "unbound", upstream_main="",
           upstream_generated="", event="schedule", actor="github-actions[bot]")
    reject("half pair main", upstream_main="")
    reject("half pair generated", upstream_generated="")
    reject("malformed main", upstream_main="B" * 40)
    reject("malformed generated", upstream_generated="x" * 40)
    reject("unrelated main", upstream_main="f" * 40)
    reject("unrelated publication", upstream_generated="f" * 40)
    reject("wrong dispatch actor", upstream_main=m1, actor="portyu9")
    reject("wrong event", upstream_main=m1, event="push")
    reject("wrong ref", upstream_main=m1, ref="refs/heads/generated")
    reject("untrusted history", upstream_main=m1, accepted_main_history={m2})
    reject("current main identity missing", accepted_main_history={m0, m1})
    reject("current publication missing", generated_history={g0})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--source-repo", type=Path)
    parser.add_argument("--published-repo", type=Path)
    parser.add_argument("--main", default="")
    parser.add_argument("--upstream-main", default="")
    parser.add_argument("--upstream-generated", default="")
    parser.add_argument("--event", default="")
    parser.add_argument("--actor", default="")
    parser.add_argument("--ref", default="")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    try:
        if args.self_test:
            self_test()
            print("Spotlight shared publication-epoch 18-case self-test passed.")
            return 0
        require(args.source_repo is not None and args.published_repo is not None
                and args.output is not None, "required provenance inputs are missing")
        current_main = validate_sha(args.main, "workflow main source")
        require(git(args.source_repo, "rev-parse", "HEAD") == current_main,
                "checked-out source differs from exact workflow commit")
        current_generated = validate_sha(git(args.published_repo, "rev-parse", "HEAD"),
                                         "published generated head")
        outcome = classify(
            current_main=current_main, current_generated=current_generated,
            upstream_main=args.upstream_main, upstream_generated=args.upstream_generated,
            accepted_main_history=first_parent_history(args.source_repo, current_main),
            generated_history=first_parent_history(args.published_repo, current_generated),
            event=args.event, actor=args.actor, ref=args.ref,
        )
        # No old main/generated input is returned to any downstream job.
        with args.output.open("a", encoding="utf-8") as stream:
            stream.write(f"superseded={'true' if outcome == 'superseded' else 'false'}\n")
        if outcome == "superseded":
            print("SUPERSEDED: trusted older Profile Stats publication epoch; no Spotlight "
                  "plan, lease, stale candidate mutation, approval, or merge authorized.")
        else:
            print(f"Spotlight shared publication epoch: {outcome}; independent live "
                  "current-main/current-generated proof is still required.")
        return 0
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
