#!/usr/bin/env python3
"""Pure verifier for monotonic generated-publication epochs."""
from __future__ import annotations

import argparse
import json
import re
import sys
from typing import Any, Iterable

VERSION = "generated-publication-epoch-v1"
ALGORITHM = "first-parent-distance-tree-novelty-v1"
BOOTSTRAP_SHA = "ade981fd4fe114dde8bcacfde28236e4f0407ba1"
PUBLICATION_MESSAGE = "chore: publish validated profile evidence [skip ci]"
BOT_NAME = "github-actions[bot]"
BOT_EMAIL = "41898282+github-actions[bot]@users.noreply.github.com"
SHA40 = re.compile(r"^[0-9a-f]{40}$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical_sha(label: str, value: str) -> str:
    require(SHA40.fullmatch(value) is not None, f"{label} must be one lowercase 40-character Git SHA")
    return value


def parse_transcript(lines: Iterable[str]) -> list[dict[str, str]]:
    records: list[dict[str, str]] = []
    for line_number, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        require(bool(line), f"generated publication transcript line {line_number} is empty")
        fields = line.split("\t")
        require(len(fields) == 8,
                f"generated publication transcript line {line_number} must contain exactly eight tab-separated fields")
        commit, parents, tree, subject, author_name, author_email, committer_name, committer_email = fields
        records.append({
            "commitSha": canonical_sha("transcript commit", commit),
            "parents": parents,
            "treeSha": canonical_sha("transcript tree", tree),
            "subject": subject,
            "authorName": author_name,
            "authorEmail": author_email,
            "committerName": committer_name,
            "committerEmail": committer_email,
        })
    return records


def validate_records(
    records: list[dict[str, str]],
    *,
    head: str,
    bootstrap_tree: str,
    parent: str | None = None,
) -> dict[str, Any]:
    head = canonical_sha("generated publication head", head)
    bootstrap_tree = canonical_sha("generated publication bootstrap tree", bootstrap_tree)
    if parent is not None:
        parent = canonical_sha("generated publication parent", parent)

    expected_parent = BOOTSTRAP_SHA
    observed_trees = {bootstrap_tree}
    previous_commit = BOOTSTRAP_SHA
    previous_sequence = 0

    for sequence, record in enumerate(records, start=1):
        commit = record["commitSha"]
        parents = record["parents"]
        tree = record["treeSha"]
        require(SHA40.fullmatch(parents) is not None and parents == expected_parent,
                "generated publication lineage is not an exact one-parent chain")
        require(record["subject"] == PUBLICATION_MESSAGE,
                "generated publication commit message is outside the governed contract")
        require(record["authorName"] == BOT_NAME and record["authorEmail"] == BOT_EMAIL,
                "generated publication author identity is outside the governed contract")
        require(record["committerName"] == BOT_NAME and record["committerEmail"] == BOT_EMAIL,
                "generated publication committer identity is outside the governed contract")
        require(tree not in observed_trees,
                "generated publication history contains a semantic evidence tree replay")
        observed_trees.add(tree)
        previous_commit = commit
        previous_sequence = sequence
        expected_parent = commit

    if not records:
        require(head == BOOTSTRAP_SHA,
                "empty generated publication transcript is valid only at the frozen bootstrap")
        require(parent is None,
                "candidate publication transcript cannot be empty")
        return {
            "version": VERSION,
            "algorithm": ALGORITHM,
            "bootstrapSha": BOOTSTRAP_SHA,
            "commitSha": BOOTSTRAP_SHA,
            "sequence": 0,
            "treeSha": bootstrap_tree,
        }

    require(previous_commit == head,
            "generated publication transcript did not terminate at the selected head")
    current = records[-1]
    result: dict[str, Any] = {
        "version": VERSION,
        "algorithm": ALGORITHM,
        "bootstrapSha": BOOTSTRAP_SHA,
        "commitSha": head,
        "sequence": previous_sequence,
        "treeSha": current["treeSha"],
    }
    if parent is not None:
        require(current["parents"] == parent,
                "generated publication candidate parent differs from the sealed parent")
        parent_sequence = previous_sequence - 1
        expected_parent_commit = BOOTSTRAP_SHA if parent_sequence == 0 else records[-2]["commitSha"]
        require(parent == expected_parent_commit,
                "generated publication candidate parent is not the immediately preceding governed epoch")
        result.update({
            "parentSha": parent,
            "parentSequence": parent_sequence,
        })
        require(result["sequence"] == result["parentSequence"] + 1,
                "generated publication candidate sequence is not exactly parent sequence plus one")
    return result


def fixture_record(commit: str, parent: str, tree: str) -> dict[str, str]:
    return {
        "commitSha": commit,
        "parents": parent,
        "treeSha": tree,
        "subject": PUBLICATION_MESSAGE,
        "authorName": BOT_NAME,
        "authorEmail": BOT_EMAIL,
        "committerName": BOT_NAME,
        "committerEmail": BOT_EMAIL,
    }


def expect_failure(records: list[dict[str, str]], *, head: str, bootstrap_tree: str,
                   parent: str | None, expected: str) -> None:
    try:
        validate_records(records, head=head, bootstrap_tree=bootstrap_tree, parent=parent)
    except ValueError as exc:
        require(expected in str(exc), f"publication epoch self-test failed for wrong reason: {exc}")
    else:
        raise ValueError(f"publication epoch self-test accepted forbidden drift: {expected}")


def self_test() -> None:
    bootstrap_tree = "0" * 40
    first = fixture_record("1" * 40, BOOTSTRAP_SHA, "a" * 40)
    second = fixture_record("2" * 40, "1" * 40, "b" * 40)
    first_epoch = validate_records([first], head="1" * 40, bootstrap_tree=bootstrap_tree, parent=BOOTSTRAP_SHA)
    require(first_epoch["parentSequence"] == 0 and first_epoch["sequence"] == 1,
            "publication epoch self-test lost exact parent+1 monotonicity")
    observed = validate_records([first, second], head="2" * 40, bootstrap_tree=bootstrap_tree)
    require(observed["sequence"] == 2 and observed["treeSha"] == "b" * 40,
            "publication epoch self-test failed deterministic head derivation")

    replay = fixture_record("3" * 40, "2" * 40, "a" * 40)
    expect_failure(
        [first, second, replay], head="3" * 40, bootstrap_tree=bootstrap_tree,
        parent="2" * 40, expected="semantic evidence tree replay",
    )
    merge = fixture_record("3" * 40, "2" * 40 + " " + "9" * 40, "c" * 40)
    expect_failure(
        [first, second, merge], head="3" * 40, bootstrap_tree=bootstrap_tree,
        parent="2" * 40, expected="one-parent chain",
    )
    wrong_parent = fixture_record("3" * 40, "9" * 40, "c" * 40)
    expect_failure(
        [first, second, wrong_parent], head="3" * 40, bootstrap_tree=bootstrap_tree,
        parent="2" * 40, expected="one-parent chain",
    )
    baseline = validate_records([], head=BOOTSTRAP_SHA, bootstrap_tree=bootstrap_tree)
    require(baseline["sequence"] == 0 and baseline["treeSha"] == bootstrap_tree,
            "publication epoch self-test lost bootstrap epoch zero")
    print(f"Generated publication epoch self-test passed: {VERSION} · pure transcript verifier · parent+1 · tree replay rejected")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--head")
    parser.add_argument("--parent")
    parser.add_argument("--bootstrap-tree")
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.self_test:
            require(args.head is None and args.parent is None and args.bootstrap_tree is None,
                    "--self-test cannot be combined with epoch arguments")
            self_test()
            return 0
        require(args.head is not None and args.bootstrap_tree is not None,
                "epoch mode requires --head and --bootstrap-tree")
        records = parse_transcript(sys.stdin)
        payload = validate_records(
            records,
            head=str(args.head),
            parent=str(args.parent) if args.parent is not None else None,
            bootstrap_tree=str(args.bootstrap_tree),
        )
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
