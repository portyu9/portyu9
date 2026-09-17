#!/usr/bin/env python3
"""Strict public release-ref proof for trusted Dependabot admission.

Network access remains in workflow YAML as a visible read-only `git ls-remote` surface. This
module only parses the captured direct/peeled tag refs and binds them to the expected exact
candidate commit SHA.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

SHA40 = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def resolve(output: str, *, repository: str, tag: str, expected_sha: str) -> str:
    require(REPOSITORY.fullmatch(repository) is not None, "Dependabot release repository is invalid")
    require(TAG.fullmatch(tag) is not None, "Dependabot release tag is invalid")
    require(SHA40.fullmatch(expected_sha) is not None, "Dependabot expected release SHA is invalid")
    direct = f"refs/tags/{tag}"
    peeled = f"{direct}^{{}}"
    refs: dict[str, str] = {}
    for raw in output.splitlines():
        fields = raw.split("\t", 1)
        require(len(fields) == 2, f"unexpected release-ref line for {repository}@{tag}")
        sha, ref = fields
        require(SHA40.fullmatch(sha) is not None, f"invalid release-ref SHA for {repository}@{tag}")
        require(ref in {direct, peeled}, f"unexpected release ref for {repository}@{tag}: {ref}")
        require(ref not in refs, f"duplicate release ref for {repository}@{tag}: {ref}")
        refs[ref] = sha
    require(direct in refs, f"Dependabot candidate release tag does not exist: {repository}@{tag}")
    resolved = refs.get(peeled, refs[direct])
    require(resolved == expected_sha,
            f"Dependabot release provenance mismatch: {repository}@{tag} resolves to {resolved}, candidate pins {expected_sha}")
    return resolved


def self_test() -> None:
    sha = "a" * 40
    tag_object = "b" * 40
    text = f"{tag_object}\trefs/tags/v1.2.3\n{sha}\trefs/tags/v1.2.3^{{}}\n"
    require(resolve(text, repository="owner/repo", tag="v1.2.3", expected_sha=sha) == sha,
            "Dependabot release self-test lost peeled annotated-tag resolution")
    lightweight = f"{sha}\trefs/tags/v1.2.3\n"
    require(resolve(lightweight, repository="owner/repo", tag="v1.2.3", expected_sha=sha) == sha,
            "Dependabot release self-test lost lightweight-tag resolution")
    try:
        resolve(text, repository="owner/repo", tag="v1.2.3", expected_sha="c" * 40)
    except ValueError:
        pass
    else:
        raise ValueError("Dependabot release self-test accepted mismatched provenance")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--refs", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    try:
        if args.self_test:
            self_test()
        resolved = resolve(
            args.refs.read_text(encoding="utf-8"),
            repository=args.repository,
            tag=args.tag,
            expected_sha=args.expected_sha,
        )
        args.out.write_text(resolved + "\n", encoding="utf-8")
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
