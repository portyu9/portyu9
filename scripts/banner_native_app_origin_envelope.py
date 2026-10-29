#!/usr/bin/env python3
"""Pure minimal selected-installation banner App identity evidence.

A trusted-main caller MUST authenticate the independent GitHub App JWT GET
responses and expected environment-scoped App/installation/repository IDs
before passing them here. A JSON snapshot alone cannot prove HTTPS origin,
grant a reviewer identity, mint an App token or authorize a protected merge.

This bridge reduces real installation and bot user responses to the exact
non-secret shape accepted by the existing native banner REST/GraphQL observer.
It rejects credentials and duplicate/ambiguous identity fields instead of
emitting raw installation metadata into cross-job artifacts.
"""
from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from independent_banner_candidate_contract import (
    verified_native_banner_app_identity,
)

INPUT = frozenset({
    "installation", "bot_user", "repository", "expected_app_id",
    "expected_installation_id", "expected_repository_id",
})
FORBIDDEN = frozenset({
    "token", "access_token", "private_key", "client_secret",
    "password", "authorization", "jwt",
})


def require(valid: bool, reason: str) -> None:
    if not valid:
        raise ValueError(reason)


def no_credentials(node: Any, *, depth: int = 0) -> None:
    require(depth <= 12, "App origin input nested beyond reviewed limit")
    if type(node) is dict:
        require(not (set(node) & FORBIDDEN),
                "App origin input contains credential-bearing fields")
        for child in node.values():
            no_credentials(child, depth=depth + 1)
    elif type(node) is list:
        require(len(node) <= 100,
                "App origin input contains an oversized unreviewed list")
        for child in node:
            no_credentials(child, depth=depth + 1)


def minimize(raw: Any) -> dict[str, Any]:
    """Normalize one authenticated response pair, NEVER certify its origin."""
    require(type(raw) is dict and set(raw) == INPUT,
            "App origin has missing, duplicate or unreviewed top-level fields")
    no_credentials(raw)
    repository = raw["repository"]
    require(type(repository) is dict
            and type(repository.get("id")) is int
            and repository["id"] == raw["expected_repository_id"]
            and repository.get("full_name") == "portyu9/portyu9"
            and type(repository.get("owner")) is dict
            and repository["owner"].get("login") == "portyu9",
            "App origin exact repository ID/name/owner response differs")
    trusted = {key: raw[key] for key in raw if key != "repository"}
    identity = verified_native_banner_app_identity(**trusted)
    installation = raw["installation"]
    bot = raw["bot_user"]
    observed = {
        "installation": {
            "id": installation["id"],
            "app_id": installation["app_id"],
            "app_slug": installation["app_slug"],
            "repository_selection": installation["repository_selection"],
            "permissions": {
                "contents": installation["permissions"]["contents"],
                "pull_requests": installation["permissions"]["pull_requests"],
            },
            "account": {"login": installation["account"]["login"]},
        },
        "bot_user": {
            "id": bot["id"],
            "login": bot["login"],
            "type": bot["type"],
        },
        "expected_app_id": raw["expected_app_id"],
        "expected_installation_id": raw["expected_installation_id"],
        "expected_repository_id": raw["expected_repository_id"],
    }
    require(set(observed) == INPUT - {"repository"}
            and verified_native_banner_app_identity(**observed) == identity,
            "minimal native App identity evidence lost reviewed binding")
    no_credentials(observed)
    # Deny type coercion and ensure predictable canonical JSON output shape.
    require(type(observed["expected_app_id"]) is int
            and type(observed["expected_installation_id"]) is int
            and type(observed["expected_repository_id"]) is int,
            "minimal App identity numeric subject is not canonical")
    return observed


def self_test() -> None:
    import banner_native_live_admission as admission

    fixture = copy.deepcopy(admission.fixture()["nativeApp"])
    fixture["repository"] = {
        "id": fixture["expected_repository_id"],
        "full_name": "portyu9/portyu9",
        "owner": {"login": "portyu9"},
    }
    good = minimize(fixture)
    require(set(good) == INPUT - {"repository"}
            and good["installation"]["repository_selection"] == "selected"
            and good["bot_user"]["login"].endswith("[bot]"),
            "minimal selected-installation positive evidence rejected")
    require(minimize({**good, "repository": fixture["repository"]}) == good,
            "minimal App evidence is not stable after re-authentication")
    payload = json.dumps(good, sort_keys=True, separators=(",", ":"))
    require("token" not in payload and "private_key" not in payload,
            "App evidence output unexpectedly contains a credential")

    def rejected(label: str, mutate: Any) -> None:
        data = copy.deepcopy(fixture)
        mutate(data)
        try:
            minimize(data)
        except (TypeError, KeyError, ValueError):
            return
        raise AssertionError("untrusted native App evidence accepted: " + label)

    cases = [
        ("unexpected token", lambda x: x.update(token="danger")),
        ("nested private key",
         lambda x: x["installation"].update(private_key="danger")),
        ("bot token", lambda x: x["bot_user"].update(access_token="danger")),
        ("wrong App", lambda x: x.update(expected_app_id=98765)),
        ("wrong installation",
         lambda x: x.update(expected_installation_id=98765)),
        ("wrong repository ID",
         lambda x: x.update(expected_repository_id=98765)),
        ("wrong observed repository ID",
         lambda x: x["repository"].update(id=98765)),
        ("wrong repository name",
         lambda x: x["repository"].update(full_name="attacker/repo")),
        ("wrong repository owner",
         lambda x: x["repository"]["owner"].update(login="attacker")),
        ("boolean App ID",
         lambda x: x.update(expected_app_id=True)),
        ("unselected installation",
         lambda x: x["installation"].update(repository_selection="all")),
        ("wrong owner",
         lambda x: x["installation"]["account"].update(login="attacker")),
        ("unmatched bot",
         lambda x: x["bot_user"].update(login="attacker[bot]")),
        ("human actor",
         lambda x: x["bot_user"].update(type="User")),
        ("wrong capability",
         lambda x: x["installation"]["permissions"].update(contents="read")),
    ]
    for label, rewrite in cases:
        rejected(label, rewrite)
    print("banner App identity minimal envelope: selected App, producer bot, "
          "immutable IDs, secret-free canonical output and 15 negatives PASS; "
          "zero JWT, network or mutation")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.self_test:
        require(args.input is None and args.output is None,
                "App origin self-test cannot use external evidence")
        self_test()
        return 0
    require(args.input is not None and args.output is not None
            and args.input != args.output,
            "App origin needs one bounded input and new exclusive output")
    # Import the already-accepted O_NOFOLLOW / O_EXCL filesystem transport
    # ONLY in the executable CLI, never in the pure protected self-test graph.
    import banner_native_observer_cli as observer
    evidence = observer.read_bounded(args.input)
    result = minimize(evidence)
    observer.write_exclusive(args.output, result)
    print("exact-selected-native-banner-app-evidence-data-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
