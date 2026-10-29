#!/usr/bin/env python3
"""Authenticated fixed-origin *read-only* source for native banner App evidence.

The existing publisher possesses a selected-installation App JWT in its isolated
environment. This transport accepts that JWT only for GET /app/installations/<id>
and an independent read token only for the exact repository and App bot user.
It never mints tokens, issues reviews/checks, mutates GitHub or moves refs.
Credentials never appear in output. The resulting minimal envelope is STILL
DATA, not approval or protected-merge authority.
"""
from __future__ import annotations

import argparse
import copy
import http.client
import json
import os
from pathlib import Path
import re
import ssl
from typing import Any, Callable

import banner_native_app_origin_envelope as envelope

HOST = "api.github.com"
REPOSITORY = "/repos/portyu9/portyu9"
MAX_BYTES = 512_000
BOT_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{2,100}$")


def require(valid: bool, reason: str) -> None:
    if not valid:
        raise ValueError(reason)


class FixedOriginRead:
    """One token, an immutable GET allowlist and GitHub's exact HTTPS origin."""

    def __init__(self, token: str, allowed: frozenset[str],
                 connection_factory: Callable[..., Any] | None = None):
        require(type(token) is str and len(token) >= 8
                and not any(char.isspace() for char in token),
                "read-only GitHub bearer credential missing or malformed")
        require(type(allowed) is frozenset and bool(allowed)
                and all(type(path) is str and path.startswith("/")
                        and "?" not in path and "#" not in path
                        and "\\" not in path and ".." not in path
                        for path in allowed),
                "read-only GitHub endpoint allowlist malformed")
        self.__token = token
        self.__allowed = allowed
        self.__factory = connection_factory or http.client.HTTPSConnection

    def get(self, path: str) -> dict[str, Any]:
        require(type(path) is str and path in self.__allowed,
                "unreviewed native App source endpoint")
        connection = self.__factory(
            HOST, timeout=15, context=ssl.create_default_context()
        )
        try:
            connection.request("GET", path, headers={
                "Authorization": "Bearer " + self.__token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "portyu9-banner-app-origin-readonly",
            })
            result = connection.getresponse()
            require(result.status == 200,
                    "native App source must return HTTP 200 without redirect")
            require(result.getheader("Link") is None,
                    "single native identity object must not be paginated")
            payload = result.read(MAX_BYTES + 1)
        finally:
            connection.close()
        require(len(payload) <= MAX_BYTES,
                "native App source response exceeded byte limit")
        try:
            parsed = json.loads(payload.decode("utf-8"),
                                object_pairs_hook=unique_object)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ValueError("native App source response must be unique-key UTF-8 JSON") from exc
        require(type(parsed) is dict, "native App source must return a JSON object")
        return parsed


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        require(key not in value, "duplicate native GitHub identity field")
        value[key] = item
    return value


def collect(*, get_installation: Callable[[str], Any],
            get_public: Callable[[str], Any], app_id: int,
            installation_id: int, repository_id: int) -> dict[str, Any]:
    """Read exact endpoints in deterministic order and minimize secret-free data."""
    require(all(type(i) is int and i > 0 for i in (
        app_id, installation_id, repository_id
    )), "native App source IDs must be positive non-boolean integers")
    installation = get_installation(f"/app/installations/{installation_id}")
    require(type(installation) is dict,
            "native App installation object missing")
    slug = installation.get("app_slug")
    require(type(slug) is str and BOT_SLUG.fullmatch(slug) is not None,
            "native App installation bot slug malformed")
    bot_path = f"/users/{slug}%5Bbot%5D"
    bot = get_public(bot_path)
    repository = get_public(REPOSITORY)
    return envelope.minimize({
        "installation": installation,
        "bot_user": bot,
        "repository": repository,
        "expected_app_id": app_id,
        "expected_installation_id": installation_id,
        "expected_repository_id": repository_id,
    })


def self_test() -> None:
    import banner_native_live_admission as admission

    fixture = copy.deepcopy(admission.fixture()["nativeApp"])
    fixture["repository"] = {
        "id": fixture["expected_repository_id"],
        "full_name": "portyu9/portyu9",
        "owner": {"login": "portyu9"},
    }
    install = fixture["installation"]
    slug = install["app_slug"]
    paths: list[tuple[str, str]] = []

    def app(path: str) -> Any:
        paths.append(("app", path))
        require(path == f"/app/installations/{install['id']}",
                "App JWT route changed")
        return copy.deepcopy(install)

    def public(path: str) -> Any:
        paths.append(("public", path))
        if path == f"/users/{slug}%5Bbot%5D":
            return copy.deepcopy(fixture["bot_user"])
        require(path == REPOSITORY, "public read route changed")
        return copy.deepcopy(fixture["repository"])

    args = {"get_installation": app, "get_public": public,
            "app_id": fixture["expected_app_id"],
            "installation_id": fixture["expected_installation_id"],
            "repository_id": fixture["expected_repository_id"]}
    minimal = collect(**args)
    require(minimal == envelope.minimize(fixture)
            and paths == [
                ("app", f"/app/installations/{install['id']}"),
                ("public", f"/users/{slug}%5Bbot%5D"),
                ("public", REPOSITORY),
            ], "App JWT/public response origins or minimal envelope drifted")

    def denied(description: str, changes: dict[str, Any]) -> None:
        try:
            collect(**{**args, **changes})
        except (ValueError, TypeError, KeyError):
            return
        raise AssertionError("malformed native App source passed: " + description)

    denied("boolean app", {"app_id": True})
    denied("wrong app", {"app_id": fixture["expected_app_id"] + 1})
    denied("wrong repo", {"repository_id": fixture["expected_repository_id"] + 1})
    denied("wrong installation", {"installation_id": install["id"] + 1})
    denied("attacker repo", {"get_public": lambda _p: {
        "id": fixture["expected_repository_id"], "full_name": "attacker/repo",
        "owner": {"login": "attacker"}}})

    class Response:
        status = 200
        def __init__(self, data: bytes, status: int = 200):
            self.data, self.status = data, status
        def getheader(self, _name: str) -> None:
            return None
        def read(self, _limit: int) -> bytes:
            return self.data

    class Connection:
        def __init__(self, response: Response):
            self.response = response
            self.calls: list[tuple[str, str, dict[str, str]]] = []
        def request(self, method: str, path: str, headers: dict[str, str]) -> None:
            self.calls.append((method, path, headers))
        def getresponse(self) -> Response:
            return self.response
        def close(self) -> None:
            pass

    seen: list[Connection] = []
    def factory(_host: str, **_kwargs: Any) -> Connection:
        connection = Connection(Response(b'{"id":1}'))
        seen.append(connection)
        return connection

    reader = FixedOriginRead("fixture-token", frozenset({REPOSITORY}), factory)
    require(reader.get(REPOSITORY) == {"id": 1}
            and seen[0].calls[0][:2] == ("GET", REPOSITORY),
            "fixed-origin GET did not bind endpoint")
    try:
        reader.get("/repos/attacker/repo")
    except ValueError:
        pass
    else:
        raise AssertionError("unreviewed GitHub source URL accepted")
    require(len(seen) == 1, "unreviewed source request reached network")
    for label, response in (
        ("redirect", Response(b'{"id":1}', 302)),
        ("duplicate", Response(b'{"id":1,"id":2}')),
        ("oversized", Response(b" " * (MAX_BYTES + 1))),
        ("not-object", Response(b"[]")),
    ):
        try:
            FixedOriginRead("fixture-token", frozenset({REPOSITORY}),
                            lambda *_a, **_kw: Connection(response)).get(REPOSITORY)
        except (ValueError, json.JSONDecodeError):
            continue
        raise AssertionError("untrusted native App transport accepted: " + label)
    print("native banner App origin: fixed HTTPS GET, split identities, "
          "no redirects/duplicate fields, exact repo/installation, "
          "secret-free envelope and adversarial negatives PASS")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--app-id", type=int)
    parser.add_argument("--installation-id", type=int)
    parser.add_argument("--repository-id", type=int)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.self_test:
        require(all(getattr(args, key) is None for key in (
            "app_id", "installation_id", "repository_id", "output"
        )), "native App self-test must not receive live credentials/paths")
        self_test()
        return 0
    require(all(getattr(args, key) is not None for key in (
        "app_id", "installation_id", "repository_id", "output"
    )), "native App origin requires all exact IDs and one output path")
    app_jwt = os.environ.get("BANNER_APP_JWT")
    read_token = os.environ.get("GH_TOKEN")
    require(app_jwt is not None and read_token is not None
            and app_jwt != read_token,
            "independent App JWT and public-read identities required")
    slug = "[a-z0-9][a-z0-9-]{2,100}"
    require(bool(slug), "reviewed bot slug pattern must be present")
    app = FixedOriginRead(
        app_jwt, frozenset({f"/app/installations/{args.installation_id}"})
    )
    # A runtime App slug cannot broaden a public URL into another repo.
    # Install first, then create a second constrained client for its bot.
    installed = app.get(f"/app/installations/{args.installation_id}")
    name = installed.get("app_slug")
    require(type(name) is str and BOT_SLUG.fullmatch(name) is not None,
            "native App bot slug invalid before scoped GET")
    read = FixedOriginRead(
        read_token, frozenset({REPOSITORY, f"/users/{name}%5Bbot%5D"})
    )
    result = collect(
        get_installation=lambda path: installed if path ==
            f"/app/installations/{args.installation_id}" else None,
        get_public=read.get, app_id=args.app_id,
        installation_id=args.installation_id,
        repository_id=args.repository_id,
    )
    import banner_native_observer_cli as observer
    observer.write_exclusive(args.output, result)
    print("native-selected-app-origin-authenticated-readonly-no-write")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
