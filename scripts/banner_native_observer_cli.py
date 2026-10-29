#!/usr/bin/env python3
"""Read-only native banner observer for separately authenticated trusted-main callers.

The observer collects complete GitHub REST/GraphQL evidence and bridges the
existing pure first-phase and two-phase terminal gates. It neither establishes
the origin of caller-supplied App evidence nor grants permission to review,
merge or mutate a ref. A future separately authorized writer MUST authenticate
the App metadata source and reviewer identity, re-read immediately before its
own exact-head ordinary protected mutation, and enforce native authorization.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import banner_native_live_admission as admission
import banner_native_rest_transport as rest
import banner_native_snapshot_collector as collector
import banner_native_terminal_reproof as terminal
import independent_banner_candidate_contract as contract

MAX_FILE_BYTES = 1_048_576
APP_KEYS = frozenset({
    "installation", "bot_user", "expected_app_id",
    "expected_installation_id", "expected_repository_id",
})


def require(ok: bool, explanation: str) -> None:
    if not ok:
        raise ValueError(explanation)


def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, "banner observer rejected duplicate JSON key")
        result[key] = value
    return result


def read_bounded(path: Path) -> Any:
    require(type(path) is Path, "banner observer input needs a concrete file path")
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path, flags)
    try:
        details = os.fstat(descriptor)
        require(stat.S_ISREG(details.st_mode)
                and 0 < details.st_size <= MAX_FILE_BYTES,
                "banner observer input must be a bounded regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(MAX_FILE_BYTES + 1)
        require(len(content) == details.st_size,
                "banner observer input changed during read")
    finally:
        os.close(descriptor)
    try:
        return json.loads(content.decode("utf-8"), object_pairs_hook=unique_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("banner observer input must be strict UTF-8 JSON") from exc


def encode_bounded(value: Any) -> bytes:
    content = (
        json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    require(0 < len(content) <= MAX_FILE_BYTES,
            "banner observer output exceeds the bounded evidence size")
    return content


def write_exclusive(path: Path, evidence: Any) -> None:
    """Create one new 0600 regular file; never truncate existing/symlink data."""
    content = encode_bounded(evidence)
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | os.O_NOFOLLOW
    )
    descriptor = os.open(path, flags, 0o600)
    completed = False
    try:
        require(stat.S_ISREG(os.fstat(descriptor).st_mode),
                "banner observer output is not a regular file")
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        completed = True
    finally:
        os.close(descriptor)
        if not completed:
            path.unlink(missing_ok=True)


def observe(
    *, app_evidence: Any, token: str,
    observed_now: datetime, client: Any | None = None,
    threads_reader: Callable[[str, int], dict[str, Any]] | None = None,
    initial: Any = None,
) -> tuple[dict[str, Any], dict[str, str | int]]:
    require(type(app_evidence) is dict and set(app_evidence) == APP_KEYS,
            "banner observer App evidence input is not the exact closed shape")
    require(type(token) is str and token.strip() == token and bool(token)
            and not any(ch.isspace() for ch in token),
            "banner observer must receive an independently read-scoped GH_TOKEN")
    if client is None:
        client = rest.ReadOnlyGitHub(token)
    snapshot = collector.collect(
        native_app=app_evidence, observed_now=observed_now,
        client=client, token=token, threads_reader=threads_reader,
    )
    decision = admission.decide(snapshot)
    if initial is None:
        # A decision is NOT an authority credential: even a pass needs a
        # separate authenticated reviewer and fresh terminal collector.
        return snapshot, decision
    terminal_result = terminal.evaluate(initial, snapshot)
    return snapshot, terminal_result

def observe_native_wake(
    *, app_evidence: Any, token: str, event: Any,
    observed_now: datetime, client: Any | None = None,
    threads_reader: Callable[[str, int], dict[str, Any]] | None = None,
) -> tuple[dict[str, Any], dict[str, str | int]]:
    """Bind a native completed workflow wake to an independently observed PR.

    This is read-only evidence; neither a webhook nor its result grants a
    privileged approval, check publication, App token or protected merge.
    """
    snapshot, decision = observe(
        app_evidence=app_evidence, token=token,
        observed_now=observed_now, client=client,
        threads_reader=threads_reader,
    )
    require(
        decision.get("decision")
        == "exact-native-banner-owner-review-ready-read-only",
        "native banner event has no fully validated unreviewed candidate",
    )
    admitted = contract.verified_native_banner_review_wake(
        event=event, pr=snapshot["pr"], native_app=app_evidence,
        expected_main_sha=snapshot["mainSha"],
        observed_now=observed_now,
    )
    require(
        admitted["prNumber"] == decision["prNumber"]
        and admitted["baseSha"] == decision["baseSha"]
        and admitted["headSha"] == decision["headSha"]
        and admitted["headRef"] == snapshot["pr"]["head"]["ref"],
        "native wake and independently verified banner subject diverged",
    )
    return snapshot, {**admitted,
                      "decision": "exact-native-banner-wake-observed-no-write"}


def self_test() -> None:
    import copy
    import tempfile
    from automation_governed_bot_review_gate import review_marker

    initial_fixture = admission.fixture()
    initial_time = admission.exact_utc(initial_fixture["observedAt"])
    kwargs = {
        "app_evidence": initial_fixture["nativeApp"],
        "token": "fixture-read-token",
    }
    initial, first = observe(
        **kwargs, observed_now=initial_time,
        client=collector._FixtureClient(initial_fixture),
        threads_reader=lambda _repo, _pr: copy.deepcopy(
            initial_fixture["reviewThreads"],
        ),
    )
    require(first["decision"] == "exact-native-banner-owner-review-ready-read-only",
            "observer initial phase rejected valid native candidate")

    after_fixture = copy.deepcopy(initial_fixture)
    after_fixture["observedAt"] = (
        initial_time + timedelta(minutes=3)
    ).isoformat().replace("+00:00", "Z")
    head = first["headSha"]
    after_fixture["reviews"] = [{
        "id": 818, "user": {"login": "portyu9"},
        "commit_id": head, "state": "APPROVED",
        "body": review_marker(first["baseSha"], head),
    }]
    after_fixture["completeness"]["reviews"]["totalCount"] = 1
    after, second = observe(
        **kwargs, observed_now=initial_time + timedelta(minutes=3),
        client=collector._FixtureClient(after_fixture),
        threads_reader=lambda _repo, _pr: copy.deepcopy(
            after_fixture["reviewThreads"],
        ),
        initial=initial,
    )
    require(second["decision"] == "exact-two-phase-owner-reviewed-banner-data-only"
            and second["ownerReviewId"] == 818,
            "observer failed to bind one newly approved owner review")

    for label, mutate in (
        ("replayed clock", lambda x: x.update(
            observedAt=initial_fixture["observedAt"],
        )),
        ("different App", lambda x: x["nativeApp"].update(
            expected_app_id=987,
        )),
        ("changed head", lambda x: x["pr"]["head"].update(
            sha="c" * 40,
        )),
        ("missing owner approval", lambda x: x["reviews"].clear()),
        ("owner veto", lambda x: x["reviews"][0].update(
            state="CHANGES_REQUESTED",
        )),
    ):
        poisoned = copy.deepcopy(after)
        mutate(poisoned)
        try:
            terminal.evaluate(initial, poisoned)
        except (ValueError, TypeError, KeyError):
            continue
        raise AssertionError(f"unsafe banner observer transition accepted {label}")

    with tempfile.TemporaryDirectory(prefix="banner-observer-self-test-") as temp:
        root = Path(temp)
        first_path = root / "initial.json"
        second_path = root / "terminal.json"
        write_exclusive(first_path, initial)
        write_exclusive(second_path, after)
        require(read_bounded(first_path) == initial
                and read_bounded(second_path) == after,
                "observer bounded evidence roundtrip changed public native JSON")
        try:
            write_exclusive(first_path, after)
        except FileExistsError:
            pass
        else:
            raise AssertionError("banner observer overwrote existing native evidence")

        alias = root / "alias.json"
        alias.symlink_to(first_path)
        try:
            read_bounded(alias)
        except (OSError, ValueError):
            pass
        else:
            raise AssertionError("banner observer followed aliased evidence")
        try:
            write_exclusive(alias, after)
        except (OSError, ValueError):
            pass
        else:
            raise AssertionError("banner observer overwrote an evidence symlink")
        duplicate = root / "duplicate.json"
        duplicate.write_text('{"schemaVersion":1,"schemaVersion":2}', encoding="utf-8")
        try:
            read_bounded(duplicate)
        except ValueError:
            pass
        else:
            raise AssertionError("banner observer accepted duplicate JSON keys")
        oversized = root / "oversized.json"
        oversized.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
        try:
            read_bounded(oversized)
        except ValueError:
            pass
        else:
            raise AssertionError("banner observer accepted oversized evidence")


    # An actual workflow completion is a wake only, never approval authority.
    pr = initial["pr"]
    native = {
        "action": "completed", "repository": {"full_name": contract.REPOSITORY},
        "sender": {"login": "github-actions[bot]"},
        "workflow_run": {
            "id": 4821, "name": "Profile quality",
            "path": contract.EXPECTED_PROTECTED_WORKFLOWS["Profile quality"][0],
            "event": "pull_request", "status": "completed",
            "conclusion": "success", "head_sha": pr["head"]["sha"],
            "head_branch": pr["head"]["ref"],
            "repository": {"full_name": contract.REPOSITORY},
            "head_repository": {"full_name": contract.REPOSITORY},
            "run_attempt": 1, "check_suite_id": 4822,
            "created_at": (initial_time - timedelta(minutes=1)).isoformat(
                timespec="seconds",
            ).replace("+00:00", "Z"),
            "pull_requests": [{
                "number": pr["number"], "head": {"sha": pr["head"]["sha"]},
                "base": {"ref": "main"},
            }],
        },
    }
    def wake(event: Any, *, sample: Any = initial_fixture,
             clock: datetime = initial_time) -> tuple[Any, Any]:
        return observe_native_wake(
            **kwargs, event=event, observed_now=clock,
            client=collector._FixtureClient(sample),
            threads_reader=lambda _repo, _pr: copy.deepcopy(
                sample["reviewThreads"],
            ),
        )
    found, proof = wake(native)
    require(found == initial
            and proof["decision"] == "exact-native-banner-wake-observed-no-write"
            and proof["sourceRunId"] == 4821
            and proof["headSha"] == pr["head"]["sha"],
            "native banner wake failed its exact read-only binding")
    for label, mutate in (
        ("wrong head", lambda x: x["workflow_run"].update(head_sha="f" * 40)),
        ("wrong path", lambda x: x["workflow_run"].update(
            path=".github/workflows/unreviewed.yml")),
        ("replayed job", lambda x: x["workflow_run"].update(run_attempt=2)),
        ("failed job", lambda x: x["workflow_run"].update(
            conclusion="failure")),
        ("unrelated PR", lambda x: x["workflow_run"].update(
            pull_requests=[])),
        ("different repository", lambda x: x["repository"].update(
            full_name="outsider/fork")),
        ("wrong event", lambda x: x.update(action="requested")),
    ):
        bad = copy.deepcopy(native)
        mutate(bad)
        try:
            wake(bad)
        except (ValueError, TypeError, KeyError):
            pass
        else:
            raise AssertionError(f"unsafe native banner wake accepted: {label}")
    for label, sample, clock in (
        ("owner review already exists", after_fixture,
         initial_time + timedelta(minutes=3)),
        ("expired webhook", initial_fixture,
         initial_time + timedelta(hours=3)),
    ):
        try:
            wake(native, sample=sample, clock=clock)
        except (ValueError, TypeError, KeyError):
            pass
        else:
            raise AssertionError(f"unsafe banner wake state accepted: {label}")
    with tempfile.TemporaryDirectory(prefix="banner-native-wake-") as tmp:
        event_path = Path(tmp) / "event.json"
        write_exclusive(event_path, native)
        require(read_bounded(event_path) == native,
                "native event lost exact JSON when persisted")
        event_path.unlink()
        event_path.write_text('{"action":"completed","action":"requested"}')
        try:
            read_bounded(event_path)
        except ValueError:
            pass
        else:
            raise AssertionError("duplicate native webhook key was accepted")

    require(after["mainSha"] == initial["mainSha"],
            "observer positive fixture did not preserve original main lease")
    print(
        "banner observer CLI: read-only first/terminal collection, exact owner "
        "transition, veto and immutable bounded evidence negative controls PASS"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--app-evidence", type=Path)
    parser.add_argument("--snapshot-out", type=Path)
    parser.add_argument("--initial-snapshot", type=Path)
    parser.add_argument("--wake-event", type=Path)
    args = parser.parse_args()

    if args.self_test:
        require(args.app_evidence is None and args.snapshot_out is None
                and args.initial_snapshot is None
                and args.wake_event is None,
                "observer self-test must not consume external evidence")
        self_test()
        return 0
    require(args.app_evidence is not None and args.snapshot_out is not None,
            "observer requires one authenticated-App evidence file and a new snapshot path")
    require(args.initial_snapshot is None or args.wake_event is None,
            "native wake cannot be combined with a post-review snapshot")
    token = os.environ.get("GH_TOKEN")
    require(token is not None, "observer GH_TOKEN is missing")
    app = read_bounded(args.app_evidence)
    initial = (
        None if args.initial_snapshot is None
        else read_bounded(args.initial_snapshot)
    )
    now = datetime.now(timezone.utc).replace(microsecond=0)
    if args.wake_event is not None:
        snapshot, result = observe_native_wake(
            app_evidence=app, token=token, observed_now=now,
            event=read_bounded(args.wake_event),
        )
    else:
        snapshot, result = observe(
            app_evidence=app, token=token, observed_now=now, initial=initial,
        )
    write_exclusive(args.snapshot_out, snapshot)
    # Never print bearer token, raw App input, or unvalidated snapshot.
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
