#!/usr/bin/env python3
"""Synchronize Signal Field headline evidence with GitHub profile semantics.

This v2.9 finalization layer queries GitHub's default ContributionsCollection once per
stats refresh and treats that single collection as the authoritative source for both:
- the profile-visible past-year Contributions headline, and
- the exact period displayed next to that headline.

The layer also normalizes card-wide evidence/source wording after all visual passes:
- card metrics are identified as coming from GitHub GraphQL + REST APIs,
- the workflow is described as scheduled every five minutes (not guaranteed refresh),
- no private/restricted contribution subset is persisted or logged.

The 30-day ACTIVE/PEAK evidence window, activity geometry, daily raw counts, and
reviewed visual treatment remain unchanged. Current STREAK is synchronized
independently from GitHub account-history contribution calendars, scanning backward in
bounded GraphQL windows until the first inactive day or account-creation boundary.
That makes STREAK semantically unbounded by the 30-day presentation window.

Unexpected SVG or GitHub API structure fails closed. Token-bearing GraphQL transport is
pinned to the exact GitHub endpoint, rejects redirects, and keeps bearer authorization
out of redirect-copyable ordinary request headers.
"""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import sys
import time
from typing import Any, Callable
import urllib.error
import urllib.parse
import urllib.request

import automation_github_read

SYNC_ID = "signal-field-v2.9"
GRAPHQL_URL = "https://api.github.com/graphql"
GRAPHQL_ATTEMPTS = automation_github_read.ATTEMPTS
GRAPHQL_TIMEOUT_SECONDS = automation_github_read.TIMEOUT_SECONDS
GRAPHQL_MAX_RESPONSE_BYTES = automation_github_read.MAX_RESPONSE_BYTES
REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
DEFAULT_USERNAME = "portyu9"
STREAK_WINDOW_DAYS = 90
STREAK_SOURCE = "github-graphql-account-history"
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)

SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
HEADLINE = re.compile(
    r'(<text\b(?=[^>]*\bdata-metric-phosphor="contributions")[^>]*>)'
    r'([\d,]+)(</text>)',
    re.I,
)
ACCESSIBLE_TOTAL = re.compile(
    r'(<desc\b[^>]*>)([\d,]+)( contributions in the past year;)',
    re.I,
)
WIDE_PERIOD = re.compile(
    r'(<text x="610" y="35"[^>]*>)(\d{4}\.\d{2}\.\d{2} — \d{4}\.\d{2}\.\d{2})(</text>)',
    re.I,
)
COMPACT_FROM = re.compile(
    r'(<text x="22" y="53"[^>]*>)([A-Z]{3} \d{2}, \d{4})(</text>)',
    re.I,
)
COMPACT_TO = re.compile(
    r'(<text x="298" y="53"[^>]*>)([A-Z]{3} \d{2}, \d{4})(</text>)',
    re.I,
)
STREAK_TSPAN = re.compile(
    r'(<tspan\b(?=[^>]*\bdata-telemetry-phosphor="streak")[^>]*>)STREAK (\d+)(</tspan>)',
    re.I,
)
ACCESSIBLE_STREAK = re.compile(r"the current streak is \d+ days;", re.I)
ROOT_ACTIVITY_TO = re.compile(r'\bdata-activity-to="(\d{4}-\d{2}-\d{2})"')

WIDE_OLD_FOOTER = "SOURCE · GITHUB GRAPHQL · REFRESH · 5 MIN"
WIDE_NEW_FOOTER = "SOURCES · GITHUB GRAPHQL + REST · SCHEDULE · 5 MIN"
COMPACT_OLD_FOOTER = "30 UTC DAYS · GITHUB GRAPHQL · LEVELS 0–4 · 5 MIN"
COMPACT_NEW_FOOTER = "GITHUB API · GRAPHQL + REST · SCHEDULE · 5 MIN"
OLD_ACCESSIBLE_SCHEDULE = "Refresh cadence: every 5 minutes."
NEW_ACCESSIBLE_SCHEDULE = (
    "Headline metrics use GitHub GraphQL and REST APIs. Generation schedule: every 5 minutes; "
    "execution and README cache propagation are best-effort."
)

QUERY = """
query ProfileVisibleContributionTotal($login: String!) {
  user(login: $login) {
    contributionsCollection {
      startedAt
      endedAt
      contributionCalendar {
        totalContributions
      }
    }
  }
}
""".strip()

STREAK_QUERY = """
query CurrentContributionStreak($login: String!, $from: DateTime!, $to: DateTime!) {
  user(login: $login) {
    createdAt
    contributionsCollection(from: $from, to: $to) {
      contributionCalendar {
        weeks {
          contributionDays {
            date
            contributionCount
          }
        }
      }
    }
  }
}
""".strip()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def normalize_contribution_count(value: object) -> int:
    """Accept only the exact non-negative JSON integer shape used by GitHub."""
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError("contribution count must be a non-negative integer")
    return value


def format_count(value: int) -> str:
    return f"{normalize_contribution_count(value):,}"


def parse_github_datetime(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError(f"GitHub GraphQL {label} is missing")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"GitHub GraphQL {label} is not an ISO datetime: {value!r}") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"GitHub GraphQL {label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def validate_graphql_url(url: str) -> str:
    """Return the one exact token-bearing GitHub GraphQL endpoint or fail closed."""
    parsed = urllib.parse.urlsplit(url)
    require(parsed.scheme == "https", f"GitHub GraphQL URL must use https: {url}")
    require(parsed.netloc == "api.github.com", f"GitHub GraphQL origin changed: {url}")
    require(parsed.username is None and parsed.password is None, f"GitHub GraphQL URL must not contain userinfo: {url}")
    require(parsed.port is None, f"GitHub GraphQL URL must not contain a port override: {url}")
    require(parsed.path == "/graphql", f"GitHub GraphQL path changed: {url}")
    require(parsed.query == "", f"GitHub GraphQL URL must not contain a query string: {url}")
    require(parsed.fragment == "", f"GitHub GraphQL URL must not contain a fragment: {url}")
    return url


def open_no_redirect(request: urllib.request.Request, *, timeout: float) -> Any:
    return urllib.request.build_opener(automation_github_read.NoRedirect()).open(
        request,
        timeout=timeout,
    )
def graphql_request(
    token: str,
    payload: bytes,
    *,
    query_document: str = QUERY,
    user_agent: str = "portyu9-signal-field-profile-total-sync",
) -> urllib.request.Request:
    if not token:
        raise ValueError("GITHUB_TOKEN is required for GitHub GraphQL contribution sync")
    require(
        QUERY.lstrip().startswith("query ") and "mutation" not in QUERY.lower(),
        "profile contribution GraphQL document must remain query-only",
    )
    require(
        STREAK_QUERY.lstrip().startswith("query ") and "mutation" not in STREAK_QUERY.lower(),
        "current-streak GraphQL document must remain query-only",
    )
    require(
        query_document.lstrip().startswith("query ") and "mutation" not in query_document.lower(),
        "selected profile GraphQL document must remain query-only",
    )
    request = urllib.request.Request(
        validate_graphql_url(GRAPHQL_URL),
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": user_agent,
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )
    request.add_unredirected_header("Authorization", f"Bearer {token}")
    return request


def transport_self_test() -> None:
    require(validate_graphql_url(GRAPHQL_URL) == GRAPHQL_URL, "GraphQL transport self-test rejected canonical endpoint")
    for unsafe in (
        "http://api.github.com/graphql",
        "https://api.github.com.evil.example/graphql",
        "https://api.github.com:443/graphql",
        "https://user@api.github.com/graphql",
        "https://api.github.com/graphql?query=forbidden",
        "https://api.github.com/graphql#fragment",
        "https://api.github.com/repos/portyu9/portyu9",
    ):
        try:
            validate_graphql_url(unsafe)
        except ValueError:
            pass
        else:
            raise ValueError(f"GraphQL transport self-test accepted unsafe endpoint: {unsafe}")

    request = graphql_request("fixture-token", b"{}")
    streak_request = graphql_request(
        "fixture-token",
        b"{}",
        query_document=STREAK_QUERY,
        user_agent="portyu9-signal-field-current-streak-sync",
    )
    ordinary = {name.lower(): value for name, value in request.headers.items()}
    unredirected = {name.lower(): value for name, value in request.unredirected_hdrs.items()}
    require(unredirected.get("authorization") == "Bearer fixture-token",
            "GraphQL bearer token must be attached as an unredirected-only header")
    require("authorization" not in ordinary,
            "GraphQL bearer token must not be attached as a redirect-copyable ordinary header")
    streak_ordinary = {name.lower(): value for name, value in streak_request.headers.items()}
    streak_unredirected = {
        name.lower(): value for name, value in streak_request.unredirected_hdrs.items()
    }
    require(
        streak_unredirected.get("authorization") == "Bearer fixture-token"
        and "authorization" not in streak_ordinary,
        "current-streak GraphQL bearer transport must remain unredirected-only",
    )
    require(
        automation_github_read.NoRedirect().redirect_request(
            None, None, 302, "fixture", {}, "https://example.com"
        )
        is None,
        "GraphQL redirect handler must refuse every redirect request",
    )
    require(GRAPHQL_ATTEMPTS == automation_github_read.ATTEMPTS == 3,
            "profile GraphQL retry budget diverged from canonical policy")
    require(GRAPHQL_TIMEOUT_SECONDS == automation_github_read.TIMEOUT_SECONDS == 20,
            "profile GraphQL timeout diverged from canonical policy")
    require(GRAPHQL_MAX_RESPONSE_BYTES == automation_github_read.MAX_RESPONSE_BYTES == 8_000_000,
            "profile GraphQL response bound diverged from canonical policy")

    calls: list[urllib.request.Request] = []
    sleeps: list[float] = []
    sequence: list[Any] = [
        urllib.error.HTTPError(
            GRAPHQL_URL,
            403,
            "fixture",
            {"X-RateLimit-Remaining": "0", "Retry-After": "1"},
            None,
        ),
        urllib.error.HTTPError(GRAPHQL_URL, 503, "fixture", {}, None),
        _FixtureResponse(
            json.dumps(
                {
                    "data": {
                        "user": {
                            "contributionsCollection": {
                                "startedAt": "2025-09-05T00:00:00Z",
                                "endedAt": "2026-09-04T00:00:00Z",
                                "contributionCalendar": {"totalContributions": 5030},
                            }
                        }
                    }
                },
                separators=(",", ":"),
            ).encode("utf-8")
        ),
    ]

    def fixture_open(request: urllib.request.Request, *, timeout: int) -> Any:
        require(request.get_method() == "POST",
                "profile GraphQL retry fixture observed non-POST transport")
        require(request.full_url == GRAPHQL_URL,
                "profile GraphQL retry fixture endpoint changed")
        require(timeout == GRAPHQL_TIMEOUT_SECONDS,
                "profile GraphQL retry fixture timeout changed")
        require(request.data is not None,
                "profile GraphQL retry fixture lost request payload")
        decoded = automation_github_read.strict_json(bytes(request.data).decode("utf-8"))
        require(decoded == {"query": QUERY, "variables": {"login": "portyu9"}},
                "profile GraphQL retry fixture payload changed")
        calls.append(request)
        outcome = sequence.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    observed = fetch_profile_visible_total(
        "fixture-token",
        "portyu9",
        opener=fixture_open,
        sleeper=sleeps.append,
    )
    require(observed == (5030, "2025-09-05", "2026-09-04"),
            "profile GraphQL retry fixture changed typed evidence")
    require(len(calls) == 3 and len({id(request) for request in calls}) == 3,
            "each profile GraphQL retry must construct one fresh request")
    require(calls[0].data == calls[1].data == calls[2].data,
            "profile GraphQL retry changed the fixed read-only query payload")
    require(sleeps == [1.0, 2.0],
            "profile GraphQL deterministic retry backoff changed")

    terminal_calls = 0

    def terminal_open(request: urllib.request.Request, *, timeout: int) -> Any:
        nonlocal terminal_calls
        terminal_calls += 1
        raise urllib.error.HTTPError(request.full_url, 401, "fixture", {}, None)

    try:
        fetch_profile_visible_total(
            "fixture-token",
            "portyu9",
            opener=terminal_open,
            sleeper=lambda _: None,
        )
    except ValueError as exc:
        require("HTTP 401" in str(exc),
                "profile GraphQL terminal authorization fixture failed for wrong reason")
    else:
        raise ValueError("profile GraphQL reader retried or accepted HTTP 401")
    require(terminal_calls == 1,
            "profile GraphQL authorization failure must remain terminal")


class _FixtureHeaders(dict[str, str]):
    def get_content_type(self) -> str:
        return "application/json"


class _FixtureResponse:
    def __init__(self, body: bytes) -> None:
        self.status = 200
        self._body = body
        self.headers = _FixtureHeaders()

    def __enter__(self) -> "_FixtureResponse":
        return self

    def __exit__(self, *args: Any) -> None:
        return None

    def geturl(self) -> str:
        return GRAPHQL_URL

    def read(self, _limit: int) -> bytes:
        return self._body


def fetch_profile_visible_total(
    token: str,
    username: str,
    *,
    opener: Callable[..., Any] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> tuple[int, str, str]:
    payload = json.dumps(
        {"query": QUERY, "variables": {"login": username}},
        separators=(",", ":"),
    ).encode("utf-8")
    transport = opener or open_no_redirect

    for attempt in range(GRAPHQL_ATTEMPTS):
        request = graphql_request(token, payload)
        try:
            with transport(request, timeout=GRAPHQL_TIMEOUT_SECONDS) as response:
                require(response.status == 200,
                        f"GitHub GraphQL query returned unexpected HTTP {response.status}")
                require(response.geturl() == GRAPHQL_URL,
                        "GitHub GraphQL query was redirected")
                raw = response.read(GRAPHQL_MAX_RESPONSE_BYTES + 1)
                require(
                    len(raw) <= GRAPHQL_MAX_RESPONSE_BYTES,
                    "GitHub GraphQL response exceeds size bound",
                )
                require(
                    response.headers.get_content_type() == "application/json",
                    "GitHub GraphQL response content type is not application/json",
                )
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(f"GitHub GraphQL response is not UTF-8: {exc}") from exc
            data = automation_github_read.strict_json(text)
            if not isinstance(data, dict):
                raise ValueError("GitHub GraphQL response must be an object")
            if data.get("errors"):
                raise ValueError(f"GitHub GraphQL returned errors: {data['errors']}")
            root = data.get("data")
            if not isinstance(root, dict):
                raise ValueError("GitHub GraphQL data object is missing")
            user = root.get("user")
            if not isinstance(user, dict) or not user:
                raise ValueError(f"GitHub user not found: {username}")
            collection = user.get("contributionsCollection")
            if not isinstance(collection, dict):
                raise ValueError("GitHub contributionsCollection is missing")
            calendar = collection.get("contributionCalendar")
            if not isinstance(calendar, dict):
                raise ValueError("GitHub contributionCalendar is missing")
            calendar_total = normalize_contribution_count(calendar.get("totalContributions"))

            started = parse_github_datetime(collection.get("startedAt"), "startedAt")
            ended = parse_github_datetime(collection.get("endedAt"), "endedAt")
            if started >= ended:
                raise ValueError("GitHub contribution collection period is not increasing")
            return calendar_total, started.date().isoformat(), ended.date().isoformat()
        except urllib.error.HTTPError as exc:
            if exc.code in REDIRECT_STATUS:
                raise ValueError(f"GitHub GraphQL redirect rejected with HTTP {exc.code}") from exc
            if (
                attempt + 1 >= GRAPHQL_ATTEMPTS
                or not automation_github_read.retryable_http_error(exc)
            ):
                raise ValueError(f"GitHub GraphQL query returned HTTP {exc.code}") from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                f"RETRY: profile contribution GraphQL query transient HTTP {exc.code}; "
                f"attempt {attempt + 1}/{GRAPHQL_ATTEMPTS}, sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)
        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
            if attempt + 1 >= GRAPHQL_ATTEMPTS:
                raise ValueError(
                    f"GitHub GraphQL query exhausted transient transport retry budget: {exc}"
                ) from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                "RETRY: profile contribution GraphQL query transient transport failure; "
                f"attempt {attempt + 1}/{GRAPHQL_ATTEMPTS}, sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)

    raise ValueError("unreachable profile contribution GraphQL retry state")


def _parse_streak_window(
    payload: Any,
    *,
    username: str,
    window_from: date,
    window_to: date,
) -> tuple[date, list[tuple[date, int]]]:
    require(isinstance(payload, dict), "current-streak GraphQL response must be an object")
    if payload.get("errors"):
        raise ValueError(f"current-streak GraphQL returned errors: {payload['errors']}")
    root = payload.get("data")
    require(isinstance(root, dict), "current-streak GraphQL data object is missing")
    user = root.get("user")
    require(isinstance(user, dict) and user, f"GitHub user not found: {username}")
    created_at = parse_github_datetime(user.get("createdAt"), "createdAt").date()
    collection = user.get("contributionsCollection")
    require(isinstance(collection, dict), "current-streak contributionsCollection is missing")
    calendar = collection.get("contributionCalendar")
    require(isinstance(calendar, dict), "current-streak contributionCalendar is missing")
    weeks = calendar.get("weeks")
    require(isinstance(weeks, list), "current-streak contribution weeks are missing")

    observed: dict[date, int] = {}
    for week in weeks:
        require(isinstance(week, dict), "current-streak contribution week is malformed")
        contribution_days = week.get("contributionDays")
        require(
            isinstance(contribution_days, list),
            "current-streak contributionDays are malformed",
        )
        for entry in contribution_days:
            require(isinstance(entry, dict), "current-streak contribution day is malformed")
            raw_day = entry.get("date")
            require(isinstance(raw_day, str), "current-streak contribution date is missing")
            try:
                day = date.fromisoformat(raw_day)
            except ValueError as exc:
                raise ValueError(
                    f"current-streak contribution date is malformed: {raw_day!r}"
                ) from exc
            count = normalize_contribution_count(entry.get("contributionCount"))
            effective_from = max(window_from, created_at)
            if effective_from <= day <= window_to:
                require(day not in observed, f"current-streak contribution date duplicated: {day}")
                observed[day] = count

    expected_days: list[date] = []
    cursor = max(window_from, created_at)
    while cursor <= window_to:
        expected_days.append(cursor)
        cursor += timedelta(days=1)
    require(
        sorted(observed) == expected_days,
        "current-streak GraphQL window must contain one exact contribution count per UTC day "
        "from the account-creation boundary through the requested end date",
    )
    return created_at, [(day, observed[day]) for day in expected_days]


def _fetch_streak_window(
    token: str,
    username: str,
    window_from: date,
    window_to: date,
    *,
    opener: Callable[..., Any] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> tuple[date, list[tuple[date, int]]]:
    require(window_from <= window_to, "current-streak GraphQL window is reversed")
    variables = {
        "login": username,
        "from": f"{window_from.isoformat()}T00:00:00Z",
        "to": f"{window_to.isoformat()}T23:59:59Z",
    }
    payload = json.dumps(
        {"query": STREAK_QUERY, "variables": variables},
        separators=(",", ":"),
    ).encode("utf-8")
    transport = opener or open_no_redirect

    for attempt in range(GRAPHQL_ATTEMPTS):
        request = graphql_request(
            token,
            payload,
            query_document=STREAK_QUERY,
            user_agent="portyu9-signal-field-current-streak-sync",
        )
        try:
            with transport(request, timeout=GRAPHQL_TIMEOUT_SECONDS) as response:
                require(
                    response.status == 200,
                    f"current-streak GitHub GraphQL query returned unexpected HTTP {response.status}",
                )
                require(
                    response.geturl() == GRAPHQL_URL,
                    "current-streak GitHub GraphQL query was redirected",
                )
                raw = response.read(GRAPHQL_MAX_RESPONSE_BYTES + 1)
                require(
                    len(raw) <= GRAPHQL_MAX_RESPONSE_BYTES,
                    "current-streak GitHub GraphQL response exceeds size bound",
                )
                require(
                    response.headers.get_content_type() == "application/json",
                    "current-streak GitHub GraphQL response content type is not application/json",
                )
            try:
                decoded = raw.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise ValueError(
                    f"current-streak GitHub GraphQL response is not UTF-8: {exc}"
                ) from exc
            return _parse_streak_window(
                automation_github_read.strict_json(decoded),
                username=username,
                window_from=window_from,
                window_to=window_to,
            )
        except urllib.error.HTTPError as exc:
            if exc.code in REDIRECT_STATUS:
                raise ValueError(
                    f"current-streak GitHub GraphQL redirect rejected with HTTP {exc.code}"
                ) from exc
            if (
                attempt + 1 >= GRAPHQL_ATTEMPTS
                or not automation_github_read.retryable_http_error(exc)
            ):
                raise ValueError(
                    f"current-streak GitHub GraphQL query returned HTTP {exc.code}"
                ) from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                f"RETRY: current-streak GraphQL query transient HTTP {exc.code}; "
                f"attempt {attempt + 1}/{GRAPHQL_ATTEMPTS}, sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)
        except (urllib.error.URLError, TimeoutError, ConnectionResetError) as exc:
            if attempt + 1 >= GRAPHQL_ATTEMPTS:
                raise ValueError(
                    "current-streak GitHub GraphQL query exhausted transient transport "
                    f"retry budget: {exc}"
                ) from exc
            delay = automation_github_read.retry_delay_seconds(exc, attempt)
            print(
                "RETRY: current-streak GraphQL query transient transport failure; "
                f"attempt {attempt + 1}/{GRAPHQL_ATTEMPTS}, sleeping {delay:g}s",
                file=sys.stderr,
            )
            sleeper(delay)

    raise ValueError("unreachable current-streak GitHub GraphQL retry state")


def fetch_current_streak(
    token: str,
    username: str,
    activity_to: str,
    *,
    opener: Callable[..., Any] | None = None,
    sleeper: Callable[[float], None] = time.sleep,
) -> int:
    try:
        anchor = date.fromisoformat(activity_to)
    except ValueError as exc:
        raise ValueError(f"Signal Field activity-to date is malformed: {activity_to!r}") from exc

    cursor_to = anchor
    created_at: date | None = None
    streak = 0
    while True:
        cursor_from = cursor_to - timedelta(days=STREAK_WINDOW_DAYS - 1)
        window_created_at, days = _fetch_streak_window(
            token,
            username,
            cursor_from,
            cursor_to,
            opener=opener,
            sleeper=sleeper,
        )
        if created_at is None:
            created_at = window_created_at
            require(
                created_at <= anchor,
                "GitHub account creation date is after Signal Field activity-to date",
            )
        else:
            require(
                window_created_at == created_at,
                "GitHub account creation date changed across current-streak windows",
            )

        for day, count in reversed(days):
            if day < created_at:
                return streak
            if count == 0:
                return streak
            streak += 1

        if cursor_from <= created_at:
            return streak
        cursor_to = cursor_from - timedelta(days=1)


def activity_to_date(text: str) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root element is missing")
    matches = ROOT_ACTIVITY_TO.findall(root.group(0))
    require(len(matches) == 1, "Signal Field SVG must declare exactly one data-activity-to")
    try:
        return date.fromisoformat(matches[0]).isoformat()
    except ValueError as exc:
        raise ValueError("Signal Field data-activity-to is malformed") from exc


def set_attr(element: str, name: str, value: str) -> str:
    pattern = re.compile(rf'\b{re.escape(name)}="[^"]*"')
    replacement = f'{name}="{value}"'
    if pattern.search(element):
        return pattern.sub(replacement, element, count=1)
    close = element.rfind(">")
    if close < 0:
        raise ValueError(f"cannot add attribute {name!r} to malformed SVG root")
    return element[:close] + f' {replacement}' + element[close:]


def remove_attr(element: str, name: str) -> str:
    return re.sub(rf'\s+{re.escape(name)}="[^"]*"', "", element, count=1)


def add_provenance(
    text: str,
    calendar_total: int,
    period_from: str,
    period_to: str,
    current_streak: int,
    streak_through: str,
) -> str:
    match = SVG_OPEN.search(text)
    if not match:
        raise ValueError("SVG root element is missing")
    root = match.group(0)
    root = remove_attr(root, "data-restricted-contributions")
    root = remove_attr(root, "data-refresh-cadence")
    for name, value in (
        ("data-contribution-total-sync", SYNC_ID),
        ("data-contribution-total-source", "github-default-contribution-calendar"),
        ("data-calendar-contributions", str(calendar_total)),
        ("data-profile-visible-contributions", str(calendar_total)),
        ("data-profile-period-from", period_from),
        ("data-profile-period-to", period_to),
        ("data-current-streak", str(current_streak)),
        ("data-current-streak-source", STREAK_SOURCE),
        ("data-current-streak-through", streak_through),
        ("data-metric-sources", "github-graphql+rest"),
        ("data-generation-schedule", "5-minutes"),
    ):
        root = set_attr(root, name, value)
    return text[: match.start()] + root + text[match.end() :]


def replace_single(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise ValueError(f"expected exactly one {label} before v2.9 finalization")
    return text.replace(old, new, 1)


def sync_period_labels(text: str, filename: str, period_from: str, period_to: str) -> str:
    start = datetime.fromisoformat(period_from)
    end = datetime.fromisoformat(period_to)
    if "wide" in filename:
        label = f"{start:%Y.%m.%d} — {end:%Y.%m.%d}"
        matches = WIDE_PERIOD.findall(text)
        if len(matches) != 1:
            raise ValueError("expected exactly one wide profile-period label")
        return WIDE_PERIOD.sub(rf"\g<1>{label}\g<3>", text, count=1)

    start_label = start.strftime("%b %d, %Y").upper()
    end_label = end.strftime("%b %d, %Y").upper()
    if len(COMPACT_FROM.findall(text)) != 1 or len(COMPACT_TO.findall(text)) != 1:
        raise ValueError("expected one compact profile-period start and end label")
    text = COMPACT_FROM.sub(rf"\g<1>{start_label}\g<3>", text, count=1)
    return COMPACT_TO.sub(rf"\g<1>{end_label}\g<3>", text, count=1)


def sync_svg(
    text: str,
    filename: str,
    calendar_total: int,
    period_from: str,
    period_to: str,
    current_streak: int,
    streak_through: str,
) -> str:
    headline_matches = HEADLINE.findall(text)
    if len(headline_matches) != 1:
        raise ValueError(
            f"expected exactly one phosphorescent Contributions headline, found {len(headline_matches)}"
        )
    accessible_matches = ACCESSIBLE_TOTAL.findall(text)
    if len(accessible_matches) != 1:
        raise ValueError(
            f"expected exactly one accessible past-year contribution total, found {len(accessible_matches)}"
        )

    formatted = format_count(calendar_total)
    text = HEADLINE.sub(rf"\g<1>{formatted}\g<3>", text, count=1)
    text = ACCESSIBLE_TOTAL.sub(rf"\g<1>{formatted}\g<3>", text, count=1)
    text = sync_period_labels(text, filename, period_from, period_to)

    streak_matches = STREAK_TSPAN.findall(text)
    if len(streak_matches) != 1:
        raise ValueError(
            f"expected exactly one phosphorescent STREAK telemetry span, found {len(streak_matches)}"
        )
    text = STREAK_TSPAN.sub(
        lambda match: f"{match.group(1)}STREAK {current_streak}{match.group(3)}",
        text,
        count=1,
    )
    accessible_streak_matches = ACCESSIBLE_STREAK.findall(text)
    if len(accessible_streak_matches) != 1:
        raise ValueError(
            "expected exactly one pre-sync accessible current-streak statement"
        )
    text = ACCESSIBLE_STREAK.sub(
        f"the account-history current streak is {current_streak} days;",
        text,
        count=1,
    )

    if "wide" in filename:
        text = replace_single(text, WIDE_OLD_FOOTER, WIDE_NEW_FOOTER, "wide source/schedule footer")
    else:
        text = replace_single(
            text,
            COMPACT_OLD_FOOTER,
            COMPACT_NEW_FOOTER,
            "compact source/schedule footer",
        )

    text = replace_single(
        text,
        OLD_ACCESSIBLE_SCHEDULE,
        NEW_ACCESSIBLE_SCHEDULE,
        "accessible refresh description",
    )
    text = add_provenance(
        text,
        calendar_total,
        period_from,
        period_to,
        current_streak,
        streak_through,
    )
    validate(
        text,
        filename,
        calendar_total,
        period_from,
        period_to,
        current_streak,
        streak_through,
    )
    return text


def validate(
    text: str,
    filename: str,
    calendar_total: int,
    period_from: str,
    period_to: str,
    current_streak: int,
    streak_through: str,
) -> None:
    formatted = format_count(calendar_total)
    required_root_attrs = (
        f'data-contribution-total-sync="{SYNC_ID}"',
        'data-contribution-total-source="github-default-contribution-calendar"',
        f'data-calendar-contributions="{calendar_total}"',
        f'data-profile-visible-contributions="{calendar_total}"',
        f'data-profile-period-from="{period_from}"',
        f'data-profile-period-to="{period_to}"',
        f'data-current-streak="{current_streak}"',
        f'data-current-streak-source="{STREAK_SOURCE}"',
        f'data-current-streak-through="{streak_through}"',
        'data-metric-sources="github-graphql+rest"',
        'data-generation-schedule="5-minutes"',
    )
    for attr in required_root_attrs:
        if text.count(attr) != 1:
            raise ValueError(f"profile evidence provenance is missing or duplicated: {attr}")

    if "data-restricted-contributions=" in text:
        raise ValueError("restricted/private contribution aggregate must not be published")
    if "data-refresh-cadence=" in text:
        raise ValueError("final SVG must describe the generation schedule, not guaranteed refresh cadence")

    headline_matches = HEADLINE.findall(text)
    if len(headline_matches) != 1 or headline_matches[0][1] != formatted:
        raise ValueError("visible Contributions headline does not match GitHub contribution calendar total")
    accessible_matches = ACCESSIBLE_TOTAL.findall(text)
    if len(accessible_matches) != 1 or accessible_matches[0][1] != formatted:
        raise ValueError("accessible contribution description does not match GitHub contribution calendar total")

    if NEW_ACCESSIBLE_SCHEDULE not in text or OLD_ACCESSIBLE_SCHEDULE in text:
        raise ValueError("accessible source/schedule semantics are not final")
    final_streak = STREAK_TSPAN.findall(text)
    if len(final_streak) != 1 or int(final_streak[0][1]) != current_streak:
        raise ValueError("visible STREAK telemetry does not match account-history evidence")
    expected_accessible_streak = (
        f"the account-history current streak is {current_streak} days;"
    )
    if text.count(expected_accessible_streak) != 1:
        raise ValueError("accessible current-streak evidence is not synchronized")
    expected_footer = WIDE_NEW_FOOTER if "wide" in filename else COMPACT_NEW_FOOTER
    if text.count(expected_footer) != 1:
        raise ValueError("final source/schedule footer is missing")

    start = datetime.fromisoformat(period_from)
    end = datetime.fromisoformat(period_to)
    if "wide" in filename:
        expected = f"{start:%Y.%m.%d} — {end:%Y.%m.%d}"
    else:
        expected = f"{start:%b %d, %Y}".upper()
        expected_end = f"{end:%b %d, %Y}".upper()
        if expected_end not in text:
            raise ValueError("compact profile-period end label does not match GitHub collection")
    if expected not in text:
        raise ValueError("profile-period label does not match GitHub collection")


def apply_directory(directory: Path, token: str, username: str) -> None:
    source_text: dict[str, str] = {}
    activity_to_values: set[str] = set()
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        text = path.read_text(encoding="utf-8")
        source_text[filename] = text
        activity_to_values.add(activity_to_date(text))
    require(
        len(activity_to_values) == 1,
        "all responsive/theme Signal Field variants must share one activity-to date",
    )
    streak_through = next(iter(activity_to_values))

    calendar_total, period_from, period_to = fetch_profile_visible_total(token, username)
    current_streak = fetch_current_streak(token, username, streak_through)
    print(
        "GitHub profile contribution evidence: "
        f"total={calendar_total:,}; period={period_from}..{period_to}; "
        f"current_streak={current_streak}; streak_through={streak_through}"
    )
    for filename in EXPECTED_FILES:
        path = directory / filename
        synced = sync_svg(
            source_text[filename],
            filename,
            calendar_total,
            period_from,
            period_to,
            current_streak,
            streak_through,
        )
        path.write_text(synced, encoding="utf-8")
        print(
            f"profile contribution evidence synchronized {filename} -> "
            f"{calendar_total:,}; streak={current_streak}"
        )


def fixture(filename: str) -> str:
    if "wide" in filename:
        period = (
            '<text x="610" y="35" text-anchor="end">2025.09.04 — 2026.09.03</text>'
            f'<text>{WIDE_OLD_FOOTER}</text>'
        )
    else:
        period = (
            '<text x="22" y="53">SEP 04, 2025</text>'
            '<text x="298" y="53" text-anchor="end">SEP 03, 2026</text>'
            f'<text>{COMPACT_OLD_FOOTER}</text>'
        )
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" data-refresh-cadence="5-minutes" '
        'data-restricted-contributions="156" data-activity-to="2026-09-03" '
        'data-current-streak="16">'
        '<desc id="desc">4,874 contributions in the past year; 12 stars. '
        f'The current streak is 16 days; {OLD_ACCESSIBLE_SCHEDULE}</desc>'
        f'{period}'
        '<text x="30" y="109" fill="#00FBCC" data-metric-phosphor="contributions">'
        '4,874</text>'
        '<text data-activity-summary="true"><tspan data-telemetry-phosphor="streak">'
        'STREAK 16</tspan></text></svg>'
    )


def self_test() -> None:
    transport_self_test()
    require(normalize_contribution_count(0) == 0, "contribution-count self-test rejected zero")
    require(normalize_contribution_count(5_030) == 5_030, "contribution-count self-test rejected a positive integer")
    for invalid_count in (True, False, -1, 1.0, "1", None):
        try:
            normalize_contribution_count(invalid_count)
        except ValueError:
            pass
        else:
            raise ValueError(f"contribution-count self-test accepted invalid JSON primitive: {invalid_count!r}")

    def streak_fixture_open(streak_days: int, *, created: date = date(2020, 1, 1)):
        calls: list[tuple[date, date]] = []
        inactive = date(2026, 9, 4) - timedelta(days=streak_days)

        def opener(request: urllib.request.Request, *, timeout: int) -> Any:
            require(timeout == GRAPHQL_TIMEOUT_SECONDS, "streak fixture timeout changed")
            require(request.data is not None, "streak fixture request lost payload")
            payload = automation_github_read.strict_json(bytes(request.data).decode("utf-8"))
            require(payload.get("query") == STREAK_QUERY, "streak fixture query authority changed")
            variables = payload.get("variables")
            require(isinstance(variables, dict), "streak fixture variables are missing")
            window_from = datetime.fromisoformat(
                str(variables["from"]).replace("Z", "+00:00")
            ).date()
            window_to = datetime.fromisoformat(
                str(variables["to"]).replace("Z", "+00:00")
            ).date()
            calls.append((window_from, window_to))
            days = []
            cursor = window_from
            while cursor <= window_to:
                count = 1 if cursor > inactive and cursor >= created else 0
                days.append(
                    {
                        "date": cursor.isoformat(),
                        "contributionCount": count,
                    }
                )
                cursor += timedelta(days=1)
            response = {
                "data": {
                    "user": {
                        "createdAt": f"{created.isoformat()}T00:00:00Z",
                        "contributionsCollection": {
                            "contributionCalendar": {
                                "weeks": [{"contributionDays": days}]
                            }
                        },
                    }
                }
            }
            return _FixtureResponse(
                json.dumps(response, separators=(",", ":")).encode("utf-8")
            )

        return opener, calls

    for expected_streak in (0, 47, 130, 420):
        opener, calls = streak_fixture_open(expected_streak)
        observed_streak = fetch_current_streak(
            "fixture-token",
            "portyu9",
            "2026-09-04",
            opener=opener,
            sleeper=lambda _: None,
        )
        require(
            observed_streak == expected_streak,
            f"unbounded current-streak self-test expected {expected_streak}, got {observed_streak}",
        )
        if expected_streak > STREAK_WINDOW_DAYS:
            require(
                len(calls) >= 2,
                "current-streak self-test did not traverse multiple bounded GraphQL windows",
            )

    created = date(2026, 8, 1)
    opener, _ = streak_fixture_open(10_000, created=created)
    lifetime_streak = fetch_current_streak(
        "fixture-token",
        "portyu9",
        "2026-09-04",
        opener=opener,
        sleeper=lambda _: None,
    )
    require(
        lifetime_streak == (date(2026, 9, 4) - created).days + 1,
        "current-streak account-creation boundary self-test changed",
    )

    calendar_total = 5_030
    period_from = "2025-09-05"
    period_to = "2026-09-04"
    current_streak = 47
    streak_through = "2026-09-03"
    for filename in EXPECTED_FILES:
        synced = sync_svg(
            fixture(filename),
            filename,
            calendar_total,
            period_from,
            period_to,
            current_streak,
            streak_through,
        )
        validate(
            synced,
            filename,
            calendar_total,
            period_from,
            period_to,
            current_streak,
            streak_through,
        )
        assert ">5,030</text>" in synced
        assert "5,030 contributions in the past year;" in synced
        assert 'data-calendar-contributions="5030"' in synced
        assert 'data-profile-visible-contributions="5030"' in synced
        assert 'data-profile-period-from="2025-09-05"' in synced
        assert 'data-profile-period-to="2026-09-04"' in synced
        assert 'data-current-streak="47"' in synced
        assert f'data-current-streak-source="{STREAK_SOURCE}"' in synced
        assert 'data-current-streak-through="2026-09-03"' in synced
        assert "STREAK 47" in synced
        assert "account-history current streak is 47 days" in synced
        assert "data-restricted-contributions=" not in synced
        assert "data-refresh-cadence=" not in synced
    print(
        f"Signal Field profile evidence self-test passed: {SYNC_ID}; "
        "one GitHub collection drives total + displayed period; current streak traverses bounded GraphQL windows "
        "without a 30-day/annual cap and stops only at the first inactive day or account creation; exact non-negative "
        "integer typing is enforced; no restricted aggregate is published; GraphQL bearer transport is exact-endpoint "
        "and no-redirect"
    )


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError(
                "usage: sync-profile-contribution-total.py <generated-directory> | --self-test"
            )
        token = os.environ.get("GITHUB_TOKEN", "")
        username = os.environ.get("GITHUB_USERNAME", DEFAULT_USERNAME)
        apply_directory(Path(sys.argv[1]), token, username)
        return 0
    except (OSError, ValueError, AssertionError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
