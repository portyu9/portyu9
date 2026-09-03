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

All 30-day activity geometry, daily raw counts, and reviewed visual treatment remain
unchanged. Unexpected SVG or GitHub API structure fails closed.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

SYNC_ID = "signal-field-v2.9"
GRAPHQL_URL = "https://api.github.com/graphql"
DEFAULT_USERNAME = "portyu9"
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


def format_count(value: int) -> str:
    if value < 0:
        raise ValueError("contribution counts cannot be negative")
    return f"{value:,}"


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


def fetch_profile_visible_total(token: str, username: str) -> tuple[int, str, str]:
    if not token:
        raise ValueError("GITHUB_TOKEN is required for GitHub GraphQL contribution sync")
    payload = json.dumps(
        {"query": QUERY, "variables": {"login": username}},
        separators=(",", ":"),
    ).encode("utf-8")
    request = Request(
        GRAPHQL_URL,
        data=payload,
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "portyu9-signal-field-profile-total-sync",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )
    try:
        with urlopen(request, timeout=20) as response:
            data = json.load(response)
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise ValueError(f"GitHub GraphQL request failed with HTTP {exc.code}: {detail}") from exc
    except URLError as exc:
        raise ValueError(f"GitHub GraphQL request failed: {exc.reason}") from exc

    if data.get("errors"):
        raise ValueError(f"GitHub GraphQL returned errors: {data['errors']}")
    user = data.get("data", {}).get("user")
    if not user:
        raise ValueError(f"GitHub user not found: {username}")
    collection = user.get("contributionsCollection") or {}
    calendar = collection.get("contributionCalendar") or {}
    calendar_total = calendar.get("totalContributions")
    if not isinstance(calendar_total, int) or calendar_total < 0:
        raise ValueError("GitHub GraphQL contribution total is missing or invalid")

    started = parse_github_datetime(collection.get("startedAt"), "startedAt")
    ended = parse_github_datetime(collection.get("endedAt"), "endedAt")
    if started >= ended:
        raise ValueError("GitHub contribution collection period is not increasing")
    return calendar_total, started.date().isoformat(), ended.date().isoformat()


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


def add_provenance(text: str, calendar_total: int, period_from: str, period_to: str) -> str:
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
    text = add_provenance(text, calendar_total, period_from, period_to)
    validate(text, filename, calendar_total, period_from, period_to)
    return text


def validate(
    text: str,
    filename: str,
    calendar_total: int,
    period_from: str,
    period_to: str,
) -> None:
    formatted = format_count(calendar_total)
    required_root_attrs = (
        f'data-contribution-total-sync="{SYNC_ID}"',
        'data-contribution-total-source="github-default-contribution-calendar"',
        f'data-calendar-contributions="{calendar_total}"',
        f'data-profile-visible-contributions="{calendar_total}"',
        f'data-profile-period-from="{period_from}"',
        f'data-profile-period-to="{period_to}"',
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
    calendar_total, period_from, period_to = fetch_profile_visible_total(token, username)
    print(
        "GitHub profile contribution evidence: "
        f"total={calendar_total:,}; period={period_from}..{period_to}"
    )
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        synced = sync_svg(
            path.read_text(encoding="utf-8"),
            filename,
            calendar_total,
            period_from,
            period_to,
        )
        path.write_text(synced, encoding="utf-8")
        print(f"profile contribution evidence synchronized {filename} -> {calendar_total:,}")


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
        'data-restricted-contributions="156">'
        '<desc id="desc">4,874 contributions in the past year; 12 stars. '
        f'{OLD_ACCESSIBLE_SCHEDULE}</desc>'
        f'{period}'
        '<text x="30" y="109" fill="#00FBCC" data-metric-phosphor="contributions">'
        '4,874</text></svg>'
    )


def self_test() -> None:
    calendar_total = 5_030
    period_from = "2025-09-05"
    period_to = "2026-09-04"
    for filename in EXPECTED_FILES:
        synced = sync_svg(
            fixture(filename),
            filename,
            calendar_total,
            period_from,
            period_to,
        )
        validate(synced, filename, calendar_total, period_from, period_to)
        assert ">5,030</text>" in synced
        assert "5,030 contributions in the past year;" in synced
        assert 'data-calendar-contributions="5030"' in synced
        assert 'data-profile-visible-contributions="5030"' in synced
        assert 'data-profile-period-from="2025-09-05"' in synced
        assert 'data-profile-period-to="2026-09-04"' in synced
        assert "data-restricted-contributions=" not in synced
        assert "data-refresh-cadence=" not in synced
    print(
        f"Signal Field profile evidence self-test passed: {SYNC_ID}; "
        "one GitHub collection drives total + displayed period; no restricted aggregate is published"
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
