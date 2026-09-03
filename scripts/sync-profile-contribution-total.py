#!/usr/bin/env python3
"""Sync Signal Field's past-year contribution headline with GitHub profile semantics.

GitHub's ContributionCalendar.totalContributions is the profile-visible contribution
total for the queried user/time span. ContributionsCollection.restrictedContributionsCount
is an informational subset of that calendar total when private/restricted contribution
visibility is enabled; it must not be added again.

This v2.9 post-processing layer queries those canonical GitHub values on every stats
refresh and rewrites only the past-year headline plus its accessible description.
All activity-calendar geometry, raw daily evidence, and other metrics remain intact.
"""

from __future__ import annotations

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

QUERY = """
query ProfileVisibleContributionTotal($login: String!) {
  user(login: $login) {
    contributionsCollection {
      restrictedContributionsCount
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


def fetch_profile_visible_total(token: str, username: str) -> tuple[int, int]:
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
    restricted_total = collection.get("restrictedContributionsCount")
    if not isinstance(calendar_total, int) or not isinstance(restricted_total, int):
        raise ValueError("GitHub GraphQL contribution totals are missing or non-integer")
    if calendar_total < 0 or restricted_total < 0:
        raise ValueError("GitHub GraphQL returned a negative contribution count")
    if restricted_total > calendar_total:
        raise ValueError(
            "restricted contribution subset exceeds contribution calendar total; GitHub semantics changed"
        )

    return calendar_total, restricted_total


def set_attr(element: str, name: str, value: str) -> str:
    pattern = re.compile(rf'\b{re.escape(name)}="[^"]*"')
    replacement = f'{name}="{value}"'
    if pattern.search(element):
        return pattern.sub(replacement, element, count=1)
    close = element.rfind(">")
    if close < 0:
        raise ValueError(f"cannot add attribute {name!r} to malformed SVG root")
    return element[:close] + f' {replacement}' + element[close:]


def add_provenance(text: str, calendar_total: int, restricted_total: int) -> str:
    match = SVG_OPEN.search(text)
    if not match:
        raise ValueError("SVG root element is missing")
    root = match.group(0)
    for name, value in (
        ("data-contribution-total-sync", SYNC_ID),
        ("data-contribution-total-source", "github-profile-visible"),
        ("data-calendar-contributions", str(calendar_total)),
        ("data-restricted-contributions", str(restricted_total)),
        ("data-profile-visible-contributions", str(calendar_total)),
    ):
        root = set_attr(root, name, value)
    return text[: match.start()] + root + text[match.end() :]


def sync_svg(text: str, calendar_total: int, restricted_total: int) -> str:
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
    text = add_provenance(text, calendar_total, restricted_total)
    validate(text, calendar_total, restricted_total)
    return text


def validate(text: str, calendar_total: int, restricted_total: int) -> None:
    formatted = format_count(calendar_total)
    required_root_attrs = (
        f'data-contribution-total-sync="{SYNC_ID}"',
        'data-contribution-total-source="github-profile-visible"',
        f'data-calendar-contributions="{calendar_total}"',
        f'data-restricted-contributions="{restricted_total}"',
        f'data-profile-visible-contributions="{calendar_total}"',
    )
    for attr in required_root_attrs:
        if text.count(attr) != 1:
            raise ValueError(f"profile-visible contribution provenance is missing or duplicated: {attr}")

    headline_matches = HEADLINE.findall(text)
    if len(headline_matches) != 1 or headline_matches[0][1] != formatted:
        raise ValueError("visible Contributions headline does not match GitHub contribution calendar total")
    accessible_matches = ACCESSIBLE_TOTAL.findall(text)
    if len(accessible_matches) != 1 or accessible_matches[0][1] != formatted:
        raise ValueError("accessible contribution description does not match GitHub contribution calendar total")


def apply_directory(directory: Path, token: str, username: str) -> None:
    calendar_total, restricted_total = fetch_profile_visible_total(token, username)
    print(
        "GitHub profile-visible contributions: "
        f"calendar/profile={calendar_total:,}; restricted subset={restricted_total:,}"
    )
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        synced = sync_svg(
            path.read_text(encoding="utf-8"),
            calendar_total,
            restricted_total,
        )
        path.write_text(synced, encoding="utf-8")
        print(f"profile-visible contribution total synced {filename} -> {calendar_total:,}")


def fixture() -> str:
    return (
        '<svg xmlns="http://www.w3.org/2000/svg">'
        '<desc id="desc">4,874 contributions in the past year; 12 stars.</desc>'
        '<text x="30" y="109" fill="#00FBCC" data-metric-phosphor="contributions">'
        '4,874</text></svg>'
    )


def self_test() -> None:
    calendar_total = 5_030
    restricted_total = 156
    synced = sync_svg(fixture(), calendar_total, restricted_total)
    validate(synced, calendar_total, restricted_total)
    assert ">5,030</text>" in synced
    assert "5,030 contributions in the past year;" in synced
    assert 'data-calendar-contributions="5030"' in synced
    assert 'data-restricted-contributions="156"' in synced
    assert 'data-profile-visible-contributions="5030"' in synced
    print(
        f"Signal Field profile-visible contribution sync self-test passed: {SYNC_ID}; "
        "calendar/profile=5,030 with restricted subset=156"
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
