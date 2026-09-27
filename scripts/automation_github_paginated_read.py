#!/usr/bin/env python3
"""Bounded paginated GitHub REST collections over the canonical governed GET client."""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Callable
import urllib.parse

import automation_github_read

PAGE_SIZE = 100
MAX_PAGES = 30
SENTINEL_PAGE = MAX_PAGES + 1


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def normalize_paginated_endpoint(value: str) -> str:
    normalized = automation_github_read.normalize_endpoint(value)
    parsed = urllib.parse.urlsplit(normalized)
    pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    per_page = [item for item in pairs if item[0] == "per_page"]
    require(per_page == [("per_page", str(PAGE_SIZE))],
            f"paginated GitHub endpoint must contain exactly per_page={PAGE_SIZE}")
    require(not any(key == "page" for key, _ in pairs),
            "paginated GitHub endpoint must not supply page; pagination is governed internally")
    return normalized


def page_endpoint(endpoint: str, page: int) -> str:
    require(1 <= page <= SENTINEL_PAGE, "paginated GitHub page is outside the bounded range")
    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}page={page}"


def fetch_pages(
    endpoint: str,
    *,
    reader: Callable[[str], str | None] = automation_github_read.get_json_text,
) -> list[list[Any]]:
    normalized = normalize_paginated_endpoint(endpoint)
    pages: list[list[Any]] = []

    for page_number in range(1, SENTINEL_PAGE + 1):
        text = reader(page_endpoint(normalized, page_number))
        require(text is not None, "paginated governed GitHub read unexpectedly returned absence")
        payload = automation_github_read.strict_json(text)
        require(isinstance(payload, list),
                f"paginated GitHub page {page_number} must be a JSON array")
        require(len(payload) <= PAGE_SIZE,
                f"paginated GitHub page {page_number} exceeds {PAGE_SIZE} items")

        if page_number == SENTINEL_PAGE:
            require(not payload,
                    f"paginated GitHub collection exceeds the {MAX_PAGES}-page bound")
            return pages

        pages.append(payload)
        if len(payload) < PAGE_SIZE:
            return pages

    raise ValueError("unreachable paginated governed GitHub read state")


def self_test() -> None:
    require(PAGE_SIZE == 100 and MAX_PAGES == 30 and SENTINEL_PAGE == 31,
            "paginated governed read bounds changed")
    endpoint = "repos/portyu9/portyu9/pulls?state=open&base=main&per_page=100"
    require(normalize_paginated_endpoint(endpoint) == endpoint,
            "paginated endpoint normalization changed")
    require(page_endpoint(endpoint, 1) == endpoint + "&page=1",
            "paginated first-page endpoint changed")
    require(page_endpoint(endpoint, 31) == endpoint + "&page=31",
            "paginated sentinel endpoint changed")

    for forbidden, expected in (
        ("repos/portyu9/portyu9/pulls?state=open", "exactly per_page=100"),
        ("repos/portyu9/portyu9/pulls?per_page=50", "exactly per_page=100"),
        ("repos/portyu9/portyu9/pulls?per_page=100&per_page=100", "exactly per_page=100"),
        ("repos/portyu9/portyu9/pulls?per_page=100&page=1", "must not supply page"),
    ):
        try:
            normalize_paginated_endpoint(forbidden)
        except ValueError as exc:
            require(expected in str(exc), f"pagination endpoint self-test failed for wrong reason: {exc}")
        else:
            raise ValueError(f"paginated endpoint accepted forbidden input: {forbidden}")

    calls: list[str] = []
    sequence = [json.dumps(list(range(PAGE_SIZE))), json.dumps([PAGE_SIZE])]

    def two_page_reader(value: str) -> str:
        calls.append(value)
        require(sequence, "two-page fixture made too many reads")
        return sequence.pop(0)

    pages = fetch_pages(endpoint, reader=two_page_reader)
    require([len(page) for page in pages] == [100, 1],
            "paginated two-page fixture changed")
    require(calls == [endpoint + "&page=1", endpoint + "&page=2"],
            "paginated client did not issue exact sequential page endpoints")

    sentinel_calls: list[int] = []

    def exact_bound_reader(value: str) -> str:
        page = int(urllib.parse.parse_qs(urllib.parse.urlsplit(value).query)["page"][0])
        sentinel_calls.append(page)
        return "[]" if page == SENTINEL_PAGE else json.dumps(list(range(PAGE_SIZE)))

    bounded = fetch_pages(endpoint, reader=exact_bound_reader)
    require(len(bounded) == MAX_PAGES and all(len(page) == PAGE_SIZE for page in bounded),
            "exact-bound paginated fixture changed")
    require(sentinel_calls == list(range(1, SENTINEL_PAGE + 1)),
            "exact-bound collection lost overflow sentinel read")

    def overflow_reader(value: str) -> str:
        page = int(urllib.parse.parse_qs(urllib.parse.urlsplit(value).query)["page"][0])
        return json.dumps([1]) if page == SENTINEL_PAGE else json.dumps(list(range(PAGE_SIZE)))

    try:
        fetch_pages(endpoint, reader=overflow_reader)
    except ValueError as exc:
        require("exceeds the 30-page bound" in str(exc),
                f"pagination overflow self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("paginated governed read accepted a collection beyond 30 pages")

    def malformed_reader(_value: str) -> str:
        return '{"not":"a page"}'

    try:
        fetch_pages(endpoint, reader=malformed_reader)
    except ValueError as exc:
        require("must be a JSON array" in str(exc),
                f"pagination page-shape self-test failed for wrong reason: {exc}")
    else:
        raise ValueError("paginated governed read accepted a non-array page")


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("endpoint", nargs="?")
    value.add_argument("--self-test", action="store_true")
    return value


def main() -> int:
    args = parser().parse_args()
    try:
        if args.self_test:
            require(args.endpoint is None, "--self-test does not accept an endpoint")
            automation_github_read.self_test()
            self_test()
            print(
                "Governed paginated GitHub read self-test passed: repository-scoped GET only; "
                "per_page=100; 30-page bound plus overflow sentinel; every page delegates to "
                "the canonical classified transient-safe GET client."
            )
            return 0
        require(args.endpoint is not None, "paginated GitHub API endpoint is required")
        pages = fetch_pages(args.endpoint)
        sys.stdout.write(json.dumps(pages, separators=(",", ":"), ensure_ascii=False) + "\n")
        return 0
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
