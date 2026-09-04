#!/usr/bin/env python3
"""Validate final, publishable Signal Field artifacts.

This validator is intentionally downstream of every transformation stage. It validates
what would actually be published rather than isolated script fixtures only, and is used
by both pull-request integration testing and the production publisher.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)

ROOT = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
HEADLINE = re.compile(
    r'<text\b(?=[^>]*\bdata-metric-phosphor="contributions")[^>]*>([\d,]+)</text>',
    re.I,
)
DESC_TOTAL = re.compile(r'<desc\b[^>]*>([\d,]+) contributions in the past year;', re.I)
ISSUE_VALUE = re.compile(
    r'<text\b(?=[^>]*\bdata-metric-phosphor="issues")[^>]*>([\d,]+)</text>',
    re.I,
)
DESC_ISSUES = re.compile(
    r'([\d,]+) authored public issues reported by GitHub REST Search',
    re.I,
)

REQUIRED_ROOT_ATTRS = {
    "data-theme": "yunior-portal-neon-v2",
    "data-polish": "signal-field-v2.1",
    "data-enhancement": "signal-field-v2.2",
    "data-background": "signal-field-v2.3",
    "data-portal": "signal-field-v2.4",
    "data-metric-phosphor": "signal-field-v2.6",
    "data-activity-phosphor": "signal-field-v2.7",
    "data-line-phosphor": "signal-field-v2.8",
    "data-contribution-total-sync": "signal-field-v2.9",
    "data-metric-labels": "signal-field-v2.10",
    "data-metric-glyphs": "signal-field-v2.11",
    "data-secondary-metric-balance": "signal-field-v2.12",
    "data-contribution-total-source": "github-default-contribution-calendar",
    "data-metric-sources": "github-graphql+rest",
    "data-generation-schedule": "5-minutes",
    "data-intensity-scale": "github-contribution-levels-0-4",
    "data-count-semantics": "raw-github-contribution-counts",
    "data-activity-layout": "month-calendar-v2",
    "data-activity-columns": "7",
    "data-issues-metric-source": "github-rest-search-authored-public-issues",
    "data-issues-display-alias": "bugs-found",
}

FORBIDDEN = (
    'data-restricted-contributions=',
    'data-refresh-cadence=',
    'data-period-days=',
    "REFRESH · 5 MIN",
    "REFRESH · DAILY",
    "Refresh cadence: every 5 minutes.",
    "Refresh cadence: daily.",
    ">ISSUES</text>",
)


def fail(message: str) -> None:
    raise ValueError(message)


def tag_attrs_for_metric(text: str, metric: str) -> dict[str, str]:
    pattern = re.compile(
        rf'(?P<tag><text\b(?=[^>]*\bdata-metric-phosphor="{re.escape(metric)}")[^>]*>)',
        re.I,
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        fail(f"metric value tag missing or duplicated for {metric}")
    return dict(ATTR.findall(matches[0].group("tag")))


def tag_attrs_for_label(text: str, label: str) -> dict[str, str]:
    pattern = re.compile(rf'(?P<tag><text\b[^>]*>){re.escape(label)}</text>', re.I)
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        fail(f"metric label tag missing or duplicated for {label}")
    return dict(ATTR.findall(matches[0].group("tag")))


def glyph_attrs(text: str, metric: str) -> dict[str, str]:
    pattern = re.compile(
        rf'(?P<tag><g\b(?=[^>]*\bdata-metric-glyph="{re.escape(metric)}")[^>]*>)',
        re.I,
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        fail(f"decorative inline-vector metric glyph missing or duplicated for {metric}")
    return dict(ATTR.findall(matches[0].group("tag")))


def validate_file(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"missing or empty generated artifact: {path.name}")
    text = path.read_text(encoding="utf-8")
    root_match = ROOT.search(text)
    if not root_match:
        fail(f"SVG root missing: {path.name}")
    attrs = dict(ATTR.findall(root_match.group(0)))

    for name, value in REQUIRED_ROOT_ATTRS.items():
        if attrs.get(name) != value:
            fail(f"{path.name}: required root provenance {name}={value!r} is missing")

    for name in (
        "data-calendar-contributions",
        "data-profile-visible-contributions",
        "data-profile-period-from",
        "data-profile-period-to",
        "data-activity-from",
        "data-activity-to",
        "data-active-days",
        "data-current-streak",
        "data-peak-count",
        "data-peak-date",
    ):
        if not attrs.get(name):
            fail(f"{path.name}: required evidence attribute {name} is missing")

    if attrs["data-calendar-contributions"] != attrs["data-profile-visible-contributions"]:
        fail(f"{path.name}: profile-visible total diverges from calendar total")

    headline = HEADLINE.findall(text)
    accessible = DESC_TOTAL.findall(text)
    if len(headline) != 1 or len(accessible) != 1:
        fail(f"{path.name}: contribution headline/accessibility contract changed")
    expected = f"{int(attrs['data-calendar-contributions']):,}"
    if headline[0] != expected or accessible[0] != expected:
        fail(f"{path.name}: visible/accessibility contribution total diverges from provenance")

    issue_value = ISSUE_VALUE.findall(text)
    accessible_issues = DESC_ISSUES.findall(text)
    if len(issue_value) != 1 or len(accessible_issues) != 1:
        fail(f"{path.name}: authored public GitHub Issues metric/source contract changed")
    if issue_value[0] != accessible_issues[0]:
        fail(f"{path.name}: BUGS FOUND display value diverges from underlying authored public Issues total")

    if text.count('data-activity-summary="true"') != 1:
        fail(f"{path.name}: activity summary count changed")
    if text.count('data-telemetry-phosphor="peak_date"') != 1:
        fail(f"{path.name}: PEAK date telemetry is missing")
    if text.count('data-telemetry-phosphor="peak_count"') != 1:
        fail(f"{path.name}: PEAK count telemetry is missing")
    if text.count('data-header-ambient="signal-field-v2.8-header"') != 1:
        fail(f"{path.name}: header ambient topology is missing")
    if text.count('data-latest-day="true"') != 1:
        fail(f"{path.name}: latest activity day marker is missing")
    if text.count('data-latest-outline="outer"') != 1:
        fail(f"{path.name}: latest activity outline is missing")

    for metric in ("contributions", "stars", "pull_requests", "issues"):
        if text.count(f'data-metric-phosphor="{metric}"') != 1:
            fail(f"{path.name}: metric value provenance missing for {metric}")
        if text.count(f'data-metric-phosphor-line="{metric}"') != 1:
            fail(f"{path.name}: metric line provenance missing for {metric}")

    expected_scale = "1.4583" if "wide" in path.name else "1.2083"
    for metric in ("stars", "pull_requests", "issues"):
        gattrs = glyph_attrs(text, metric)
        if gattrs.get("data-glyph-rendering") != "inline-vector":
            fail(f"{path.name}: metric glyph rendering provenance changed for {metric}")
        if gattrs.get("aria-hidden") != "true":
            fail(f"{path.name}: decorative metric glyph must remain accessibility-hidden for {metric}")
        if f"scale({expected_scale})" not in gattrs.get("transform", ""):
            fail(f"{path.name}: {metric} glyph is not using the reviewed v2.12 display scale")
    for vector in ("star", "pull-request", "bug"):
        if text.count(f'data-glyph-vector="{vector}"') != 1:
            fail(f"{path.name}: expected {vector} vector glyph is missing or duplicated")

    pull_value = tag_attrs_for_metric(text, "pull_requests")
    pull_label = tag_attrs_for_label(text, "PULL REQUESTS")
    if "wide" in path.name:
        if pull_value.get("x") != "447" or pull_value.get("text-anchor") != "middle":
            fail(f"{path.name}: Pull Requests value must remain centered between outer metric axes")
        if pull_label.get("x") != "447" or pull_label.get("text-anchor") != "middle":
            fail(f"{path.name}: Pull Requests label must remain centered between outer metric axes")
        line = re.compile(
            r'(?P<tag><path\b(?=[^>]*\bdata-metric-phosphor-line="pull_requests")[^>]*>)',
            re.I,
        ).search(text)
        if not line or dict(ATTR.findall(line.group("tag"))).get("d") != "M404 73h86":
            fail(f"{path.name}: Pull Requests phosphor line must remain centered at x=447")
    else:
        if pull_value.get("x") != "160" or pull_value.get("text-anchor") != "middle":
            fail(f"{path.name}: compact Pull Requests value must remain centered at x=160")
        if pull_label.get("x") != "160" or pull_label.get("text-anchor") != "middle":
            fail(f"{path.name}: compact Pull Requests label must remain centered at x=160")

    if text.count(">BUGS FOUND</text>") != 1:
        fail(f"{path.name}: visible Bugs Found metric label is missing or duplicated")
    if "authored public issues reported by GitHub REST Search" not in text:
        fail(f"{path.name}: accessible Issues source semantics must remain explicit")

    for forbidden in FORBIDDEN:
        if forbidden in text:
            fail(f"{path.name}: forbidden stale/sensitive contract remains: {forbidden}")

    expected_footer = (
        "SOURCES · GITHUB GRAPHQL + REST · SCHEDULE · 5 MIN"
        if "wide" in path.name
        else "GITHUB API · GRAPHQL + REST · SCHEDULE · 5 MIN"
    )
    if text.count(expected_footer) != 1:
        fail(f"{path.name}: final source/schedule footer is missing")
    if "Generation schedule: every 5 minutes; execution and README cache propagation are best-effort." not in text:
        fail(f"{path.name}: accessible best-effort schedule semantics are missing")

    if "wide" in path.name:
        if attrs.get("data-metric-layout") != "signal-field-v2.5":
            fail(f"{path.name}: wide metric alignment provenance is missing")
        if text.count('data-day-alignment="centered-month-boundary"') < 1:
            fail(f"{path.name}: wide month-boundary alignment provenance is missing")
    elif "data-metric-layout" in attrs:
        fail(f"{path.name}: compact artifact unexpectedly carries wide metric-layout provenance")


def validate_directory(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        validate_file(directory / filename)
    actual = sorted(path.name for path in directory.glob("signal-field-*.svg"))
    if actual != sorted(EXPECTED_FILES):
        fail(f"generated artifact set changed: {actual}")
    print(
        "Final Signal Field validation passed: four responsive artifacts are complete, attributable, "
        "source-accurate, privacy-minimized, BUGS FOUND remains a display alias over the authored-public "
        "GitHub Issues total, exact profile-period provenance is unambiguous, glyphs are balanced/centered, "
        "and generation uses best-effort five-minute scheduling semantics."
    )


def main() -> int:
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: validate-generated-signal-field.py <generated-directory>")
        validate_directory(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
