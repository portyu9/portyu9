#!/usr/bin/env python3
"""Validate final, publishable Signal Field artifacts.

This validator runs downstream of every transformation stage and validates the bytes
that may be attested/published. It protects source semantics, Evidence ID provenance,
30-day membership, reviewed final presentation, metric geometry, privacy limits, and
the measured best-effort generation-refresh contract.
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
HEADLINE = re.compile(r'<text\b(?=[^>]*\bdata-metric-phosphor="contributions")[^>]*>([\d,]+)</text>', re.I)
DESC_TOTAL = re.compile(r'<desc\b[^>]*>([\d,]+) contributions in the past year;', re.I)
ISSUE_VALUE = re.compile(r'<text\b(?=[^>]*\bdata-metric-phosphor="issues")[^>]*>([\d,]+)</text>', re.I)
DESC_ISSUES = re.compile(r'([\d,]+) authored public issues reported by GitHub REST Search', re.I)
MEASURED = re.compile(r'(?P<tag><rect\b(?=[^>]*\bdata-evidence-window-role="measured")[^>]*/>)', re.I)
CONTEXT = re.compile(r'(?P<tag><rect\b(?=[^>]*\bdata-evidence-window-role="context")[^>]*/>)', re.I)
MONTH = re.compile(r'(?P<tag><text\b(?=[^>]*\bdata-month-boundary="[A-Z]{3}")[^>]*>)', re.I)
LATEST = re.compile(r'(?P<tag><rect\b(?=[^>]*\bdata-latest-day="true")[^>]*/>)', re.I)
OUTLINE = re.compile(r'(?P<tag><rect\b(?=[^>]*\bdata-latest-outline="outer")[^>]*/>)', re.I)

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
    "data-evidence-window-clarity": "signal-field-v2.13",
    "data-evidence-identity": "signal-field-v2.14",
    "data-evidence-presentation": "signal-field-v2.15",
    "data-issues-label-balance": "signal-field-v2.16",
    "data-issues-label-scale": "peer-metric-label",
    "data-generation-cadence-contract": "profile-refresh-v2",
    "data-current-day-highlight": "phosphorescent-red-v1",
    "data-contribution-total-source": "github-default-contribution-calendar",
    "data-metric-sources": "github-graphql+rest",
    "data-generation-schedule": "1-hour",
    "data-intensity-scale": "github-contribution-levels-0-4",
    "data-count-semantics": "raw-github-contribution-counts",
    "data-activity-layout": "month-calendar-v2",
    "data-activity-columns": "7",
    "data-issues-metric-source": "github-rest-search-authored-public-issues",
    "data-issues-display-alias": "bug-found",
    "data-calendar-context-visual": "outlined",
}

FORBIDDEN = (
    'data-restricted-contributions=',
    'data-refresh-cadence=',
    'data-period-days=',
    "REFRESH · 5 MIN",
    "REFRESH · 30 MIN",
    "REFRESH · DAILY",
    "Refresh cadence: every 5 minutes.",
    "Refresh cadence: daily.",
    "SCHEDULE · 5 MIN",
    "SCHEDULE · 30 MIN",
    "Generation schedule: every 5 minutes; execution and README cache propagation are best-effort.",
    "Generation schedule: every 30 minutes; execution and README cache propagation are best-effort.",
    ">ISSUES</text>",
    ">ISSUES AUTHORED</text>",
    ">BUGS FOUND</text>",
    "DIM CONTEXT",
)


def fail(message: str) -> None:
    raise ValueError(message)


def attrs_of(tag: str) -> dict[str, str]:
    return dict(ATTR.findall(tag))


def tag_attrs_for_metric(text: str, metric: str) -> dict[str, str]:
    pattern = re.compile(rf'(?P<tag><text\b(?=[^>]*\bdata-metric-phosphor="{re.escape(metric)}")[^>]*>)', re.I)
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        fail(f"metric value tag missing or duplicated for {metric}")
    return attrs_of(matches[0].group("tag"))


def tag_attrs_for_label(text: str, label: str) -> dict[str, str]:
    pattern = re.compile(rf'(?P<tag><text\b[^>]*>){re.escape(label)}</text>', re.I)
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        fail(f"metric label tag missing or duplicated for {label}")
    return attrs_of(matches[0].group("tag"))


def glyph_attrs(text: str, metric: str) -> dict[str, str]:
    pattern = re.compile(rf'(?P<tag><g\b(?=[^>]*\bdata-metric-glyph="{re.escape(metric)}")[^>]*>)', re.I)
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        fail(f"decorative inline-vector metric glyph missing or duplicated for {metric}")
    return attrs_of(matches[0].group("tag"))


def validate_file(path: Path) -> None:
    if not path.is_file() or path.stat().st_size == 0:
        fail(f"missing or empty generated artifact: {path.name}")
    text = path.read_text(encoding="utf-8")
    root = ROOT.search(text)
    if not root:
        fail(f"SVG root missing: {path.name}")
    attrs = attrs_of(root.group(0))

    for name, value in REQUIRED_ROOT_ATTRS.items():
        if attrs.get(name) != value:
            fail(f"{path.name}: required root provenance {name}={value!r} is missing")
    for name in (
        "data-calendar-contributions", "data-profile-visible-contributions",
        "data-profile-period-from", "data-profile-period-to", "data-activity-from",
        "data-activity-to", "data-active-days", "data-current-streak", "data-peak-count",
        "data-peak-date", "data-evidence-id", "data-evidence-digest",
    ):
        if not attrs.get(name):
            fail(f"{path.name}: required evidence attribute {name} is missing")
    if not re.fullmatch(r"SF1-[0-9A-F]{16}", attrs["data-evidence-id"]):
        fail(f"{path.name}: Evidence ID format changed")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", attrs["data-evidence-digest"]):
        fail(f"{path.name}: Evidence digest format changed")

    if attrs["data-calendar-contributions"] != attrs["data-profile-visible-contributions"]:
        fail(f"{path.name}: profile-visible total diverges from calendar total")
    headline = HEADLINE.findall(text)
    accessible = DESC_TOTAL.findall(text)
    expected = f"{int(attrs['data-calendar-contributions']):,}"
    if len(headline) != 1 or len(accessible) != 1 or headline[0] != expected or accessible[0] != expected:
        fail(f"{path.name}: contribution headline/accessibility contract changed")

    issue_value = ISSUE_VALUE.findall(text)
    accessible_issues = DESC_ISSUES.findall(text)
    if len(issue_value) != 1 or len(accessible_issues) != 1 or issue_value[0] != accessible_issues[0]:
        fail(f"{path.name}: authored public GitHub Issues metric/source contract changed")
    if text.count(">BUG FOUND</text>") != 1:
        fail(f"{path.name}: visible BUG FOUND metric label is missing or duplicated")

    measured = [attrs_of(m.group("tag")) for m in MEASURED.finditer(text)]
    context = [attrs_of(m.group("tag")) for m in CONTEXT.finditer(text)]
    if len(measured) != 30:
        fail(f"{path.name}: exactly 30 measured evidence tiles are required")
    display_days = int(attrs.get("data-activity-display-days", "0"))
    if len(context) != display_days - 30:
        fail(f"{path.name}: leading-context membership diverges from display provenance")
    context_stroke = "#59657A" if path.name.endswith("-dark.svg") else "#A7B0C4"
    for tile in context:
        if "opacity" in tile:
            fail(f"{path.name}: leading context must not alter contribution intensity with opacity")
        if tile.get("stroke") != context_stroke or tile.get("stroke-width") != "1.15":
            fail(f"{path.name}: leading-context outline styling changed")
        if tile.get("stroke-dasharray") != "3 2" or tile.get("data-context-encoding") != "outline":
            fail(f"{path.name}: leading-context encoding changed")

    months = [attrs_of(m.group("tag")) for m in MONTH.finditer(text)]
    if not months:
        fail(f"{path.name}: month markers disappeared")
    expected_month = "#FFFFFF" if path.name.endswith("-dark.svg") else "#111827"
    expected_month_size = "7.2" if "wide" in path.name else "6"
    for month in months:
        if month.get("fill") != expected_month or month.get("opacity") != "1":
            fail(f"{path.name}: month marker contrast changed")
        if month.get("font-size") != expected_month_size or month.get("font-weight") != "800":
            fail(f"{path.name}: month marker scale/weight changed")

    latest = LATEST.search(text)
    outline = OUTLINE.search(text)
    if not latest or not outline:
        fail(f"{path.name}: latest activity ring is missing")
    latest_attrs = attrs_of(latest.group("tag"))
    outline_attrs = attrs_of(outline.group("tag"))
    if latest_attrs.get("stroke") != "none" or latest_attrs.get("stroke-width") != "0":
        fail(f"{path.name}: latest-day tile retained a second keyline")
    if outline_attrs.get("stroke") != "#FF335F" or outline_attrs.get("stroke-width") != "1.4" or outline_attrs.get("opacity") != "0.96":
        fail(f"{path.name}: phosphorescent-red current-day ring changed")

    if text.count('data-activity-summary="true"') != 1:
        fail(f"{path.name}: activity summary count changed")
    if text.count('data-telemetry-phosphor="peak_date"') != 1 or text.count('data-telemetry-phosphor="peak_count"') != 1:
        fail(f"{path.name}: PEAK telemetry is incomplete")
    if text.count('data-header-ambient="signal-field-v2.8-header"') != 1:
        fail(f"{path.name}: header ambient topology is missing")

    for metric in ("contributions", "stars", "pull_requests", "issues"):
        if text.count(f'data-metric-phosphor="{metric}"') != 1:
            fail(f"{path.name}: metric value provenance missing for {metric}")
        if text.count(f'data-metric-phosphor-line="{metric}"') != 1:
            fail(f"{path.name}: metric line provenance missing for {metric}")

    expected_scale = "1.4583" if "wide" in path.name else "1.2083"
    for metric in ("stars", "pull_requests", "issues"):
        gattrs = glyph_attrs(text, metric)
        if gattrs.get("data-glyph-rendering") != "inline-vector" or gattrs.get("aria-hidden") != "true":
            fail(f"{path.name}: vector glyph accessibility/provenance changed for {metric}")
        if f"scale({expected_scale})" not in gattrs.get("transform", ""):
            fail(f"{path.name}: {metric} glyph display scale changed")
    for vector in ("star", "pull-request", "bug"):
        if text.count(f'data-glyph-vector="{vector}"') != 1:
            fail(f"{path.name}: expected {vector} vector glyph is missing or duplicated")

    star_label = tag_attrs_for_label(text, "STARS")
    pull_value = tag_attrs_for_metric(text, "pull_requests")
    pull_label = tag_attrs_for_label(text, "PULL REQUESTS")
    bug_label = tag_attrs_for_label(text, "BUG FOUND")
    expected_label_size = "12" if "wide" in path.name else "9"
    label_sizes = {star_label.get("font-size"), pull_label.get("font-size"), bug_label.get("font-size")}
    if label_sizes != {expected_label_size}:
        fail(
            f"{path.name}: STARS / PULL REQUESTS / BUG FOUND label sizes must all equal "
            f"{expected_label_size}px, got {sorted(value for value in label_sizes if value is not None)}"
        )

    if "wide" in path.name:
        if pull_value.get("x") != "447" or pull_value.get("text-anchor") != "middle":
            fail(f"{path.name}: Pull Requests value alignment changed")
        if pull_label.get("x") != "447" or pull_label.get("text-anchor") != "middle":
            fail(f"{path.name}: Pull Requests label alignment changed")
        line = re.compile(r'(?P<tag><path\b(?=[^>]*\bdata-metric-phosphor-line="pull_requests")[^>]*>)', re.I).search(text)
        if not line or attrs_of(line.group("tag")).get("d") != "M404 73h86":
            fail(f"{path.name}: Pull Requests phosphor line alignment changed")
        if text.count("30D EVIDENCE · LEADING CONTEXT · LEVELS 0–4 · RAW COUNTS") != 1:
            fail(f"{path.name}: leading-context footer is missing")
    else:
        if pull_value.get("x") != "160" or pull_value.get("text-anchor") != "middle":
            fail(f"{path.name}: compact Pull Requests value alignment changed")
        if pull_label.get("x") != "160" or pull_label.get("text-anchor") != "middle":
            fail(f"{path.name}: compact Pull Requests label alignment changed")

    if "authored public issues reported by GitHub REST Search" not in text:
        fail(f"{path.name}: accessible Issues source semantics must remain explicit")
    if "as Monday-aligned leading context." not in text:
        fail(f"{path.name}: accessible leading-context semantics are missing")
    if f"Evidence ID {attrs['data-evidence-id']} is the deterministic identity" not in text:
        fail(f"{path.name}: accessible Evidence ID semantics are missing")

    for forbidden in FORBIDDEN:
        if forbidden in text:
            fail(f"{path.name}: forbidden stale/sensitive contract remains: {forbidden}")

    expected_footer = (
        "SOURCES · GITHUB GRAPHQL + REST · REFRESH · 1 HR"
        if "wide" in path.name else "GITHUB API · GRAPHQL + REST · REFRESH · 1 HR"
    )
    if text.count(expected_footer) != 1:
        fail(f"{path.name}: final source/refresh footer is missing")
    if "Generation refresh: every hour; execution and README cache propagation are best-effort." not in text:
        fail(f"{path.name}: accessible best-effort hourly refresh semantics are missing")

    if "wide" in path.name:
        if attrs.get("data-metric-layout") != "signal-field-v2.5":
            fail(f"{path.name}: wide metric alignment provenance is missing")
        if text.count('data-day-alignment="centered-month-boundary"') < 1:
            fail(f"{path.name}: wide month-boundary alignment provenance is missing")
    elif "data-metric-layout" in attrs:
        fail(f"{path.name}: compact artifact unexpectedly carries wide metric-layout provenance")


def validate_directory(directory: Path) -> None:
    identities: set[tuple[str, str]] = set()
    for filename in EXPECTED_FILES:
        path = directory / filename
        validate_file(path)
        root = ROOT.search(path.read_text(encoding="utf-8"))
        assert root is not None
        attrs = attrs_of(root.group(0))
        identities.add((attrs["data-evidence-id"], attrs["data-evidence-digest"]))
    if len(identities) != 1:
        fail("responsive Signal Field variants do not share one Evidence ID/digest")
    actual = sorted(path.name for path in directory.glob("signal-field-*.svg"))
    if actual != sorted(EXPECTED_FILES):
        fail(f"generated artifact set changed: {actual}")
    evidence_id, _ = next(iter(identities))
    print(
        "Final Signal Field validation passed: four responsive artifacts preserve one measured evidence set "
        f"({evidence_id}), source-accurate authored-Issues semantics with a peer-scale BUG FOUND label, "
        "outline-only leading context, maximum-contrast month markers, a phosphorescent-red current-day ring, "
        "balanced glyph geometry, and best-effort hourly refresh."
    )


def main() -> int:
    try:
        if len(sys.argv) != 2:
            raise ValueError("usage: validate-generated-signal-field.py <generated-directory>")
        validate_directory(Path(sys.argv[1])); return 0
    except (OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
