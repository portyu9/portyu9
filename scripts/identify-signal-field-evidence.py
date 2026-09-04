#!/usr/bin/env python3
"""Stamp Signal Field v2.14 with a deterministic semantic Evidence ID.

The Evidence ID is intentionally derived from measured evidence semantics rather than
rendered SVG bytes. All four responsive/theme variants therefore share one identity,
while presentation-only differences do not create false evidence changes.

Canonical evidence covers:
- exact profile contribution period and total,
- headline contributions/stars/pull requests/authored-public Issues values,
- exact 30-day activity window, active/streak/peak telemetry,
- all 30 measured date/count/GitHub-level tuples,
- source/timezone/intensity semantics.

The short visible ID is the first 64 bits of the canonical SHA-256 digest. The complete
digest is retained in SVG provenance and is also consumed by the attestation predicate.
"""
from __future__ import annotations

from datetime import date, timedelta
import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile

VERSION = "signal-field-v2.14"
SCHEMA = "signal-field-evidence-v1"
ID_PREFIX = "SF1"
PREVIOUS = "signal-field-v2.13"
EXPECTED_FILES = tuple(
    f"signal-field-{layout}-{theme}.svg"
    for layout in ("wide", "compact")
    for theme in ("light", "dark")
)
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
DESC = re.compile(r"<desc\b([^>]*)>([^<]*)</desc>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
MEASURED_RECT = re.compile(
    r'(?P<tag><rect\b(?=[^>]*\bdata-evidence-window-role="measured")[^>]*/>)',
    re.I,
)
METRIC_VALUE = re.compile(
    r'<text\b(?=[^>]*\bdata-metric-phosphor="(?P<metric>contributions|stars|pull_requests|issues)")[^>]*>(?P<value>[\d,]+)</text>',
    re.I,
)
EID_LABEL = re.compile(r'<text\b(?=[^>]*\bdata-signal-field-evidence-id="true")[^>]*>[^<]+</text>', re.I)
MONO_FONT = "ui-monospace,SFMono-Regular,Consolas,Liberation Mono,monospace"


def attrs_of(tag: str) -> dict[str, str]:
    return dict(ATTR.findall(tag))


def set_attr(tag: str, name: str, value: str) -> str:
    pattern = re.compile(rf'\b{re.escape(name)}="[^"]*"')
    replacement = f'{name}="{value}"'
    if pattern.search(tag):
        return pattern.sub(replacement, tag, count=1)
    close = tag.rfind("/>") if tag.endswith("/>") else tag.rfind(">")
    if close < 0:
        raise ValueError(f"cannot set {name!r} on malformed SVG element")
    return tag[:close].rstrip() + f' {replacement}' + tag[close:]


def root_attrs(text: str) -> dict[str, str]:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing")
    return attrs_of(root.group(0))


def metric_values(text: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for match in METRIC_VALUE.finditer(text):
        metric = match.group("metric").lower()
        if metric in values:
            raise ValueError(f"headline metric duplicated: {metric}")
        values[metric] = int(match.group("value").replace(",", ""))
    expected = {"contributions", "stars", "pull_requests", "issues"}
    if set(values) != expected:
        raise ValueError(f"headline metric set changed: {sorted(values)}")
    return values


def measured_days(text: str) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for match in MEASURED_RECT.finditer(text):
        attrs = attrs_of(match.group("tag"))
        required = {"data-date", "data-count", "data-level"}
        missing = required - attrs.keys()
        if missing:
            raise ValueError("measured activity tile is missing: " + ", ".join(sorted(missing)))
        try:
            count = int(attrs["data-count"])
            level = int(attrs["data-level"])
            parsed = date.fromisoformat(attrs["data-date"])
        except ValueError as exc:
            raise ValueError("measured activity tile contains malformed evidence") from exc
        if count < 0 or level not in range(5):
            raise ValueError("measured activity count/level is out of contract")
        result.append({"date": parsed.isoformat(), "count": count, "level": level})
    if len(result) != 30:
        raise ValueError(f"Evidence ID requires exactly 30 measured days, found {len(result)}")
    dates = [date.fromisoformat(str(item["date"])) for item in result]
    if len(set(dates)) != 30 or dates != sorted(dates):
        raise ValueError("measured evidence dates must be unique and chronological")
    for previous, current in zip(dates, dates[1:]):
        if current - previous != timedelta(days=1):
            raise ValueError("measured evidence dates must be consecutive")
    return result


def canonical_evidence(text: str) -> dict[str, object]:
    attrs = root_attrs(text)
    if attrs.get("data-evidence-window-clarity") != PREVIOUS:
        raise ValueError("Signal Field v2.13 must precede Evidence ID stamping")
    required = (
        "data-profile-visible-contributions",
        "data-profile-period-from",
        "data-profile-period-to",
        "data-activity-from",
        "data-activity-to",
        "data-active-days",
        "data-current-streak",
        "data-peak-count",
        "data-peak-date",
        "data-source",
        "data-metric-sources",
        "data-issues-metric-source",
        "data-intensity-scale",
        "data-count-semantics",
        "data-window-timezone",
    )
    missing = [name for name in required if not attrs.get(name)]
    if missing:
        raise ValueError("Evidence ID source provenance is missing: " + ", ".join(missing))

    metrics = metric_values(text)
    visible_total = int(attrs["data-profile-visible-contributions"])
    if metrics["contributions"] != visible_total:
        raise ValueError("headline contributions diverge from profile-visible provenance")

    days = measured_days(text)
    if days[0]["date"] != attrs["data-activity-from"] or days[-1]["date"] != attrs["data-activity-to"]:
        raise ValueError("measured tile dates diverge from activity-window provenance")

    return {
        "schema": SCHEMA,
        "profile": {
            "periodFrom": attrs["data-profile-period-from"],
            "periodTo": attrs["data-profile-period-to"],
            "contributions": visible_total,
        },
        "headline": {
            "contributions": metrics["contributions"],
            "stars": metrics["stars"],
            "pullRequests": metrics["pull_requests"],
            "authoredPublicIssues": metrics["issues"],
        },
        "activity": {
            "from": attrs["data-activity-from"],
            "to": attrs["data-activity-to"],
            "activeDays": int(attrs["data-active-days"]),
            "currentStreak": int(attrs["data-current-streak"]),
            "peakCount": int(attrs["data-peak-count"]),
            "peakDate": attrs["data-peak-date"],
            "days": days,
        },
        "sources": {
            "activity": attrs["data-source"],
            "headlines": attrs["data-metric-sources"],
            "issues": attrs["data-issues-metric-source"],
            "intensity": attrs["data-intensity-scale"],
            "counts": attrs["data-count-semantics"],
            "timezone": attrs["data-window-timezone"],
        },
    }


def evidence_identity(text: str) -> tuple[str, str, dict[str, object]]:
    canonical = canonical_evidence(text)
    payload = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    evidence_id = f"{ID_PREFIX}-{digest[:16].upper()}"
    return evidence_id, f"sha256:{digest}", canonical


def layout_for(path: Path) -> str:
    if "-wide-" in path.name:
        return "wide"
    if "-compact-" in path.name:
        return "compact"
    raise ValueError(f"unsupported Signal Field layout: {path.name}")


def scheme_for(path: Path) -> str:
    if path.name.endswith("-dark.svg"):
        return "dark"
    if path.name.endswith("-light.svg"):
        return "light"
    raise ValueError(f"unsupported Signal Field theme: {path.name}")


def add_accessible_identity(text: str, evidence_id: str) -> str:
    matches = list(DESC.finditer(text))
    if len(matches) != 1:
        raise ValueError("Signal Field must contain exactly one accessible description")
    sentence = (
        f" Evidence ID {evidence_id} is the deterministic identity of the measured Signal Field "
        "evidence semantics shared by all four responsive variants."
    )
    if sentence in matches[0].group(2):
        return text
    replacement = f"<desc{matches[0].group(1)}>{matches[0].group(2).rstrip()}{sentence}</desc>"
    return text[:matches[0].start()] + replacement + text[matches[0].end():]


def label_svg(layout: str, scheme: str, evidence_id: str) -> str:
    color = "#A7B0C4" if scheme == "dark" else "#5B6475"
    if layout == "wide":
        return (
            f'<text x="320" y="391" fill="{color}" font-family="{MONO_FONT}" font-size="6.8" '
            f'font-weight="650" text-anchor="middle" letter-spacing="0.25" '
            f'data-signal-field-evidence-id="true">EID · {evidence_id}</text>'
        )
    return (
        f'<text x="160" y="463" fill="{color}" font-family="{MONO_FONT}" font-size="6.2" '
        f'font-weight="650" text-anchor="middle" letter-spacing="0.15" '
        f'data-signal-field-evidence-id="true">EID · {evidence_id}</text>'
    )


def stamp_text(text: str, path: Path, evidence_id: str, digest: str) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing")
    attrs = attrs_of(root.group(0))
    existing = attrs.get("data-evidence-identity")
    if existing and existing != VERSION:
        raise ValueError(f"unexpected pre-existing Evidence ID version: {existing}")

    tag = root.group(0)
    for name, value in (
        ("data-evidence-identity", VERSION),
        ("data-evidence-id-schema", SCHEMA),
        ("data-evidence-id", evidence_id),
        ("data-evidence-digest", digest),
    ):
        tag = set_attr(tag, name, value)
    text = text[:root.start()] + tag + text[root.end():]
    text = add_accessible_identity(text, evidence_id)

    labels = EID_LABEL.findall(text)
    if not labels:
        marker = label_svg(layout_for(path), scheme_for(path), evidence_id)
        closing = text.rfind("</svg>")
        if closing < 0:
            raise ValueError("SVG closing tag missing")
        text = text[:closing] + marker + text[closing:]
    elif len(labels) == 1:
        if f">EID · {evidence_id}</text>" not in labels[0]:
            raise ValueError("existing visible Evidence ID diverges from canonical identity")
    else:
        raise ValueError("visible Evidence ID is duplicated")
    return text


def validate_stamped(text: str, path: Path, evidence_id: str, digest: str) -> None:
    attrs = root_attrs(text)
    expected = {
        "data-evidence-identity": VERSION,
        "data-evidence-id-schema": SCHEMA,
        "data-evidence-id": evidence_id,
        "data-evidence-digest": digest,
    }
    for name, value in expected.items():
        if attrs.get(name) != value:
            raise ValueError(f"{path.name}: Evidence ID provenance changed for {name}")
    recomputed_id, recomputed_digest, _ = evidence_identity(text)
    if recomputed_id != evidence_id or recomputed_digest != digest:
        raise ValueError(f"{path.name}: Evidence ID does not reproduce from measured semantics")
    labels = EID_LABEL.findall(text)
    if len(labels) != 1 or f">EID · {evidence_id}</text>" not in labels[0]:
        raise ValueError(f"{path.name}: visible Evidence ID label changed")
    label_attrs = attrs_of(labels[0])
    expected_y = "391" if layout_for(path) == "wide" else "463"
    expected_x = "320" if layout_for(path) == "wide" else "160"
    if label_attrs.get("x") != expected_x or label_attrs.get("y") != expected_y or label_attrs.get("text-anchor") != "middle":
        raise ValueError(f"{path.name}: Evidence ID geometry changed")
    if f"Evidence ID {evidence_id} is the deterministic identity" not in text:
        raise ValueError(f"{path.name}: accessible Evidence ID semantics missing")


def apply(directory: Path) -> tuple[str, str]:
    paths = [directory / name for name in EXPECTED_FILES]
    for path in paths:
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {path.name}")

    identities = [evidence_identity(path.read_text(encoding="utf-8")) for path in paths]
    evidence_id, digest, canonical = identities[0]
    for other_id, other_digest, other_canonical in identities[1:]:
        if other_id != evidence_id or other_digest != digest or other_canonical != canonical:
            raise ValueError("responsive Signal Field variants do not share one measured evidence set")

    for path in paths:
        transformed = stamp_text(path.read_text(encoding="utf-8"), path, evidence_id, digest)
        validate_stamped(transformed, path, evidence_id, digest)
        path.write_text(transformed, encoding="utf-8")
        print(f"stamped {path.name}: {evidence_id}")
    return evidence_id, digest


def fixture(layout: str, scheme: str) -> str:
    start = date(2026, 8, 6)
    days = []
    counts = []
    for index in range(30):
        current = start + timedelta(days=index)
        count = (index * 7) % 19
        counts.append(count)
        level = 0 if count == 0 else min(4, 1 + (count % 4))
        days.append(
            f'<rect data-date="{current.isoformat()}" data-count="{count}" data-level="{level}" '
            f'data-window-day="{index + 1}" data-evidence-window-role="measured"/>'
        )
    active = sum(value > 0 for value in counts)
    streak = 0
    for value in reversed(counts):
        if value == 0:
            break
        streak += 1
    peak_index = max(range(30), key=counts.__getitem__)
    peak_date = (start + timedelta(days=peak_index)).isoformat()
    end = (start + timedelta(days=29)).isoformat()
    viewbox = "0 0 640 425" if layout == "wide" else "0 0 320 500"
    return (
        f'<svg viewBox="{viewbox}" data-evidence-window-clarity="{PREVIOUS}" '
        'data-profile-visible-contributions="5728" data-profile-period-from="2025-08-31" '
        'data-profile-period-to="2026-09-04" data-activity-from="2026-08-06" '
        f'data-activity-to="{end}" data-active-days="{active}" data-current-streak="{streak}" '
        f'data-peak-count="{counts[peak_index]}" data-peak-date="{peak_date}" '
        'data-source="github-graphql-contribution-calendar" data-metric-sources="github-graphql+rest" '
        'data-issues-metric-source="github-rest-search-authored-public-issues" '
        'data-intensity-scale="github-contribution-levels-0-4" '
        'data-count-semantics="raw-github-contribution-counts" data-window-timezone="UTC">'
        '<desc>fixture.</desc>'
        '<text data-metric-phosphor="contributions">5,728</text>'
        '<text data-metric-phosphor="stars">14</text>'
        '<text data-metric-phosphor="pull_requests">502</text>'
        '<text data-metric-phosphor="issues">51</text>'
        + "".join(days) + '</svg>'
    )


def self_test() -> None:
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        for filename in EXPECTED_FILES:
            layout = "wide" if "-wide-" in filename else "compact"
            scheme = "dark" if filename.endswith("-dark.svg") else "light"
            (directory / filename).write_text(fixture(layout, scheme), encoding="utf-8")
        evidence_id, digest = apply(directory)
        if not re.fullmatch(r"SF1-[0-9A-F]{16}", evidence_id):
            raise AssertionError("Evidence ID format changed")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
            raise AssertionError("Evidence digest format changed")
        for filename in EXPECTED_FILES:
            path = directory / filename
            text = path.read_text(encoding="utf-8")
            validate_stamped(text, path, evidence_id, digest)
        print(f"Signal Field Evidence ID self-test passed: {VERSION} · {evidence_id}")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError("usage: identify-signal-field-evidence.py <generated-directory> | --self-test")
        evidence_id, digest = apply(Path(sys.argv[1]))
        print(f"Signal Field evidence identity: {evidence_id} · {digest}")
        return 0
    except (OSError, ValueError, AssertionError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
