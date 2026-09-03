#!/usr/bin/env python3
"""Apply Signal Field v2.7 phosphorescent activity telemetry colors.

The rolling activity summary is rendered as neutral text by the v2 base layer.
This deterministic post-processing step keeps every metric value and layout intact
while splitting the summary into colored SVG tspans. The palette deliberately
reuses the reviewed v2.6 phosphorescent metric colors so headline metrics and
activity telemetry read as one visual system.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

PHOSPHOR_ID = "signal-field-v2.7"
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)

COLORS = {
    "dark": {
        "active": "#FF4DE1",
        "streak": "#C96BFF",
        "peak_date": "#8C7CFF",
        "peak_count": "#28D7FF",
    },
    "light": {
        "active": "#C800A8",
        "streak": "#7E22CE",
        "peak_date": "#5B4FE6",
        "peak_count": "#007EA8",
    },
}

SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
PLAIN_SUMMARY = re.compile(
    r'<text\b(?=[^>]*\bdata-activity-summary="true")[^>]*>[^<]+</text>',
    re.I,
)
COLORED_SUMMARY = re.compile(
    r'<text\b(?=[^>]*\bdata-activity-summary="true")'
    r'(?=[^>]*\bdata-activity-summary-phosphor="true")[^>]*>.*?</text>',
    re.I | re.S,
)
WIDE_CONTENT = re.compile(
    r"^ACTIVE (?P<active>\d+)/30 · STREAK (?P<streak>\d+) · "
    r"PEAK (?P<peak_date>[A-Z]{3} \d{2}) · (?P<peak_count>\d+)$"
)
COMPACT_CONTENT = re.compile(
    r"^ACTIVE (?P<active>\d+)/30 · STREAK (?P<streak>\d+) · "
    r"PEAK (?P<peak_count>\d+)$"
)


def scheme_for(path: Path) -> str:
    if path.name.endswith("-light.svg"):
        return "light"
    if path.name.endswith("-dark.svg"):
        return "dark"
    raise ValueError(f"unsupported Signal Field filename: {path.name}")


def layout_for(path: Path) -> str:
    if "-wide-" in path.name:
        return "wide"
    if "-compact-" in path.name:
        return "compact"
    raise ValueError(f"unsupported Signal Field layout: {path.name}")


def set_attr(element: str, name: str, value: str) -> str:
    pattern = re.compile(rf'\b{re.escape(name)}="[^"]*"')
    replacement = f'{name}="{value}"'
    if pattern.search(element):
        return pattern.sub(replacement, element, count=1)
    index = element.find(">")
    if index < 0:
        raise ValueError(f"cannot add attribute {name!r} to malformed element")
    return element[:index] + f' {replacement}' + element[index:]


def add_provenance(text: str) -> str:
    match = SVG_OPEN.search(text)
    if not match:
        raise ValueError("SVG root element is missing")
    if "data-activity-phosphor=" in match.group(0):
        raise ValueError("Signal Field unexpectedly already contains v2.7 provenance")
    attrs = match.group(1)
    replacement = f'<svg{attrs} data-activity-phosphor="{PHOSPHOR_ID}">'
    return text[:match.start()] + replacement + text[match.end():]


def summary_content(element: str) -> str:
    start = element.find(">")
    end = element.rfind("</text>")
    if start < 0 or end < 0 or end <= start:
        raise ValueError("activity summary text element is malformed")
    return element[start + 1 : end]


def tspan(label: str, color: str, token: str) -> str:
    return (
        f'<tspan fill="{color}" data-telemetry-phosphor="{token}">'
        f'{label}</tspan>'
    )


def separator() -> str:
    return '<tspan data-telemetry-separator="true"> · </tspan>'


def render_colored_summary(element: str, layout: str, scheme: str) -> str:
    content = summary_content(element)
    palette = COLORS[scheme]
    if layout == "wide":
        match = WIDE_CONTENT.fullmatch(content)
        if not match:
            raise ValueError(f"unexpected wide activity summary: {content!r}")
        parts = (
            tspan(f'ACTIVE {match.group("active")}/30', palette["active"], "active"),
            separator(),
            tspan(f'STREAK {match.group("streak")}', palette["streak"], "streak"),
            separator(),
            tspan(
                f'PEAK {match.group("peak_date")}',
                palette["peak_date"],
                "peak_date",
            ),
            separator(),
            tspan(match.group("peak_count"), palette["peak_count"], "peak_count"),
        )
    elif layout == "compact":
        match = COMPACT_CONTENT.fullmatch(content)
        if not match:
            raise ValueError(f"unexpected compact activity summary: {content!r}")
        parts = (
            tspan(f'ACTIVE {match.group("active")}/30', palette["active"], "active"),
            separator(),
            tspan(f'STREAK {match.group("streak")}', palette["streak"], "streak"),
            separator(),
            tspan(f'PEAK {match.group("peak_count")}', palette["peak_count"], "peak_count"),
        )
    else:
        raise ValueError(f"unsupported layout: {layout}")

    opening_end = element.find(">")
    opening = set_attr(element[: opening_end + 1], "data-activity-summary-phosphor", "true")
    return opening + "".join(parts) + "</text>"


def color_activity_summary(text: str, layout: str, scheme: str) -> str:
    matches = PLAIN_SUMMARY.findall(text)
    if len(matches) != 1:
        raise ValueError(
            f"expected one plain {layout} activity summary before v2.7, found {len(matches)}"
        )
    original = matches[0]
    colored = render_colored_summary(original, layout, scheme)
    text = text.replace(original, colored, 1)
    text = add_provenance(text)
    validate(text, layout, scheme)
    return text


def validate(text: str, layout: str, scheme: str) -> None:
    if f'data-activity-phosphor="{PHOSPHOR_ID}"' not in text:
        raise ValueError("v2.7 activity phosphor root provenance is missing")

    summaries = COLORED_SUMMARY.findall(text)
    if len(summaries) != 1:
        raise ValueError(f"expected one colored {layout} activity summary, found {len(summaries)}")
    summary = summaries[0]
    palette = COLORS[scheme]
    content_patterns = {
        "active": r"ACTIVE \d+/30",
        "streak": r"STREAK \d+",
        "peak_count": r"PEAK \d+",
    }
    if layout == "wide":
        content_patterns = {
            "active": r"ACTIVE \d+/30",
            "streak": r"STREAK \d+",
            "peak_date": r"PEAK [A-Z]{3} \d{2}",
            "peak_count": r"\d+",
        }

    for token, content_pattern in content_patterns.items():
        pattern = re.compile(
            rf'<tspan\b(?=[^>]*\bfill="{re.escape(palette[token])}")'
            rf'(?=[^>]*\bdata-telemetry-phosphor="{token}")[^>]*>'
            rf'{content_pattern}</tspan>',
            re.I,
        )
        if len(pattern.findall(summary)) != 1:
            raise ValueError(f"{layout} telemetry token {token!r} is not correctly phosphor themed")

    separator_count = summary.count('data-telemetry-separator="true"')
    expected_separator_count = 3 if layout == "wide" else 2
    if separator_count != expected_separator_count:
        raise ValueError(
            f"{layout} telemetry must retain {expected_separator_count} neutral separators"
        )


def apply_directory(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        layout = layout_for(path)
        scheme = scheme_for(path)
        themed = color_activity_summary(path.read_text(encoding="utf-8"), layout, scheme)
        path.write_text(themed, encoding="utf-8")
        print(f"activity phosphor themed {filename} -> {PHOSPHOR_ID}")


def fixture(layout: str, scheme: str) -> str:
    fill = "#A7B0C4" if scheme == "dark" else "#5B6475"
    if layout == "wide":
        content = "ACTIVE 26/30 · STREAK 16 · PEAK SEP 02 · 674"
        summary = (
            f'<text x="30" y="199" fill="{fill}" font-size="9" font-weight="600" '
            f'data-activity-summary="true">{content}</text>'
        )
    else:
        content = "ACTIVE 26/30 · STREAK 16 · PEAK 674"
        summary = (
            f'<text x="22" y="285" fill="{fill}" font-size="7.5" font-weight="600" '
            f'data-activity-summary="true">{content}</text>'
        )
    return f'<svg xmlns="http://www.w3.org/2000/svg">{summary}</svg>'


def self_test() -> None:
    for scheme in COLORS:
        for layout in ("wide", "compact"):
            themed = color_activity_summary(fixture(layout, scheme), layout, scheme)
            validate(themed, layout, scheme)
            assert f'data-activity-phosphor="{PHOSPHOR_ID}"' in themed
            assert 'data-activity-summary-phosphor="true"' in themed
            if layout == "wide":
                assert "PEAK SEP 02" in themed
                assert ">674</tspan>" in themed
            else:
                assert "PEAK 674" in themed
    print(f"Signal Field activity phosphor self-test passed: {PHOSPHOR_ID}")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError(
                "usage: phosphor-activity-signal-field-v2.py <generated-directory> | --self-test"
            )
        apply_directory(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
