#!/usr/bin/env python3
"""Apply Signal Field v2.8 metric-line phosphor colors and refresh provenance.

Each headline metric already receives a reviewed phosphorescent value color in v2.6.
This deterministic post-processing step applies the same token to the horizontal
accent associated with that metric, without changing geometry or metric data.
It also updates the generated SVG refresh provenance to match the workflow's
five-minute schedule.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

PHOSPHOR_ID = "signal-field-v2.8"
REFRESH_CADENCE = "5-minutes"
REFRESH_DESCRIPTION = "every 5 minutes"
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)

COLORS = {
    "dark": {
        "contributions": "#FF4DE1",
        "stars": "#C96BFF",
        "pull_requests": "#8C7CFF",
        "issues": "#28D7FF",
    },
    "light": {
        "contributions": "#C800A8",
        "stars": "#7E22CE",
        "pull_requests": "#5B4FE6",
        "issues": "#007EA8",
    },
}

SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')

WIDE_LINES = {
    "contributions": re.compile(
        r'<rect x="30" y="132" width="20" height="2"[^>]*/>', re.I
    ),
    "stars": re.compile(r'<path d="M284 73h86"[^>]*/>', re.I),
    "pull_requests": re.compile(r'<path d="M390 73h86"[^>]*/>', re.I),
    "issues": re.compile(r'<path d="M524 73h86"[^>]*/>', re.I),
}
COMPACT_LINES = {
    "contributions": re.compile(
        r'<rect x="150" y="141" width="20" height="2"[^>]*/>', re.I
    ),
    "stars": re.compile(r'<path d="M24 173h84"[^>]*/>', re.I),
    "pull_requests": re.compile(r'<path d="M118 173h84"[^>]*/>', re.I),
    "issues": re.compile(r'<path d="M212 173h84"[^>]*/>', re.I),
}


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
    index = element.find("/>")
    if index < 0:
        index = element.find(">")
    if index < 0:
        raise ValueError(f"cannot add attribute {name!r} to malformed element")
    return element[:index].rstrip() + f' {replacement}' + element[index:]


def add_provenance(text: str) -> str:
    match = SVG_OPEN.search(text)
    if not match:
        raise ValueError("SVG root element is missing")
    if "data-line-phosphor=" in match.group(0):
        raise ValueError("Signal Field unexpectedly already contains v2.8 provenance")
    attrs = match.group(1)
    replacement = f'<svg{attrs} data-line-phosphor="{PHOSPHOR_ID}">'
    return text[: match.start()] + replacement + text[match.end() :]


def update_refresh_provenance(text: str) -> str:
    old_attr = 'data-refresh-cadence="daily"'
    if text.count(old_attr) != 1:
        raise ValueError("expected exactly one upstream daily refresh provenance attribute")
    text = text.replace(
        old_attr,
        f'data-refresh-cadence="{REFRESH_CADENCE}"',
        1,
    )

    old_desc = "Refresh cadence: daily."
    if text.count(old_desc) != 1:
        raise ValueError("expected exactly one upstream daily refresh description")
    return text.replace(
        old_desc,
        f"Refresh cadence: {REFRESH_DESCRIPTION}.",
        1,
    )


def color_metric_lines(text: str, layout: str, scheme: str) -> str:
    lines = WIDE_LINES if layout == "wide" else COMPACT_LINES
    palette = COLORS[scheme]

    for metric, pattern in lines.items():
        matches = pattern.findall(text)
        if len(matches) != 1:
            raise ValueError(
                f"expected one {layout} {metric} metric accent line, found {len(matches)}"
            )
        original = matches[0]
        color_attr = "fill" if metric == "contributions" else "stroke"
        colored = set_attr(original, color_attr, palette[metric])
        colored = set_attr(colored, "data-metric-phosphor-line", metric)
        text = text.replace(original, colored, 1)

    text = update_refresh_provenance(text)
    text = add_provenance(text)
    validate(text, layout, scheme)
    return text


def validate(text: str, layout: str, scheme: str) -> None:
    if f'data-line-phosphor="{PHOSPHOR_ID}"' not in text:
        raise ValueError("v2.8 root provenance is missing")
    if f'data-refresh-cadence="{REFRESH_CADENCE}"' not in text:
        raise ValueError("five-minute refresh provenance is missing")
    if f"Refresh cadence: {REFRESH_DESCRIPTION}." not in text:
        raise ValueError("five-minute refresh description is missing")
    if 'data-refresh-cadence="daily"' in text or "Refresh cadence: daily." in text:
        raise ValueError("stale daily refresh provenance remains")

    lines = WIDE_LINES if layout == "wide" else COMPACT_LINES
    palette = COLORS[scheme]
    for metric, pattern in lines.items():
        matches = pattern.findall(text)
        if len(matches) != 1:
            raise ValueError(f"{metric} accent line disappeared after v2.8")
        attrs = dict(ATTR.findall(matches[0]))
        color_attr = "fill" if metric == "contributions" else "stroke"
        if attrs.get(color_attr) != palette[metric]:
            raise ValueError(
                f"{metric} accent line does not match its reviewed phosphor value color"
            )
        if attrs.get("data-metric-phosphor-line") != metric:
            raise ValueError(f"{metric} line phosphor provenance is missing")


def apply_directory(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        layout = layout_for(path)
        scheme = scheme_for(path)
        themed = color_metric_lines(path.read_text(encoding="utf-8"), layout, scheme)
        path.write_text(themed, encoding="utf-8")
        print(f"metric-line phosphor themed {filename} -> {PHOSPHOR_ID}")


def fixture(layout: str, scheme: str) -> str:
    hairline = "#28324A" if scheme == "dark" else "#D9DFF0"
    accent = "#FF2BD6" if scheme == "dark" else "#FF2BD6"
    if layout == "wide":
        lines = (
            f'<rect x="30" y="132" width="20" height="2" fill="{accent}"/>'
            f'<path d="M284 73h86" stroke="{hairline}"/>'
            f'<path d="M390 73h86" stroke="{hairline}"/>'
            f'<path d="M524 73h86" stroke="{hairline}"/>'
        )
    else:
        lines = (
            f'<rect x="150" y="141" width="20" height="2" fill="{accent}"/>'
            f'<path d="M24 173h84" stroke="{hairline}"/>'
            f'<path d="M118 173h84" stroke="{hairline}"/>'
            f'<path d="M212 173h84" stroke="{hairline}"/>'
        )
    return (
        '<svg xmlns="http://www.w3.org/2000/svg" data-refresh-cadence="daily">'
        '<desc>Fixture. Refresh cadence: daily.</desc>'
        f"{lines}</svg>"
    )


def self_test() -> None:
    for scheme in COLORS:
        for layout in ("wide", "compact"):
            themed = color_metric_lines(fixture(layout, scheme), layout, scheme)
            validate(themed, layout, scheme)
            for metric, color in COLORS[scheme].items():
                assert color in themed
                assert f'data-metric-phosphor-line="{metric}"' in themed
            assert f'data-refresh-cadence="{REFRESH_CADENCE}"' in themed
            assert f"Refresh cadence: {REFRESH_DESCRIPTION}." in themed
    print(
        f"Signal Field metric-line phosphor self-test passed: {PHOSPHOR_ID}; "
        f"refresh={REFRESH_DESCRIPTION}"
    )


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError(
                "usage: phosphor-lines-signal-field-v2.py <generated-directory> | --self-test"
            )
        apply_directory(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
