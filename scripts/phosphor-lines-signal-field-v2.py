#!/usr/bin/env python3
"""Apply Signal Field v2.8 metric-line phosphor colors, header ambience, and refresh provenance.

Each headline metric already receives a reviewed phosphorescent value color in v2.6.
This deterministic final presentation pass applies the same token to the horizontal
accent associated with that metric, adds a second faint evidence-topology treatment
behind the top header band, and updates refresh provenance to the workflow's
five-minute schedule. Metric data and established layout geometry remain unchanged.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

PHOSPHOR_ID = "signal-field-v2.8"
HEADER_AMBIENT_ID = "signal-field-v2.8-header"
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
        "contributions": "#00FBCC",
        "stars": "#C96BFF",
        "pull_requests": "#8C7CFF",
        "issues": "#28D7FF",
    },
    "light": {
        "contributions": "#008F72",
        "stars": "#7E22CE",
        "pull_requests": "#5B4FE6",
        "issues": "#007EA8",
    },
}
HEADER_COLORS = {
    "dark": {
        "green": "#00FBCC",
        "magenta": "#FF4DE1",
        "violet": "#8C7CFF",
        "cyan": "#28D7FF",
    },
    "light": {
        "green": "#008F72",
        "magenta": "#C800A8",
        "violet": "#5B4FE6",
        "cyan": "#007EA8",
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


def render_header_ambient(layout: str, scheme: str) -> str:
    palette = HEADER_COLORS[scheme]
    if layout == "wide":
        return (
            f'<g data-header-ambient="{HEADER_AMBIENT_ID}" '
            f'data-header-ambient-layout="wide" pointer-events="none">'
            f'<path d="M-18 58 C64 17 134 18 202 43 S344 64 410 26 S548 8 660 47" '
            f'fill="none" stroke="{palette["green"]}" stroke-width="0.8" opacity="0.070" '
            f'stroke-linecap="round" data-header-trace="flow"/>'
            f'<path d="M18 48 H92 L114 32 H194 L218 51 H316 L342 18 H431 L458 39 H548 L574 22 H626" '
            f'fill="none" stroke="{palette["violet"]}" stroke-width="0.75" opacity="0.060" '
            f'stroke-linecap="round" stroke-linejoin="round" data-header-trace="circuit"/>'
            f'<path d="M72 12 C132 32 192 2 252 23 S374 48 436 19 S552 4 622 28" '
            f'fill="none" stroke="{palette["magenta"]}" stroke-width="0.65" opacity="0.055" '
            f'stroke-linecap="round" data-header-trace="orbit"/>'
            f'<circle cx="114" cy="32" r="2" fill="{palette["green"]}" opacity="0.14" data-header-node="a"/>'
            f'<circle cx="114" cy="32" r="6" fill="none" stroke="{palette["green"]}" stroke-width="0.6" opacity="0.045"/>'
            f'<circle cx="342" cy="18" r="1.8" fill="{palette["violet"]}" opacity="0.13" data-header-node="b"/>'
            f'<circle cx="342" cy="18" r="5.6" fill="none" stroke="{palette["violet"]}" stroke-width="0.55" opacity="0.042"/>'
            f'<circle cx="458" cy="39" r="1.7" fill="{palette["magenta"]}" opacity="0.12" data-header-node="c"/>'
            f'<circle cx="574" cy="22" r="1.9" fill="{palette["cyan"]}" opacity="0.13" data-header-node="d"/>'
            f'<circle cx="574" cy="22" r="5.8" fill="none" stroke="{palette["cyan"]}" stroke-width="0.55" opacity="0.043"/>'
            f'</g>'
        )
    if layout == "compact":
        return (
            f'<g data-header-ambient="{HEADER_AMBIENT_ID}" '
            f'data-header-ambient-layout="compact" pointer-events="none">'
            f'<path d="M-12 66 C34 24 78 19 112 43 S190 67 226 31 S286 15 334 49" '
            f'fill="none" stroke="{palette["green"]}" stroke-width="0.75" opacity="0.068" '
            f'stroke-linecap="round" data-header-trace="flow"/>'
            f'<path d="M10 52 H47 L60 36 H103 L118 55 H168 L184 23 H229 L244 42 H286 L299 28 H316" '
            f'fill="none" stroke="{palette["violet"]}" stroke-width="0.7" opacity="0.058" '
            f'stroke-linecap="round" stroke-linejoin="round" data-header-trace="circuit"/>'
            f'<path d="M30 14 C64 31 96 5 132 24 S202 46 236 21 S290 7 322 31" '
            f'fill="none" stroke="{palette["magenta"]}" stroke-width="0.6" opacity="0.052" '
            f'stroke-linecap="round" data-header-trace="orbit"/>'
            f'<circle cx="60" cy="36" r="1.7" fill="{palette["green"]}" opacity="0.14" data-header-node="a"/>'
            f'<circle cx="60" cy="36" r="5" fill="none" stroke="{palette["green"]}" stroke-width="0.55" opacity="0.044"/>'
            f'<circle cx="184" cy="23" r="1.55" fill="{palette["violet"]}" opacity="0.13" data-header-node="b"/>'
            f'<circle cx="244" cy="42" r="1.5" fill="{palette["magenta"]}" opacity="0.12" data-header-node="c"/>'
            f'<circle cx="299" cy="28" r="1.65" fill="{palette["cyan"]}" opacity="0.13" data-header-node="d"/>'
            f'<circle cx="299" cy="28" r="5" fill="none" stroke="{palette["cyan"]}" stroke-width="0.55" opacity="0.043"/>'
            f'</g>'
        )
    raise ValueError(f"unsupported layout: {layout}")


def add_header_ambient(text: str, layout: str, scheme: str) -> str:
    if f'data-header-ambient="{HEADER_AMBIENT_ID}"' in text:
        raise ValueError("Signal Field unexpectedly already contains v2.8 header ambience")
    anchor = "</defs>"
    if text.count(anchor) != 1:
        raise ValueError("expected exactly one defs block for header ambience placement")
    return text.replace(anchor, anchor + render_header_ambient(layout, scheme), 1)


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
    text = add_header_ambient(text, layout, scheme)
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

    if text.count(f'data-header-ambient="{HEADER_AMBIENT_ID}"') != 1:
        raise ValueError("v2.8 header ambience provenance is missing or duplicated")
    if text.count(f'data-header-ambient-layout="{layout}"') != 1:
        raise ValueError("v2.8 header ambience layout provenance is incorrect")
    if text.count('data-header-trace="') != 3:
        raise ValueError("v2.8 header ambience must retain exactly three faint topology traces")
    if text.count('data-header-node="') != 4:
        raise ValueError("v2.8 header ambience must retain exactly four evidence nodes")

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
        print(f"metric-line/header phosphor themed {filename} -> {PHOSPHOR_ID}")


def fixture(layout: str, scheme: str) -> str:
    hairline = "#28324A" if scheme == "dark" else "#D9DFF0"
    accent = "#FF2BD6"
    if layout == "wide":
        lines = (
            f'<rect x="30" y="132" width="20" height="2" fill="{accent}"/>'
            f'<path d="M284 73h86" stroke="{hairline}"/>'
            f'<path d="M390 73h86" stroke="{hairline}"/>'
            f'<path d="M524 73h86" stroke="{hairline}"/>'
        )
        geometry = 'viewBox="0 0 640 425" width="640" height="425"'
    else:
        lines = (
            f'<rect x="150" y="141" width="20" height="2" fill="{accent}"/>'
            f'<path d="M24 173h84" stroke="{hairline}"/>'
            f'<path d="M118 173h84" stroke="{hairline}"/>'
            f'<path d="M212 173h84" stroke="{hairline}"/>'
        )
        geometry = 'viewBox="0 0 320 500" width="320" height="500"'
    surface = "#0B1020" if scheme == "dark" else "#FFFFFF"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" {geometry} data-refresh-cadence="daily">'
        '<desc>Fixture. Refresh cadence: daily.</desc>'
        f'<rect width="100%" height="100%" fill="{surface}"/><defs></defs>'
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
            assert f'data-header-ambient="{HEADER_AMBIENT_ID}"' in themed
            assert themed.count('data-header-node="') == 4
    print(
        f"Signal Field metric-line/header phosphor self-test passed: {PHOSPHOR_ID}; "
        f"refresh={REFRESH_DESCRIPTION}; header={HEADER_AMBIENT_ID}"
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
