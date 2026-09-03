#!/usr/bin/env python3
"""Apply Signal Field v2.6 phosphorescent headline metric colors.

Each headline value receives a distinct high-energy color while labels and all
underlying metric data remain unchanged. Wide and compact layouts are both themed;
layout/alignment is not modified here.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

PHOSPHOR_ID = "signal-field-v2.6"
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

WIDE_TARGETS = {
    "contributions": re.compile(r'<text x="30" y="109"[^>]*>[^<]+</text>', re.I),
    "stars": re.compile(r'<text x="284" y="108"[^>]*>[^<]+</text>', re.I),
    "pull_requests": re.compile(r'<text x="390" y="108"[^>]*>[^<]+</text>', re.I),
    "issues": re.compile(r'<text x="610" y="108"[^>]*>[^<]+</text>', re.I),
}
COMPACT_TARGETS = {
    "contributions": re.compile(r'<text x="160" y="124"[^>]*>[^<]+</text>', re.I),
    "stars": re.compile(r'<text x="66" y="206"[^>]*>[^<]+</text>', re.I),
    "pull_requests": re.compile(r'<text x="160" y="206"[^>]*>[^<]+</text>', re.I),
    "issues": re.compile(r'<text x="254" y="206"[^>]*>[^<]+</text>', re.I),
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
    index = element.find(">")
    if index < 0:
        raise ValueError(f"cannot add attribute {name!r} to malformed element")
    return element[:index] + f' {replacement}' + element[index:]


def add_provenance(text: str) -> str:
    match = SVG_OPEN.search(text)
    if not match:
        raise ValueError("SVG root element is missing")
    if "data-metric-phosphor=" in match.group(0):
        raise ValueError("Signal Field unexpectedly already contains v2.6 provenance")
    attrs = match.group(1)
    replacement = f'<svg{attrs} data-metric-phosphor="{PHOSPHOR_ID}">'
    return text[:match.start()] + replacement + text[match.end():]


def color_metrics(text: str, layout: str, scheme: str) -> str:
    targets = WIDE_TARGETS if layout == "wide" else COMPACT_TARGETS
    palette = COLORS[scheme]

    for metric, pattern in targets.items():
        matches = pattern.findall(text)
        if len(matches) != 1:
            raise ValueError(
                f"expected one {layout} {metric} headline value, found {len(matches)}"
            )
        original = matches[0]
        colored = set_attr(original, "fill", palette[metric])
        colored = set_attr(colored, "data-metric-phosphor", metric)
        text = text.replace(original, colored, 1)

    text = add_provenance(text)
    validate(text, layout, scheme)
    return text


def validate(text: str, layout: str, scheme: str) -> None:
    if f'data-metric-phosphor="{PHOSPHOR_ID}"' not in text:
        raise ValueError("v2.6 root provenance is missing")
    targets = WIDE_TARGETS if layout == "wide" else COMPACT_TARGETS
    palette = COLORS[scheme]
    for metric, pattern in targets.items():
        matches = pattern.findall(text)
        if len(matches) != 1:
            raise ValueError(f"{metric} headline value disappeared after v2.6")
        attrs = dict(ATTR.findall(matches[0]))
        if attrs.get("fill") != palette[metric]:
            raise ValueError(f"{metric} does not use its reviewed phosphor color")
        if attrs.get("data-metric-phosphor") != metric:
            raise ValueError(f"{metric} phosphor provenance is missing")

    if len(set(palette.values())) != 4:
        raise ValueError("headline metric phosphor colors must remain distinct")


def apply_directory(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        layout = layout_for(path)
        scheme = scheme_for(path)
        themed = color_metrics(path.read_text(encoding="utf-8"), layout, scheme)
        path.write_text(themed, encoding="utf-8")
        print(f"phosphor themed {filename} -> {PHOSPHOR_ID}")


def fixture(layout: str, scheme: str) -> str:
    fill = "#F8FAFC" if scheme == "dark" else "#111827"
    if layout == "wide":
        body = (
            f'<text x="30" y="109" fill="{fill}">4559</text>'
            f'<text x="284" y="108" fill="{fill}">12</text>'
            f'<text x="390" y="108" fill="{fill}">445</text>'
            f'<text x="610" y="108" text-anchor="end" fill="{fill}">32</text>'
        )
    else:
        body = (
            f'<text x="160" y="124" fill="{fill}">4559</text>'
            f'<text x="66" y="206" fill="{fill}">12</text>'
            f'<text x="160" y="206" fill="{fill}">445</text>'
            f'<text x="254" y="206" fill="{fill}">32</text>'
        )
    return f'<svg xmlns="http://www.w3.org/2000/svg">{body}</svg>'


def self_test() -> None:
    for scheme in COLORS:
        for layout in ("wide", "compact"):
            themed = color_metrics(fixture(layout, scheme), layout, scheme)
            validate(themed, layout, scheme)
            for metric, color in COLORS[scheme].items():
                assert color in themed
                assert f'data-metric-phosphor="{metric}"' in themed
    print(f"Signal Field phosphor self-test passed: {PHOSPHOR_ID}")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError(
                "usage: phosphor-signal-field-v2.py <generated-directory> | --self-test"
            )
        apply_directory(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
