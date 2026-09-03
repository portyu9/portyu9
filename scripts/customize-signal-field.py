#!/usr/bin/env python3
"""Apply the Ƴunior Ƥortal neon theme to pinned Signal Field SVG output.

The upstream generator is pinned in profile-stats.yml. This post-processor treats
its published palette as an input contract: unknown source colors fail the run
instead of producing a partially customized artifact.
"""

from __future__ import annotations

from pathlib import Path
import re
import sys

THEME_ID = "yunior-portal-neon-v1"
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)

# shinpr/github-profile-stats@49b5f7091182a45f3ef93923505b660c6da5f835 (v0.2.0)
SOURCE_PALETTES = {
    "light": {
        "#FCFAF5": "#FFFFFF",  # surface
        "#17171B": "#111827",  # primary text
        "#5E5B63": "#5B6475",  # secondary text
        "#D8D2C7": "#D9DFF0",  # hairline
        "#DE4F44": "#FF2BD6",  # accent / rail 1
        "#918A21": "#A020F0",  # rail 2
        "#1D97A3": "#7A5CFF",  # rail 3
        "#906AE5": "#00AEEF",  # rail 4
        "#E7E1D7": "#EEF2FF",  # activity 0
        "#7967C9": "#E879F9",  # activity 1
        "#654FC2": "#C026D3",  # activity 2
        "#5036AA": "#7A5CFF",  # activity 3
        "#382077": "#00AEEF",  # activity 4
    },
    "dark": {
        "#151821": "#0B1020",  # surface
        "#F7F3EA": "#F8FAFC",  # primary text
        "#AAA8B4": "#A7B0C4",  # secondary text
        "#303543": "#28324A",  # hairline
        "#F9786A": "#FF2BD6",  # accent / rail 1
        "#B0A946": "#A020F0",  # rail 2
        "#48B7C2": "#7A5CFF",  # rail 3
        "#AB91F2": "#00AEEF",  # rail 4
        "#262A35": "#171D2D",  # activity 0
        "#7768C7": "#D946EF",  # activity 1
        "#927EE7": "#A020F0",  # activity 2
        "#B29AFF": "#7A5CFF",  # activity 3
        "#D5C5FF": "#00AEEF",  # activity 4
    },
}

HEX_COLOR = re.compile(r"#[0-9A-Fa-f]{6}\b")
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)


def scheme_for(path: Path) -> str:
    if path.name.endswith("-light.svg"):
        return "light"
    if path.name.endswith("-dark.svg"):
        return "dark"
    raise ValueError(f"unsupported Signal Field filename: {path.name}")


def customize_svg(text: str, scheme: str) -> str:
    palette = SOURCE_PALETTES[scheme]
    observed = {color.upper() for color in HEX_COLOR.findall(text)}
    allowed = {color.upper() for color in palette}
    unknown = sorted(observed - allowed)
    if unknown:
        raise ValueError(
            "upstream Signal Field palette changed; refusing partial customization: "
            + ", ".join(unknown)
        )

    if "data-period-days=" not in text or "<title" not in text or "<desc" not in text:
        raise ValueError("Signal Field structural signature is missing")

    themed = text
    for source, target in palette.items():
        themed = themed.replace(source, target)

    if THEME_ID not in themed:
        match = SVG_OPEN.search(themed)
        if not match:
            raise ValueError("SVG root element is missing")
        attrs = match.group(1)
        replacement = f'<svg{attrs} data-theme="{THEME_ID}">'
        themed = themed[: match.start()] + replacement + themed[match.end() :]

    remaining = sorted({color.upper() for color in HEX_COLOR.findall(themed)} & allowed)
    if remaining:
        raise ValueError("source palette colors remain after customization: " + ", ".join(remaining))

    required_theme_colors = {"#FF2BD6", "#A020F0", "#7A5CFF", "#00AEEF"}
    themed_colors = {color.upper() for color in HEX_COLOR.findall(themed)}
    if not required_theme_colors.issubset(themed_colors):
        raise ValueError("customized SVG is missing one or more canonical profile theme colors")

    return themed


def customize_directory(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        scheme = scheme_for(path)
        original = path.read_text(encoding="utf-8")
        themed = customize_svg(original, scheme)
        path.write_text(themed, encoding="utf-8")
        print(f"themed {filename} -> {THEME_ID}")


def self_test() -> None:
    for scheme, palette in SOURCE_PALETTES.items():
        colors = "".join(f'<rect fill="{color}"/>' for color in palette)
        sample = (
            '<svg xmlns="http://www.w3.org/2000/svg" data-period-days="365">'
            f'<title>{scheme}</title><desc>fixture</desc>{colors}</svg>'
        )
        themed = customize_svg(sample, scheme)
        assert f'data-theme="{THEME_ID}"' in themed
        assert not ({color.upper() for color in palette} & {c.upper() for c in HEX_COLOR.findall(themed)})
    print(f"Signal Field customization self-test passed: {THEME_ID}")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError("usage: customize-signal-field.py <generated-directory> | --self-test")
        customize_directory(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
