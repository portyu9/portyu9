#!/usr/bin/env python3
"""Apply the Ƴunior Ƥortal theme and 30-day activity view to Signal Field SVGs.

The upstream generator remains pinned and continues to collect the complete
365/366-day contribution dataset used by its headline metric. This deterministic
presentation layer changes only the rendered daily-activity field to the newest
30 dated records, while preserving the upstream metric values and provenance.

The published upstream palette and activity-cell structure are treated as an
input contract. Any unexpected palette, missing dates, duplicate dates, or
non-consecutive activity series fails closed instead of publishing a partially
customized card.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
import re
import sys

THEME_ID = "yunior-portal-neon-v1"
ACTIVITY_WINDOW_DAYS = 30
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
ACTIVITY_CELL = re.compile(r"<rect\b[^>]*\bdata-date=\"\d{4}-\d{2}-\d{2}\"[^>]*/>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
ACCESSIBLE_ACTIVITY = re.compile(
    r"(?:365|366) daily activity marks from (\d{4}-\d{2}-\d{2}) through "
    r"(\d{4}-\d{2}-\d{2}), inclusive\."
)
COMPACT_BAND_LABEL = re.compile(
    r'<text x="22" y="(?:291|397)"[^>]*>[A-Z]{3} \d{2} — [A-Z]{3} \d{2}</text>'
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


def parse_activity_cells(text: str) -> list[dict[str, str]]:
    cells: list[dict[str, str]] = []
    for match in ACTIVITY_CELL.finditer(text):
        attrs = dict(ATTR.findall(match.group(0)))
        required = {"fill", "data-date", "data-count", "data-level"}
        missing = sorted(required - attrs.keys())
        if missing:
            raise ValueError("activity cell is missing attributes: " + ", ".join(missing))
        cells.append(attrs)

    if len(cells) not in (365, 366):
        raise ValueError(f"expected 365 or 366 upstream activity cells, found {len(cells)}")

    dates = [date.fromisoformat(cell["data-date"]) for cell in cells]
    if len(set(dates)) != len(dates):
        raise ValueError("upstream activity dates contain duplicates")
    if dates != sorted(dates):
        raise ValueError("upstream activity dates are not chronological")
    for previous, current in zip(dates, dates[1:]):
        if current - previous != timedelta(days=1):
            raise ValueError("upstream activity dates are not consecutive")

    return cells


def render_activity_window(cells: list[dict[str, str]], layout: str) -> str:
    recent = cells[-ACTIVITY_WINDOW_DAYS:]
    rendered: list[str] = []

    if layout == "wide":
        # Two chronological rows of 15 large squares use the full visual field.
        columns, x0, y0, size, step_x, step_y = 15, 30, 199, 28, 39, 39
    elif layout == "compact":
        # Three chronological rows of 10 squares preserve compact readability.
        columns, x0, y0, size, step_x, step_y = 10, 22, 291, 22, 28, 32
    else:
        raise ValueError(f"unsupported layout: {layout}")

    for index, cell in enumerate(recent):
        row, column = divmod(index, columns)
        x = x0 + column * step_x
        y = y0 + row * step_y
        rendered.append(
            f'<rect x="{x}" y="{y}" width="{size}" height="{size}" rx="4" '
            f'fill="{cell["fill"]}" data-date="{cell["data-date"]}" '
            f'data-count="{cell["data-count"]}" data-level="{cell["data-level"]}" '
            f'data-window-day="{index + 1}"/>'
        )

    return "".join(rendered)


def apply_activity_window(text: str, layout: str) -> str:
    cells = parse_activity_cells(text)
    recent = cells[-ACTIVITY_WINDOW_DAYS:]
    from_date = recent[0]["data-date"]
    to_date = recent[-1]["data-date"]

    first = ACTIVITY_CELL.search(text)
    if not first:
        raise ValueError("Signal Field activity cells are missing")
    all_matches = list(ACTIVITY_CELL.finditer(text))
    start = all_matches[0].start()
    end = all_matches[-1].end()

    # The pinned renderer emits all activity rects contiguously in both layouts.
    between = text[start:end]
    if len(ACTIVITY_CELL.findall(between)) != len(cells):
        raise ValueError("activity-cell block is not contiguous")

    text = text[:start] + render_activity_window(cells, layout) + text[end:]

    if layout == "wide":
        old_label = "DAILY ACTIVITY · PAST YEAR"
        new_label = "DAILY ACTIVITY · LAST 30 DAYS"
    else:
        old_label = "DAILY ACTIVITY"
        new_label = "DAILY ACTIVITY · 30 DAYS"
        text = COMPACT_BAND_LABEL.sub("", text)

    if text.count(old_label) != 1:
        raise ValueError(f"expected exactly one activity label {old_label!r}")
    text = text.replace(old_label, new_label, 1)

    description_matches = list(ACCESSIBLE_ACTIVITY.finditer(text))
    if len(description_matches) != 1:
        raise ValueError("expected exactly one accessible annual activity description")
    text = ACCESSIBLE_ACTIVITY.sub(
        f"{ACTIVITY_WINDOW_DAYS} daily activity marks from {from_date} through {to_date}, inclusive.",
        text,
        count=1,
    )

    match = SVG_OPEN.search(text)
    if not match:
        raise ValueError("SVG root element is missing")
    attrs = match.group(1)
    if "data-activity-window-days=" in attrs:
        raise ValueError("upstream SVG unexpectedly defines an activity-window attribute")
    window_attrs = (
        f' data-activity-window-days="{ACTIVITY_WINDOW_DAYS}"'
        f' data-activity-from="{from_date}" data-activity-to="{to_date}"'
    )
    replacement = f"<svg{attrs}{window_attrs}>"
    return text[: match.start()] + replacement + text[match.end() :]


def customize_svg(text: str, scheme: str, layout: str) -> str:
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

    themed = apply_activity_window(text, layout)
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

    published_cells = ACTIVITY_CELL.findall(themed)
    if len(published_cells) != ACTIVITY_WINDOW_DAYS:
        raise ValueError(f"customized SVG must publish exactly {ACTIVITY_WINDOW_DAYS} activity cells")
    if f'data-activity-window-days="{ACTIVITY_WINDOW_DAYS}"' not in themed:
        raise ValueError("customized SVG is missing activity-window provenance")

    return themed


def customize_directory(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        scheme = scheme_for(path)
        layout = layout_for(path)
        original = path.read_text(encoding="utf-8")
        themed = customize_svg(original, scheme, layout)
        path.write_text(themed, encoding="utf-8")
        print(f"themed {filename} -> {THEME_ID}; activity window -> {ACTIVITY_WINDOW_DAYS} days")


def fixture_svg(scheme: str, layout: str) -> tuple[str, str, str]:
    palette = SOURCE_PALETTES[scheme]
    activity_colors = list(palette.keys())[-5:]
    start = date(2025, 9, 4)
    days = 365
    end = start + timedelta(days=days - 1)
    cells = []
    for index in range(days):
        current = start + timedelta(days=index)
        level = index % 5
        cells.append(
            f'<rect x="0" y="0" width="9" height="9" rx="2" fill="{activity_colors[level]}" '
            f'data-date="{current.isoformat()}" data-count="{index}" data-level="{level}"/>'
        )

    palette_fixture = "".join(f'<rect fill="{color}"/>' for color in palette)
    if layout == "wide":
        label = "DAILY ACTIVITY · PAST YEAR"
        band_labels = ""
        geometry = 'viewBox="0 0 640 360" width="640" height="360"'
    else:
        label = "DAILY ACTIVITY"
        band_labels = (
            '<text x="22" y="291" fill="#5E5B63">SEP 04 — MAR 04</text>'
            '<text x="22" y="397" fill="#5E5B63">MAR 05 — SEP 03</text>'
            if scheme == "light"
            else '<text x="22" y="291" fill="#AAA8B4">SEP 04 — MAR 04</text>'
                 '<text x="22" y="397" fill="#AAA8B4">MAR 05 — SEP 03</text>'
        )
        geometry = 'viewBox="0 0 320 528" width="320" height="528"'

    sample = (
        f'<svg xmlns="http://www.w3.org/2000/svg" {geometry} data-period-days="{days}">'
        f'<title>{scheme}-{layout}</title>'
        f'<desc>fixture; {days} daily activity marks from {start.isoformat()} through {end.isoformat()}, inclusive.</desc>'
        f'<text>{label}</text>{band_labels}{palette_fixture}{"".join(cells)}</svg>'
    )
    expected_from = (end - timedelta(days=ACTIVITY_WINDOW_DAYS - 1)).isoformat()
    return sample, expected_from, end.isoformat()


def self_test() -> None:
    for scheme in SOURCE_PALETTES:
        for layout in ("wide", "compact"):
            sample, expected_from, expected_to = fixture_svg(scheme, layout)
            themed = customize_svg(sample, scheme, layout)
            assert f'data-theme="{THEME_ID}"' in themed
            assert f'data-activity-window-days="{ACTIVITY_WINDOW_DAYS}"' in themed
            assert f'data-activity-from="{expected_from}"' in themed
            assert f'data-activity-to="{expected_to}"' in themed
            assert len(ACTIVITY_CELL.findall(themed)) == ACTIVITY_WINDOW_DAYS
            assert expected_from in themed and expected_to in themed
            if layout == "wide":
                assert "DAILY ACTIVITY · LAST 30 DAYS" in themed
            else:
                assert "DAILY ACTIVITY · 30 DAYS" in themed
                assert "SEP 04 — MAR 04" not in themed
            assert not (
                {color.upper() for color in SOURCE_PALETTES[scheme]}
                & {color.upper() for color in HEX_COLOR.findall(themed)}
            )
    print(
        f"Signal Field customization self-test passed: {THEME_ID}; "
        f"activity window={ACTIVITY_WINDOW_DAYS} days"
    )


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
