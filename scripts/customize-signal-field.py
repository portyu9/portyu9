#!/usr/bin/env python3
"""Apply the Ƴunior Ƥortal Signal Field v2 theme and rolling 30-day calendar.

The pinned upstream generator still collects the complete 365/366-day contribution
dataset used by the headline metric. This deterministic presentation layer changes
only the rendered daily-activity field to the newest 30 dated records.

Signal Field v2 renders a true month calendar:
- seven weekday columns (Sunday through Saturday)
- five or six chronological week rows
- one numbered tile per real day
- explicit partial-week placeholders
- derived 30-day active/streak/peak telemetry
- month-boundary markers
- an explicit latest-day highlight

Unexpected colors, malformed activity data, duplicate/non-consecutive dates, or an
upstream structural change fail closed instead of publishing a partial artifact.
"""

from __future__ import annotations

from datetime import date, timedelta
from pathlib import Path
import re
import sys

THEME_ID = "yunior-portal-neon-v2"
ACTIVITY_WINDOW_DAYS = 30
ACTIVITY_LAYOUT = "month-calendar-v2"
WEEKDAYS = ("SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT")
EXPECTED_FILES = (
    "signal-field-wide-light.svg",
    "signal-field-wide-dark.svg",
    "signal-field-compact-light.svg",
    "signal-field-compact-dark.svg",
)

# shinpr/github-profile-stats@49b5f7091182a45f3ef93923505b660c6da5f835 (v0.2.0)
SOURCE_PALETTES = {
    "light": {
        "#FCFAF5": "#FFFFFF",
        "#17171B": "#111827",
        "#5E5B63": "#5B6475",
        "#D8D2C7": "#D9DFF0",
        "#DE4F44": "#FF2BD6",
        "#918A21": "#A020F0",
        "#1D97A3": "#7A5CFF",
        "#906AE5": "#00AEEF",
        "#E7E1D7": "#EEF2FF",
        "#7967C9": "#E879F9",
        "#654FC2": "#C026D3",
        "#5036AA": "#7A5CFF",
        "#382077": "#00AEEF",
    },
    "dark": {
        "#151821": "#0B1020",
        "#F7F3EA": "#F8FAFC",
        "#AAA8B4": "#A7B0C4",
        "#303543": "#28324A",
        "#F9786A": "#FF2BD6",
        "#B0A946": "#A020F0",
        "#48B7C2": "#7A5CFF",
        "#AB91F2": "#00AEEF",
        "#262A35": "#171D2D",
        "#7768C7": "#D946EF",
        "#927EE7": "#A020F0",
        "#B29AFF": "#7A5CFF",
        "#D5C5FF": "#00AEEF",
    },
}

HEX_COLOR = re.compile(r"#[0-9A-Fa-f]{6}\b")
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ACTIVITY_CELL = re.compile(
    r'<rect\b[^>]*\bdata-date="\d{4}-\d{2}-\d{2}"[^>]*/>',
    re.I,
)
OUTSIDE_SLOT = re.compile(
    r'<rect\b[^>]*\bdata-slot-state="outside-window"[^>]*/>',
    re.I,
)
DAY_LABEL = re.compile(
    r'<text\b[^>]*\bdata-day-label="(\d{4}-\d{2}-\d{2})"[^>]*>[^<]+</text>',
    re.I,
)
MONTH_LABEL = re.compile(
    r'<text\b[^>]*\bdata-month-boundary="([A-Z]{3})"[^>]*>[^<]+</text>',
    re.I,
)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
ACCESSIBLE_ACTIVITY = re.compile(
    r"(?:365|366) daily activity marks from (\d{4}-\d{2}-\d{2}) through "
    r"(\d{4}-\d{2}-\d{2}), inclusive\."
)
COMPACT_BAND_LABEL = re.compile(
    r'<text x="22" y="(?:291|397)"[^>]*>[A-Z]{3} \d{2} — [A-Z]{3} \d{2}</text>'
)

MONO_FONT = "ui-monospace,SFMono-Regular,Consolas,Liberation Mono,monospace"


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


def sunday_weekday(value: date) -> int:
    """Return Sunday=0 ... Saturday=6."""
    return (value.weekday() + 1) % 7


def calendar_bounds(recent: list[dict[str, str]]) -> tuple[date, date, int]:
    first_date = date.fromisoformat(recent[0]["data-date"])
    last_date = date.fromisoformat(recent[-1]["data-date"])
    week_origin = first_date - timedelta(days=sunday_weekday(first_date))
    week_rows = ((last_date - week_origin).days // 7) + 1
    if week_rows not in (5, 6):
        raise ValueError(
            f"30-day rolling calendar must occupy 5 or 6 week rows, found {week_rows}"
        )
    return first_date, week_origin, week_rows


def source_token(scheme: str, key: str) -> str:
    tokens = {
        "light": {
            "primary": "#17171B",
            "secondary": "#5E5B63",
            "hairline": "#D8D2C7",
            "accent": "#DE4F44",
        },
        "dark": {
            "primary": "#F7F3EA",
            "secondary": "#AAA8B4",
            "hairline": "#303543",
            "accent": "#F9786A",
        },
    }
    return tokens[scheme][key]


def activity_stats(recent: list[dict[str, str]]) -> tuple[int, int, int, str]:
    counts = [int(cell["data-count"]) for cell in recent]
    active_days = sum(count > 0 for count in counts)

    current_streak = 0
    for count in reversed(counts):
        if count <= 0:
            break
        current_streak += 1

    peak_index = max(range(len(counts)), key=counts.__getitem__)
    peak_count = counts[peak_index]
    peak_date = recent[peak_index]["data-date"]
    return active_days, current_streak, peak_count, peak_date


def month_boundary_dates(recent: list[dict[str, str]]) -> dict[date, str]:
    boundaries: dict[date, str] = {}
    seen: set[tuple[int, int]] = set()
    for cell in recent:
        current = date.fromisoformat(cell["data-date"])
        key = (current.year, current.month)
        if key not in seen:
            seen.add(key)
            boundaries[current] = current.strftime("%b").upper()
    return boundaries


def render_summary(
    layout: str,
    scheme: str,
    active_days: int,
    current_streak: int,
    peak_count: int,
    peak_date: str,
) -> str:
    secondary = source_token(scheme, "secondary")
    peak_short = date.fromisoformat(peak_date).strftime("%b %d").upper()
    if layout == "wide":
        return (
            f'<text x="30" y="199" fill="{secondary}" font-family="{MONO_FONT}" '
            f'font-size="9" font-weight="600" data-activity-summary="true">'
            f'ACTIVE {active_days}/30 · STREAK {current_streak} · '
            f'PEAK {peak_short} · {peak_count}</text>'
        )
    return (
        f'<text x="22" y="285" fill="{secondary}" font-family="{MONO_FONT}" '
        f'font-size="7.5" font-weight="600" data-activity-summary="true">'
        f'ACTIVE {active_days}/30 · STREAK {current_streak} · PEAK {peak_count}</text>'
    )


def render_activity_window(
    cells: list[dict[str, str]], layout: str, scheme: str
) -> tuple[str, int, tuple[int, int, int, str]]:
    recent = cells[-ACTIVITY_WINDOW_DAYS:]
    first_date, week_origin, week_rows = calendar_bounds(recent)
    last_date = date.fromisoformat(recent[-1]["data-date"])
    stats = activity_stats(recent)
    boundaries = month_boundary_dates(recent)
    cells_by_date = {
        date.fromisoformat(cell["data-date"]): (index, cell)
        for index, cell in enumerate(recent)
    }

    if layout == "wide":
        x0, label_y, grid_y = 52, 218, 225
        step_x, step_y = 78, 25
        width, height, radius = 56, 21, 5
        weekday_font_size, day_font_size, month_font_size = 8, 9, 6.5
    elif layout == "compact":
        x0, label_y, grid_y = 18, 306, 314
        step_x, step_y = 42, 28
        width, height, radius = 34, 24, 5
        weekday_font_size, day_font_size, month_font_size = 7, 8, 5.5
    else:
        raise ValueError(f"unsupported layout: {layout}")

    primary = source_token(scheme, "primary")
    secondary = source_token(scheme, "secondary")
    hairline = source_token(scheme, "hairline")
    accent = source_token(scheme, "accent")

    rendered: list[str] = []
    for weekday_column, weekday in enumerate(WEEKDAYS):
        x = x0 + weekday_column * step_x + width / 2
        rendered.append(
            f'<text x="{x:g}" y="{label_y}" fill="{secondary}" '
            f'font-family="{MONO_FONT}" font-size="{weekday_font_size}" '
            f'font-weight="650" text-anchor="middle" '
            f'data-weekday-label="{weekday_column}">{weekday}</text>'
        )

    for week_row in range(week_rows):
        for weekday_column in range(7):
            slot_date = week_origin + timedelta(days=week_row * 7 + weekday_column)
            x = x0 + weekday_column * step_x
            y = grid_y + week_row * step_y
            entry = cells_by_date.get(slot_date)

            if entry is None:
                if slot_date < first_date or slot_date > last_date:
                    rendered.append(
                        f'<rect x="{x}" y="{y}" width="{width}" height="{height}" '
                        f'rx="{radius}" fill="none" stroke="{hairline}" stroke-width="1" '
                        f'stroke-dasharray="2 3" opacity="0.38" '
                        f'data-slot-state="outside-window" data-calendar-week="{week_row}" '
                        f'data-weekday-column="{weekday_column}"/>'
                    )
                    continue
                raise ValueError(
                    f"calendar slot unexpectedly missing in-window date: {slot_date}"
                )

            index, cell = entry
            level = int(cell["data-level"])
            is_latest = slot_date == last_date
            month_marker = boundaries.get(slot_date)

            stroke = ""
            if is_latest:
                stroke = f' stroke="{accent}" stroke-width="2"'
            elif level == 0:
                stroke = f' stroke="{hairline}" stroke-width="1"'

            marker_attr = (
                f' data-month-boundary="{month_marker}"' if month_marker else ""
            )
            latest_attr = ' data-latest-day="true"' if is_latest else ""

            rendered.append(
                f'<rect x="{x}" y="{y}" width="{width}" height="{height}" '
                f'rx="{radius}" fill="{cell["fill"]}"{stroke} '
                f'data-date="{cell["data-date"]}" data-count="{cell["data-count"]}" '
                f'data-level="{cell["data-level"]}" data-window-day="{index + 1}" '
                f'data-week-row="{week_row}" data-weekday-column="{weekday_column}"'
                f'{marker_attr}{latest_attr}/>'
            )

            center_x = x + width / 2
            if month_marker:
                if layout == "wide":
                    rendered.append(
                        f'<text x="{x + 5:g}" y="{y + 8:g}" fill="{primary}" '
                        f'font-family="{MONO_FONT}" font-size="{month_font_size}" '
                        f'font-weight="800" data-month-boundary="{month_marker}">'
                        f'{month_marker}</text>'
                    )
                    rendered.append(
                        f'<text x="{x + width - 5:g}" y="{y + 15:g}" fill="{primary}" '
                        f'font-family="{MONO_FONT}" font-size="{day_font_size}" '
                        f'font-weight="800" text-anchor="end" '
                        f'data-day-label="{slot_date.isoformat()}">{slot_date.day:02d}</text>'
                    )
                else:
                    rendered.append(
                        f'<text x="{center_x:g}" y="{y + 8:g}" fill="{primary}" '
                        f'font-family="{MONO_FONT}" font-size="{month_font_size}" '
                        f'font-weight="800" text-anchor="middle" '
                        f'data-month-boundary="{month_marker}">{month_marker}</text>'
                    )
                    rendered.append(
                        f'<text x="{center_x:g}" y="{y + 18:g}" fill="{primary}" '
                        f'font-family="{MONO_FONT}" font-size="{day_font_size}" '
                        f'font-weight="800" text-anchor="middle" '
                        f'data-day-label="{slot_date.isoformat()}">{slot_date.day:02d}</text>'
                    )
            else:
                baseline = y + (15 if layout == "wide" else 16)
                rendered.append(
                    f'<text x="{center_x:g}" y="{baseline:g}" fill="{primary}" '
                    f'font-family="{MONO_FONT}" font-size="{day_font_size}" '
                    f'font-weight="800" text-anchor="middle" '
                    f'data-day-label="{slot_date.isoformat()}">{slot_date.day:02d}</text>'
                )

    return "".join(rendered), week_rows, stats


def resize_wide_card(text: str) -> str:
    required = (
        ('viewBox="0 0 640 360" width="640" height="360"',
         'viewBox="0 0 640 425" width="640" height="425"'),
        ('<rect width="640" height="360"',
         '<rect width="640" height="425"'),
        ('<rect x="0.5" y="0.5" width="639" height="359"',
         '<rect x="0.5" y="0.5" width="639" height="424"'),
        ('<path d="M30 288h580"',
         '<path d="M30 390h580"'),
    )
    for old, new in required:
        if old not in text:
            raise ValueError(f"wide Signal Field geometry signature changed: {old}")
        text = text.replace(old, new, 1)

    text, source_count = re.subn(
        r'(<text x="30" )y="330"([^>]*>SOURCE · GITHUB GRAPHQL CONTRIBUTION CALENDAR</text>)',
        r'\1y="410"\2',
        text,
        count=1,
    )
    text, through_count = re.subn(
        r'(<text x="610" )y="330"([^>]*>CONTRIBUTIONS THROUGH · [^<]+</text>)',
        r'\1y="410"\2',
        text,
        count=1,
    )
    if source_count != 1 or through_count != 1:
        raise ValueError("wide Signal Field footer geometry signature changed")
    return text


def apply_activity_window(text: str, layout: str, scheme: str) -> str:
    cells = parse_activity_cells(text)
    recent = cells[-ACTIVITY_WINDOW_DAYS:]
    from_date = recent[0]["data-date"]
    to_date = recent[-1]["data-date"]

    matches = list(ACTIVITY_CELL.finditer(text))
    start, end = matches[0].start(), matches[-1].end()
    if len(ACTIVITY_CELL.findall(text[start:end])) != len(cells):
        raise ValueError("activity-cell block is not contiguous")

    rendered, week_rows, stats = render_activity_window(cells, layout, scheme)
    active_days, current_streak, peak_count, peak_date = stats
    text = text[:start] + rendered + text[end:]

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

    summary = render_summary(
        layout, scheme, active_days, current_streak, peak_count, peak_date
    )
    label_close = f">{new_label}</text>"
    if text.count(label_close) != 1:
        raise ValueError("could not locate customized activity label element")
    text = text.replace(label_close, label_close + summary, 1)

    if len(ACCESSIBLE_ACTIVITY.findall(text)) != 1:
        raise ValueError("expected exactly one accessible annual activity description")
    text = ACCESSIBLE_ACTIVITY.sub(
        f"{ACTIVITY_WINDOW_DAYS} daily activity marks from {from_date} through "
        f"{to_date}, inclusive.",
        text,
        count=1,
    )

    if layout == "wide":
        text = resize_wide_card(text)

    match = SVG_OPEN.search(text)
    if not match:
        raise ValueError("SVG root element is missing")
    attrs = match.group(1)
    if "data-activity-window-days=" in attrs:
        raise ValueError("upstream SVG unexpectedly defines an activity-window attribute")
    window_attrs = (
        f' data-activity-window-days="{ACTIVITY_WINDOW_DAYS}"'
        f' data-activity-from="{from_date}" data-activity-to="{to_date}"'
        f' data-activity-layout="{ACTIVITY_LAYOUT}"'
        f' data-activity-columns="7" data-activity-week-rows="{week_rows}"'
        f' data-active-days="{active_days}" data-current-streak="{current_streak}"'
        f' data-peak-count="{peak_count}" data-peak-date="{peak_date}"'
    )
    replacement = f"<svg{attrs}{window_attrs}>"
    return text[:match.start()] + replacement + text[match.end():]


def customize_svg(text: str, scheme: str, layout: str) -> str:
    palette = SOURCE_PALETTES[scheme]
    allowed = {color.upper() for color in palette}
    original_colors = {color.upper() for color in HEX_COLOR.findall(text)}
    unknown = sorted(original_colors - allowed)
    if unknown:
        raise ValueError(
            "upstream Signal Field palette changed; refusing partial customization: "
            + ", ".join(unknown)
        )
    if "data-period-days=" not in text or "<title" not in text or "<desc" not in text:
        raise ValueError("Signal Field structural signature is missing")

    themed = apply_activity_window(text, layout, scheme)

    source_colors_after_crop = {color.upper() for color in HEX_COLOR.findall(themed)}
    expected_targets = {
        target.upper()
        for source, target in palette.items()
        if source.upper() in source_colors_after_crop
    }

    for source, target in palette.items():
        themed = themed.replace(source, target)

    match = SVG_OPEN.search(themed)
    if not match:
        raise ValueError("SVG root element is missing")
    if THEME_ID not in match.group(0):
        attrs = match.group(1)
        replacement = f'<svg{attrs} data-theme="{THEME_ID}">'
        themed = themed[:match.start()] + replacement + themed[match.end():]

    themed_colors = {color.upper() for color in HEX_COLOR.findall(themed)}
    remaining = sorted(themed_colors & allowed)
    if remaining:
        raise ValueError(
            "source palette colors remain after customization: " + ", ".join(remaining)
        )

    missing_targets = sorted(expected_targets - themed_colors)
    if missing_targets:
        raise ValueError(
            "customized SVG is missing target colors implied by its source palette: "
            + ", ".join(missing_targets)
        )

    published = ACTIVITY_CELL.findall(themed)
    if len(published) != ACTIVITY_WINDOW_DAYS:
        raise ValueError(
            f"customized SVG must publish exactly {ACTIVITY_WINDOW_DAYS} activity cells"
        )
    if f'data-activity-window-days="{ACTIVITY_WINDOW_DAYS}"' not in themed:
        raise ValueError("customized SVG is missing activity-window provenance")
    if f'data-activity-layout="{ACTIVITY_LAYOUT}"' not in themed:
        raise ValueError("customized SVG is missing activity-layout provenance")
    if 'data-activity-columns="7"' not in themed:
        raise ValueError("customized SVG must declare seven weekday columns")
    if f'data-theme="{THEME_ID}"' not in themed:
        raise ValueError("customized SVG is missing theme provenance")
    if themed.count('data-activity-summary="true"') != 1:
        raise ValueError("customized SVG must render one 30-day telemetry summary")

    published_attrs = [dict(ATTR.findall(cell)) for cell in published]
    weekday_columns = {int(cell["data-weekday-column"]) for cell in published_attrs}
    if weekday_columns != set(range(7)):
        raise ValueError("activity calendar must cover all seven weekday columns")

    week_rows = [int(cell["data-week-row"]) for cell in published_attrs]
    row_count = max(week_rows) + 1
    if min(week_rows) != 0 or row_count not in (5, 6):
        raise ValueError(
            "activity calendar must occupy five or six chronological week rows"
        )
    if f'data-activity-week-rows="{row_count}"' not in themed:
        raise ValueError(
            "activity calendar week-row provenance does not match rendered cells"
        )

    for cell in published_attrs:
        current = date.fromisoformat(cell["data-date"])
        if int(cell["data-weekday-column"]) != sunday_weekday(current):
            raise ValueError(f"weekday column mismatch for {current.isoformat()}")

    weekday_labels = re.findall(r'data-weekday-label="([0-6])"', themed)
    if weekday_labels != [str(index) for index in range(7)]:
        raise ValueError("activity calendar must render ordered SUN-SAT weekday labels")

    placeholder_count = len(OUTSIDE_SLOT.findall(themed))
    if placeholder_count != row_count * 7 - ACTIVITY_WINDOW_DAYS:
        raise ValueError(
            "outside-window placeholder count does not complete the calendar matrix"
        )

    day_labels = DAY_LABEL.findall(themed)
    published_dates = [cell["data-date"] for cell in published_attrs]
    if day_labels != published_dates:
        raise ValueError("every published activity date must render exactly one day number")

    expected_months = []
    seen_months = set()
    for value in published_dates:
        current = date.fromisoformat(value)
        key = (current.year, current.month)
        if key not in seen_months:
            seen_months.add(key)
            expected_months.append(current.strftime("%b").upper())
    if MONTH_LABEL.findall(themed) != expected_months:
        raise ValueError("month-boundary markers do not match the rolling window")

    latest = [cell for cell in published_attrs if cell.get("data-latest-day") == "true"]
    if len(latest) != 1 or latest[0]["data-date"] != published_dates[-1]:
        raise ValueError("latest-day highlight must identify the newest displayed date")
    latest_rect = next(
        cell for cell in published
        if 'data-latest-day="true"' in cell
    )
    if 'stroke-width="2"' not in latest_rect:
        raise ValueError("latest-day highlight must use the explicit v2 outline")

    zero_cells = [cell for cell in published_attrs if cell["data-level"] == "0"]
    if zero_cells:
        zero_rects = [
            cell
            for cell in published
            if 'data-level="0"' in cell
            and (
                'stroke-width="1"' in cell
                or 'data-latest-day="true"' in cell
            )
        ]
        if len(zero_rects) != len(zero_cells):
            raise ValueError("zero-activity dates must remain visibly outlined")

    for attr in ("data-active-days", "data-current-streak", "data-peak-count", "data-peak-date"):
        if f"{attr}=" not in themed:
            raise ValueError(f"customized SVG is missing derived telemetry: {attr}")

    return themed


def customize_directory(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        scheme = scheme_for(path)
        layout = layout_for(path)
        themed = customize_svg(path.read_text(encoding="utf-8"), scheme, layout)
        path.write_text(themed, encoding="utf-8")
        print(
            f"themed {filename} -> {THEME_ID}; "
            f"activity window -> {ACTIVITY_WINDOW_DAYS} days; layout -> {ACTIVITY_LAYOUT}"
        )


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
            f'<rect x="0" y="0" width="9" height="9" rx="2" '
            f'fill="{activity_colors[level]}" data-date="{current.isoformat()}" '
            f'data-count="{index}" data-level="{level}"/>'
        )

    common_sources = list(palette.keys())[:5]
    decorative = "".join(f'<rect fill="{color}"/>' for color in common_sources)
    if layout == "wide":
        decorative += "".join(
            f'<rect fill="{color}"/>' for color in list(palette.keys())[5:8]
        )
        label = "DAILY ACTIVITY · PAST YEAR"
        band_labels = ""
        geometry = 'viewBox="0 0 640 360" width="640" height="360"'
        surface = (
            f'<rect width="640" height="360" fill="{list(palette)[0]}"/>'
            f'<rect x="0.5" y="0.5" width="639" height="359" fill="none" '
            f'stroke="{source_token(scheme, "hairline")}"/>'
            f'<path d="M30 288h580" stroke="{source_token(scheme, "hairline")}"/>'
            f'<text x="30" y="330" fill="{source_token(scheme, "secondary")}">'
            f'SOURCE · GITHUB GRAPHQL CONTRIBUTION CALENDAR</text>'
            f'<text x="610" y="330" fill="{source_token(scheme, "secondary")}">'
            f'CONTRIBUTIONS THROUGH · SEP 03, 2026</text>'
        )
    else:
        label = "DAILY ACTIVITY"
        muted = source_token(scheme, "secondary")
        band_labels = (
            f'<text x="22" y="291" fill="{muted}">SEP 04 — MAR 04</text>'
            f'<text x="22" y="397" fill="{muted}">MAR 05 — SEP 03</text>'
        )
        geometry = 'viewBox="0 0 320 528" width="320" height="528"'
        surface = ""

    sample = (
        f'<svg xmlns="http://www.w3.org/2000/svg" {geometry} data-period-days="{days}">'
        f'<title>{scheme}-{layout}</title>'
        f'<desc>fixture; {days} daily activity marks from {start.isoformat()} '
        f'through {end.isoformat()}, inclusive.</desc>'
        f'<text>{label}</text>{band_labels}{surface}{decorative}{"".join(cells)}</svg>'
    )
    expected_from = (end - timedelta(days=ACTIVITY_WINDOW_DAYS - 1)).isoformat()
    return sample, expected_from, end.isoformat()


def self_test() -> None:
    five_week_fixture = [
        {"data-date": (date(2026, 8, 5) + timedelta(days=index)).isoformat()}
        for index in range(30)
    ]
    six_week_fixture = [
        {"data-date": (date(2026, 8, 1) + timedelta(days=index)).isoformat()}
        for index in range(30)
    ]
    assert calendar_bounds(five_week_fixture)[2] == 5
    assert calendar_bounds(six_week_fixture)[2] == 6

    for scheme in SOURCE_PALETTES:
        for layout in ("wide", "compact"):
            sample, expected_from, expected_to = fixture_svg(scheme, layout)
            themed = customize_svg(sample, scheme, layout)
            assert f'data-theme="{THEME_ID}"' in themed
            assert f'data-activity-window-days="{ACTIVITY_WINDOW_DAYS}"' in themed
            assert f'data-activity-layout="{ACTIVITY_LAYOUT}"' in themed
            assert 'data-activity-columns="7"' in themed
            assert f'data-activity-from="{expected_from}"' in themed
            assert f'data-activity-to="{expected_to}"' in themed

            published = ACTIVITY_CELL.findall(themed)
            assert len(published) == ACTIVITY_WINDOW_DAYS
            published_attrs = [dict(ATTR.findall(cell)) for cell in published]
            assert {
                int(cell["data-weekday-column"]) for cell in published_attrs
            } == set(range(7))
            assert min(int(cell["data-week-row"]) for cell in published_attrs) == 0
            assert max(int(cell["data-week-row"]) for cell in published_attrs) in (4, 5)
            assert len(OUTSIDE_SLOT.findall(themed)) in (5, 12)
            assert re.findall(r'data-weekday-label="([0-6])"', themed) == [
                str(index) for index in range(7)
            ]
            assert DAY_LABEL.findall(themed) == [
                cell["data-date"] for cell in published_attrs
            ]
            assert themed.count('data-latest-day="true"') == 1
            assert themed.count('data-activity-summary="true"') == 1

            if layout == "wide":
                assert "DAILY ACTIVITY · LAST 30 DAYS" in themed
                assert 'viewBox="0 0 640 425"' in themed
                assert 'height="425"' in themed
            else:
                assert "DAILY ACTIVITY · 30 DAYS" in themed
                assert "SEP 04 — MAR 04" not in themed

            assert not (
                {color.upper() for color in SOURCE_PALETTES[scheme]}
                & {color.upper() for color in HEX_COLOR.findall(themed)}
            )

    print(
        f"Signal Field customization self-test passed: {THEME_ID}; "
        f"activity window={ACTIVITY_WINDOW_DAYS} days; layout={ACTIVITY_LAYOUT}"
    )


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test()
            return 0
        if len(sys.argv) != 2:
            raise ValueError(
                "usage: customize-signal-field.py <generated-directory> | --self-test"
            )
        customize_directory(Path(sys.argv[1]))
        return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
