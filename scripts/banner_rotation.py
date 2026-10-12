#!/usr/bin/env python3
"""Deterministic, read-only UTC-day banner selector and bounded README proposer.

GitHub profile Markdown cannot execute JS. This tool intentionally does NOT claim
to rotate a rendered README by itself: a separately authorized scheduled
publisher must apply its exact, reviewed README proposal through a PR.
"""
from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "scripts/banner-rotation-v1.json"
README = ROOT / "README.md"
ASSET_ROOT = ROOT / "assets/profile-banners/daily"
EPOCH = date(1970, 1, 1)
NS = "{http://www.w3.org/2000/svg}"
PALETTE = ("#00E6FF", "#E328FC", "#00FBCC")
BANNER_MARKER = re.compile(r"^<!-- banner-rotation:v1 utc-day=(\d{4}-\d{2}-\d{2}) slug=(0[1-7]-[a-z-]+) -->$", re.MULTILINE)
BANNER_MARKER_PREFIX = "<!-- banner-rotation:v1 "
SURFACES = ("top", "top-compact", "bottom")
SCENE_RE = re.compile(r"0[1-7]-[a-z]+(?:-[a-z]+)*\Z")
ASSET_RE = re.compile(r"assets/profile-banners/daily/0[1-7]-[a-z-]+-(?:top|top-compact|bottom)\.svg\Z")
BANNER_REFERENCE = {
    "top-compact": re.compile(r'(<source media="\x28max-width: 640px\x29" srcset=")(assets/profile-banners/[^"]+)(?=")'),
    "top": re.compile(r'(<img alt="Animated quantum apex signal crown" src=")(assets/profile-banners/[^"]+)(?=")'),
    "bottom": re.compile(r'(<img alt="Animated evidence horizon" src=")(assets/profile-banners/[^"]+)(?=")'),
}
ORIGINAL = {
    "top": "assets/profile-banners/quantum-apex-signal-crown-hero.svg",
    "top-compact": "assets/profile-banners/quantum-apex-signal-crown-hero-compact.svg",
    "bottom": "assets/profile-banners/elite-evidence-horizon-bottom.svg",
}


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def read_regular(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f"banner file must be a regular file: {path}")
    require(stat.S_ISREG(path.lstat().st_mode), f"banner file type changed: {path}")
    return path.read_text(encoding="utf-8")


def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        require(name not in result, f"duplicate banner manifest key: {name}")
        result[name] = value
    return result


def load_catalog() -> list[dict[str, str]]:
    spec = json.loads(read_regular(MANIFEST), object_pairs_hook=unique_keys)
    require(isinstance(spec, dict) and set(spec) == {
        "version", "epoch", "timezone", "period_seconds", "selection", "surfaces", "palette", "scenes"
    }, "banner catalog structure changed")
    require(spec["version"] == "banner-rotation-v1" and spec["epoch"] == "1970-01-01", "banner epoch changed")
    require(spec["timezone"] == "UTC" and type(spec["period_seconds"]) is int and spec["period_seconds"] == 86400,
            "banner day must be exactly 86400 seconds in UTC")
    require(spec["selection"] == "floor(unix_utc_seconds/86400)%7", "banner deterministic selection policy changed")
    require(spec["surfaces"] == list(SURFACES) and spec["palette"] == list(PALETTE), "banner surfaces/palette changed")
    scenes = spec["scenes"]
    require(isinstance(scenes, list) and len(scenes) == 7, "exactly seven banner scenes required")
    for index, scene in enumerate(scenes, 1):
        require(isinstance(scene, dict) and set(scene) == {"slug", "title", "kind"},
                "banner scene must have exact identity/metadata keys")
        require(all(isinstance(value, str) and value for value in scene.values()), "banner scene identity is empty")
        require(SCENE_RE.fullmatch(scene["slug"]) is not None and scene["slug"].startswith(f"{index:02d}-"),
                "banner scene ordering or slug is invalid")
    require(len({item["slug"] for item in scenes}) == 7 and len({item["kind"] for item in scenes}) == 7,
            "seven banner scenes must have unique identities and visual morphologies")
    return scenes


def chosen(day: date, scenes: list[dict[str, str]]) -> dict[str, Any]:
    require(isinstance(day, date) and not isinstance(day, datetime), "UTC day must be a calendar date")
    days_since_epoch = (day - EPOCH).days
    require(days_since_epoch >= 0, "banner selector does not accept pre-epoch dates")
    index = days_since_epoch % len(scenes)
    scene = scenes[index]
    return {
        "version": "banner-rotation-v1",
        "utc_day": day.isoformat(),
        "unix_day": days_since_epoch,
        "slot": index + 1,
        "slug": scene["slug"],
        "top": f"assets/profile-banners/daily/{scene['slug']}-top.svg",
        "top-compact": f"assets/profile-banners/daily/{scene['slug']}-top-compact.svg",
        "bottom": f"assets/profile-banners/daily/{scene['slug']}-bottom.svg",
    }


def validate_assets(scenes: list[dict[str, str]]) -> None:
    require(ASSET_ROOT.is_dir() and not ASSET_ROOT.is_symlink(), "banner asset root missing/aliased")
    expected = {f"{scene['slug']}-{surface}.svg" for scene in scenes for surface in SURFACES}
    actual = {path.name for path in ASSET_ROOT.iterdir()}
    require(actual == expected, f"banner art inventory changed: missing={sorted(expected-actual)}, extra={sorted(actual-expected)}")
    for scene in scenes:
        for surface in SURFACES:
            relative = f"assets/profile-banners/daily/{scene['slug']}-{surface}.svg"
            require(ASSET_RE.fullmatch(relative) is not None, f"banner art path changed: {relative}")
            data = read_regular(ROOT / relative)
            require(2400 <= len(data.encode("utf-8")) < 30000, f"banner payload bound violated: {relative}")
            lower = data.lower()
            # XML namespace declarations are not network resource loads.
            checked = re.sub(r'\s+xmlns(?::[a-z]+)?="https?://www\.w3\.org/[^"]+"', "", lower)
            require(not any(token in checked for token in ("<script", "<image", "<foreignobject", "javascript:", "data:image", "http://", "https://")),
                    f"banner art must not load external payloads or scripts: {relative}")
            svg = ET.fromstring(data)
            require(svg.tag == NS+"svg" and svg.get("role") == "img", f"banner root must be accessible SVG: {relative}")
            require(svg.get("data-banner-art") == "rotating-collection-v1" and
                    svg.get("data-scene") == scene["slug"] and svg.get("data-surface") == surface,
                    f"banner asset identity mismatch: {relative}")
            require(svg.find(NS+"title") is not None and svg.find(NS+"desc") is not None,
                    f"banner title/description missing: {relative}")
            require(svg.get("aria-labelledby") == "title desc", f"banner accessible name mismatch: {relative}")
            w,h = (1280,150) if surface == "bottom" else (640,196) if surface == "top-compact" else (1280,258)
            require(svg.get("viewBox") == f"0 0 {w} {h}" and
                    svg.get("width") == str(w*3) and svg.get("height") == str(h*3),
                    f"banner intrinsic aspect ratio changed: {relative}")
            require(all(color in data for color in PALETTE), f"banner original neon palette missing: {relative}")
            style = svg.find(f".//{NS}style")
            require(style is not None and "prefers-reduced-motion:reduce" in (style.text or "") and
                    ".motion{display:none}" in (style.text or ""),
                    f"banner motion fallback missing: {relative}")
            require(len(svg.findall(f".//{NS}animate")) + len(svg.findall(f".//{NS}animateMotion")) +
                    len(svg.findall(f".//{NS}animateTransform")) >= 3,
                    f"banner lacks motion paths: {relative}")
            require(svg.find(f".//{NS}g[@class='skeleton']") is not None,
                    f"reduced-motion static artwork missing: {relative}")


def referenced(readme: str) -> dict[str, str]:
    current: dict[str, str] = {}
    for surface, pattern in BANNER_REFERENCE.items():
        found = pattern.findall(readme)
        require(len(found) == 1, f"README must have exactly one {surface} banner reference")
        path = found[0][1]
        require(path == ORIGINAL[surface] or ASSET_RE.fullmatch(path) is not None,
                f"README {surface} banner ref outside reviewed catalog: {path}")
        current[surface] = path
    bottom = re.compile(r'<a\b[^>]*>(?:(?!</a>).)*<img alt="Animated evidence horizon"(?:(?!</a>).)*</a>',re.I|re.S)
    require(bottom.search(readme) is None, "bottom horizon must remain non-clickable")
    return current


def propose(readme: str, selection: dict[str, Any]) -> str:
    """Build a replay-safe three-surface candidate without mutating source."""
    existing = referenced(readme)
    matches = list(BANNER_MARKER.finditer(readme))
    require(readme.count(BANNER_MARKER_PREFIX) == len(matches) and len(matches) <= 1,
            "README banner high-water marker is ambiguous or malformed")
    next_marker = f"<!-- banner-rotation:v1 utc-day={selection['utc_day']} slug={selection['slug']} -->"
    if matches:
        prior = matches[0]
        prior_day = date.fromisoformat(prior.group(1))
        require(prior_day >= EPOCH, "README banner marker predates UTC epoch")
        require((prior_day-EPOCH).days <= selection["unix_day"], "banner UTC-day rotation rollback forbidden")
        prior_slug = prior.group(2)
        require(all(existing[surface] == f"assets/profile-banners/daily/{prior_slug}-{surface}.svg"
                    for surface in SURFACES), "README banner marker and three current artwork references disagree")
        prior_slot = int(prior_slug[:2])
        require(prior_slot == ((prior_day-EPOCH).days % 7) + 1,
                "README banner high-water scene does not match historical UTC date")
        output = readme[:prior.start()] + next_marker + readme[prior.end():]
    else:
        require(all(existing[s] == ORIGINAL[s] for s in SURFACES),
                "unmarked README banner must be the canonical original triplet")
        top = '<p align="center">\n<picture>\n  <source media="(max-width: 640px)" '
        require(readme.count(top) == 1, "README original hero location must be unambiguous")
        output = readme.replace(top, next_marker + "\n" + top, 1)

    for surface, pattern in BANNER_REFERENCE.items():
        output, replacements = pattern.subn(lambda m: m.group(1)+selection[surface], output)
        require(replacements == 1, f"README banner proposal failed to replace {surface}")
    require(referenced(output) == {s: selection[s] for s in SURFACES} and
            output.count(next_marker) == 1,
            "README banner proposal must bind one epoch and all three surfaces")
    return output


def test_rotation(scenes: list[dict[str, str]]) -> None:
    seven = [chosen(EPOCH.fromordinal(EPOCH.toordinal()+i),scenes) for i in range(15)]
    require([v["slot"] for v in seven] == [1,2,3,4,5,6,7,1,2,3,4,5,6,7,1],
            "seven-scene 24-hour selection is non-deterministic")
    require(chosen(date(2024,2,29),scenes)["unix_day"] + 1 ==
            chosen(date(2024,3,1),scenes)["unix_day"], "leap day rotation broke")
    require(chosen(date(2026,12,31),scenes)["unix_day"] + 1 ==
            chosen(date(2027,1,1),scenes)["unix_day"], "year boundary rotation broke")
    sel = chosen(date(2026,10,12),scenes)
    fixture = (
        '<br>\n\n<p align="center">\n<picture>\n'
        '  <source media="(max-width: 640px)" srcset="'+ORIGINAL["top-compact"]+'">\n'
        '<img alt="Animated quantum apex signal crown" src="'+ORIGINAL["top"]+'" width="100%">\n'
        '<img alt="Animated evidence horizon" src="'+ORIGINAL["bottom"]+'" width="100%">'
    )
    updated = propose(fixture,sel)
    require(updated != fixture and propose(updated,sel) == updated, "selector cannot update safely/idempotently")
    another = chosen(date(2026,10,13),scenes)
    advanced = propose(updated, another)
    require(advanced != updated, "next day's banner must change")
    try:
        propose(advanced,sel)
    except ValueError as exc:
        require("rollback" in str(exc), "stale-day proposal rejected for wrong reason")
    else:
        raise ValueError("stale-day banner rollback accepted")
    try:
        propose(updated.replace(sel["top"], another["top"]), another)
    except ValueError as exc:
        require("disagree" in str(exc), "unbound banner reference rejected for wrong reason")
    else:
        raise ValueError("inconsistent top/mobile/footer banner accepted")
    try:
        propose(fixture + fixture,sel)
    except ValueError as exc:
        require("exactly one" in str(exc), "ambiguous README banner fixture rejected for wrong reason")
    else:
        raise ValueError("ambiguous duplicate banner targets accepted")
    require(len({v["slug"] for v in seven[:7]}) == 7, "weekly scene period is incomplete")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--select",action="store_true",help="Emit the deterministic UTC-day three-art selection as JSON")
    mode.add_argument("--propose",action="store_true",help="Emit a safe README proposal to stdout; never mutate it")
    mode.add_argument("--check",action="store_true",help="Read-only validate all 21 art assets and rotation rules")
    mode.add_argument("--self-test",action="store_true",help="Check day boundaries and fail-closed README proposal")
    parser.add_argument("--date",help="YYYY-MM-DD UTC calendar day fixture; defaults to the current UTC day")
    args = parser.parse_args()
    try:
        scenes = load_catalog()
        if args.check:
            require(args.date is None,"asset check does not take a date")
            validate_assets(scenes)
            print("Banner collection contract passed: 7 unique scenes, 21 accessible animated SVGs, bounded payloads, matching mobile/footer, reduced-motion fallbacks.")
        elif args.self_test:
            require(args.date is None,"rotation self-test does not take a date")
            test_rotation(scenes)
            print("Banner UTC-day selection passed: 86400-second epochs, every seven days, leap/year boundaries, idempotent exact 3-surface README proposals.")
        else:
            day = date.fromisoformat(args.date) if args.date else datetime.now(timezone.utc).date()
            selection = chosen(day,scenes)
            if args.select:
                print(json.dumps(selection,sort_keys=True,separators=(",",":")))
            else:
                print(propose(read_regular(README),selection),end="")
        return 0
    except (ValueError,TypeError,OSError,ET.ParseError) as exc:
        print(f"ERROR: banner rotation: {exc}",file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
