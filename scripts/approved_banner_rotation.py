#!/usr/bin/env python3
"""Fail-closed three-day UTC rotation of reviewed profile banner triplets.

Slot 1 now serves the exact accepted V1 Photonic Depth triplet; original art stays immutable.
Slots 2 and 3 stay Fractal Iris and Chronohedron. Slots 4-8 stay reserved.
Legacy v3 and v4 README markers retain their exact original art and provenance.
CLI is read-only: it never directly pushes README or alters branches.
"""
from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import stat
import sys
from typing import Any
from xml.etree import ElementTree as ET

import banner_rotation as historical

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "scripts/approved-banner-rotation-v4.json"
LEGACY_MANIFEST = ROOT / "scripts/approved-banner-rotation-v3.json"
LEGACY_CATALOG_BLOB = "616dd2beba7b49fe933c243c7c08d50e562861c2"
V1_ASSETS = {
    surface: f"assets/profile-banners/approved/01-quantum-apex-photonic-depth-{surface}.svg"
    for surface in ("top", "top-compact", "bottom")
}
V1_BLOBS = {
    "top": "4d783a9f32cc747e50db36312f8ae6d1894403f2",
    "top-compact": "39f6298bfece3ef19ec8496a907869b7cecb2f59",
    "bottom": "47c5b6cfce89a0ae1497749f1c5ef129f58739d5",
}
EPOCH = date(2026, 10, 12)
SURFACES = ("top", "top-compact", "bottom")
MARKER = re.compile(
    r"^<!-- banner-rotation:v([345]) utc-day=(\d{4}-\d{2}-\d{2}) "
    r"slot=([1-8]) slug=(0[1-8]-[a-z-]+) -->$", re.MULTILINE,
)
PREFIX = "<!-- banner-rotation:"
HEADER_ANCHOR = '<p align="center">\n<picture>\n  <source media="(max-width: 640px)" '
EXPECTED_SLUGS = (
    "01-photonic-depth", "02-fractal-iris", "03-chronohedron",
    "04-reserved", "05-reserved", "06-reserved", "07-reserved", "08-reserved",
)


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValueError(message)


def unique_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in output, f"duplicate approved rotation key: {key}")
        output[key] = value
    return output


def git_blob(text: str) -> str:
    data = text.encode("utf-8")
    return hashlib.sha1(
        f"blob {len(data)}\0".encode("ascii") + data,
        usedforsecurity=False,
    ).hexdigest()


def read_file(path: Path) -> str:
    require(path.is_file() and not path.is_symlink(), f"banner is not regular: {path}")
    require(stat.S_ISREG(path.lstat().st_mode), f"banner is not a regular inode: {path}")
    return path.read_text(encoding="utf-8")


def load_catalog() -> list[dict[str, Any]]:
    raw = json.loads(read_file(MANIFEST), object_pairs_hook=unique_keys)
    require(isinstance(raw, dict) and set(raw) ==
            {"version", "epoch", "timezone", "period_seconds", "slots"},
            "approved banner catalog keys changed")
    require(raw["version"] == "approved-profile-banners-v4" and
            raw["epoch"] == EPOCH.isoformat() and raw["timezone"] == "UTC" and
            type(raw["period_seconds"]) is int and raw["period_seconds"] == 86400,
            "UTC-day approved schedule changed")
    slots = raw["slots"]
    require(isinstance(slots, list) and len(slots) == 8,
            "approved rotation requires exactly eight slots")
    for n, slot in enumerate(slots, start=1):
        require(isinstance(slot, dict) and
                slot.get("slot") == n and type(slot.get("slot")) is int and
                slot.get("slug") == EXPECTED_SLUGS[n - 1], f"slot {n} identity changed")
        if n <= 3:
            require(set(slot) == {"slot", "slug", "state", "assets", "blobs"}
                    and slot["state"] == "approved", f"approved slot {n} changed")
            require(isinstance(slot["assets"], dict) and
                    isinstance(slot["blobs"], dict) and
                    set(slot["assets"]) == set(slot["blobs"]) == set(SURFACES),
                    f"slot {n}: incomplete responsive triplet")
            expected = (V1_ASSETS if n == 1 else {
                key: f"assets/profile-banners/approved/{slot['slug']}-{key}.svg"
                for key in SURFACES
            })
            require(slot["assets"] == expected, f"slot {n} assets not reviewed")
            if n == 1:
                require(slot["blobs"] == V1_BLOBS,
                        "production V1 photonic art must match accepted immutable V1 review blobs")
            for surface in SURFACES:
                require(bool(re.fullmatch(r"[0-9a-f]{40}", str(slot["blobs"][surface]))),
                        f"slot {n} missing content-addressed {surface}")
        else:
            require(set(slot) == {"slot", "slug", "state", "fallback_slot"} and
                    slot["state"] == "reserved" and slot["fallback_slot"] == 1,
                    f"unapproved art must not be activated in slot {n}")
    return slots


def validate_assets(slots: list[dict[str, Any]]) -> None:
    for slot in slots[:3]:
        for surface, path in slot["assets"].items():
            data = read_file(ROOT / path)
            require(git_blob(data) == slot["blobs"][surface],
                    f"approved art blob changed: {path}")
            if slot["slot"] == 1:
                # V1's original geometry is still verified by the immutable historical
                # delegate; this deployment pins an additional, accepted triplet.
                require(16000 <= len(data.encode("utf-8")) < 48000,
                        f"reviewed V1 artwork unexpectedly sized: {path}")
                root = ET.fromstring(data)
                require(root.tag == historical.NS + "svg" and root.get("role") == "img"
                        and root.get("aria-labelledby") == "title desc"
                        and root.get("fill") == "none"
                        and root.get("data-review-art") == "quantum-apex-photonic-depth-v1",
                        f"reviewed V1 responsive metadata invalid: {path}")
                expected_canvas = {
                    "top": ("3840", "774", "0 0 1280 258"),
                    "top-compact": ("1920", "588", "0 0 640 196"),
                    "bottom": ("3840", "450", "0 0 1280 150"),
                }[surface]
                require((root.get("width"), root.get("height"), root.get("viewBox"))
                        == expected_canvas, f"reviewed V1 canvas changed: {path}")
                style = root.find(f".//{historical.NS}style")
                require(style is not None and
                        "prefers-reduced-motion: reduce" in
                        " ".join((node.text or "") for node in root.iter(historical.NS + "style"))
                        and len(list(root.iter(historical.NS + "animate"))) >= 6
                        and len(list(root.iter(historical.NS + "feTurbulence"))) == 1,
                        f"approved V1 texture, motion or static fallback missing: {path}")
                ids = [node.get("id") for node in root.iter() if node.get("id")]
                require(len(ids) == len(set(ids)) and
                        set(re.findall(r"url\(#([^)]+)\)", data)) <= set(ids),
                        f"approved V1 internal refs or IDs invalid: {path}")
                checked = re.sub(r'\s+xmlns(?::[a-z]+)?="https?://www\.w3\.org/[^"]+"',
                                 "", data.lower())
                require(not any(v in checked for v in
                                ("<script", "<image", "<foreignobject",
                                 "javascript:", "data:image", "http://", "https://")),
                        f"approved V1 external payload forbidden: {path}")
                continue
            bounds = ((100000, 160000) if slot["slot"] == 2
                      else (150000, 200000))
            require(bounds[0] <= len(data.encode("utf-8")) < bounds[1],
                    f"approved animation source unexpectedly sized: {path}")
            lower = re.sub(r'\s+xmlns(?::[a-z]+)?="https?://www\.w3\.org/[^"]+"',
                           "", data.lower())
            require(not any(v in lower for v in
                            ("<script", "<image", "<foreignobject", "javascript:",
                             "data:image", "http://", "https://")),
                    f"approved banner source includes external payload: {path}")
            root = ET.fromstring(data)
            ns = historical.NS
            require(root.tag == ns + "svg" and root.get("role") == "img"
                    and root.get("data-banner-art") == "approved-banner-v3"
                    and root.get("data-scene") == slot["slug"]
                    and root.get("data-surface") == surface
                    and root.get("aria-labelledby") == "title desc",
                    f"approved SVG metadata invalid: {path}")
            viewbox = {
                "top": ("1280", "258", "0 0 1280 258"),
                "top-compact": ("640", "196", "320 31 640 196"),
                "bottom": ("1280", "150", "0 54 1280 150"),
            }[surface]
            require((root.get("width"), root.get("height"), root.get("viewBox"))
                    == viewbox, f"responsive {surface} viewport changed")
            require(root.find(ns + "title") is not None and
                    root.find(ns + "desc") is not None and
                    len(list(root.iter(ns + "animateTransform"))) >= 15,
                    f"approved animation/a11y missing: {path}")
            style = root.find(f".//{ns}style")
            require(style is not None and "prefers-reduced-motion" in (style.text or ""),
                    f"reduced-motion fallback missing: {path}")
            require(not any(a.get("attributeName") in
                            ({"baseFrequency", "scale", "stdDeviation"} |
                             ({"stroke-dashoffset"} if slot["slot"] == 2 else set()))
                            for a in root.iter(ns + "animate")),
                    f"frame-heavy animation regressed: {path}")
            if slot["slot"] == 3:
                # Chronohedron's closed dash loops deliberately match its photon
                # transport. Never allow scripts, off-palette colors or big halos.
                colors = set(re.findall(r"#[0-9a-fA-F]{6}\b", data))
                require(colors == {"#00FBCC", "#28D7FF", "#8C7CFF", "#FF4DE1"},
                        f"Chronohedron profile colors drifted: {path}")
                require(root.get("style") == "background-color:black" and
                        root.find(f".//{ns}g[@id='chronohedron-spectrum-perimeter']") is not None and
                        root.find(f".//{ns}g[@id='chronohedron-perimeter-underlight']") is not None and
                        root.find(f".//{ns}g[@id='chronohedron-core']") is not None,
                        f"Chronohedron opaque canvas, crystal, or rim lost: {path}")
                require(not any(tag in data for tag in (
                            "hybrid-front-containment", "hybrid-rear-containment")),
                        f"rejected side-claw geometry returned: {path}")
                ids = [node.get("id") for node in root.iter() if node.get("id")]
                require(len(ids) == len(set(ids)) and
                        set(re.findall(r"url\(#([^)]+)\)", data)) <= set(ids),
                        f"Chronohedron internal refs or IDs invalid: {path}")
                require(len(root.findall(f".//{ns}animateTransform")) == 54 and
                        len(root.findall(f".//{ns}animate")) == 131,
                        f"Chronohedron synchronized energy layers incomplete: {path}")
                require(".spectrum-motion{display:none}.spectrum-still{display:inline}"
                        in (style.text or ""),
                        f"Chronohedron reduced-motion spectral rim missing: {path}")



def load_legacy_catalog() -> list[dict[str, Any]]:
    """Freeze the original approved catalog independently of the new V1 selection."""
    raw = read_file(LEGACY_MANIFEST)
    require(git_blob(raw) == LEGACY_CATALOG_BLOB,
            "historical v3 approved catalog altered")
    spec = json.loads(raw, object_pairs_hook=unique_keys)
    require(spec["version"] == "approved-profile-banners-v3" and
            len(spec["slots"]) == 8 and
            spec["slots"][0]["assets"] == historical.ORIGINAL and
            spec["slots"][0]["blobs"] == historical.ORIGINAL_BLOBS,
            "historical v3 original triplet identity changed")
    return spec["slots"]


def legacy_v4_chosen(day: date, slots: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate the old v4 three-day marker against the old ORIGINAL for slot 1."""
    require(type(day) is date and (day - EPOCH).days >= 0,
            "legacy v4 UTC date invalid")
    archived = load_legacy_catalog()[:3]
    selected = archived[(day - EPOCH).days % 3]
    require(selected["state"] == "approved", "legacy v4 slot was unapproved")
    return {
        "version": "v4", "utc_day": day.isoformat(),
        "unix_day": (day - EPOCH).days,
        "slot": selected["slot"], "slug": selected["slug"],
        "active_slug": selected["slug"],
        **dict(selected["assets"]),
    }

def legacy_chosen(day: date, slots: list[dict[str, Any]]) -> dict[str, Any]:
    """Validate existing v3 README markers against the old eight-slot schedule."""
    require(type(day) is date, "UTC selection requires a date")
    ordinal = (day - EPOCH).days
    require(ordinal >= 0, "approved rotation cannot predate epoch")
    archival = load_legacy_catalog()
    selected = archival[ordinal % 8]
    applied = selected if selected["state"] == "approved" else archival[0]
    return {
        "version": "v3", "utc_day": day.isoformat(), "unix_day": ordinal,
        "slot": selected["slot"], "slug": selected["slug"],
        "active_slug": applied["slug"],
        **dict(applied["assets"]),
    }


def chosen(day: date, slots: list[dict[str, Any]]) -> dict[str, Any]:
    """Publish exactly one of the three approved synchronized triplets each day."""
    require(type(day) is date, "UTC selection requires a date")
    ordinal = (day - EPOCH).days
    require(ordinal >= 0, "approved rotation cannot predate epoch")
    approved = slots[:3]
    require(len(approved) == 3 and all(s["state"] == "approved" for s in approved),
            "exactly three reviewed banner triplets required")
    selected = approved[ordinal % len(approved)]
    return {
        "version": "v5", "utc_day": day.isoformat(), "unix_day": ordinal,
        "slot": selected["slot"], "slug": selected["slug"],
        "active_slug": selected["slug"],
        **dict(selected["assets"]),
    }


def referenced(readme: str, slots: list[dict[str, Any]]) -> dict[str, str]:
    approved = {slot["assets"][surface]
                for slot in slots[:3] for surface in SURFACES}
    # Only permit the exact old image set while validating a legacy v3/v4
    # publication; validate_readme_state then proves marker/art atomicity.
    approved |= {slot["assets"][surface]
                 for slot in load_legacy_catalog()[:3] for surface in SURFACES}
    observed: dict[str, str] = {}
    for surface, pattern in historical.BANNER_REFERENCE.items():
        found = pattern.findall(readme)
        require(len(found) == 1, f"README has not exactly one {surface} banner")
        path = found[0][1]
        require(path in approved, f"unapproved {surface} art forbidden: {path}")
        observed[surface] = path
    require(len(set(observed.values())) == 3,
            "each profile banner surface must have its own asset")
    require(historical.re.compile(
        r'<a\b[^>]*>(?:(?!</a>).)*<img alt="Animated evidence horizon"(?:(?!</a>).)*</a>',
        re.I | re.S
    ).search(readme) is None, "footer must remain unlinked")
    return observed


def validate_readme_state(readme: str, slots: list[dict[str, Any]]) -> dict[str, str]:
    observed = referenced(readme, slots)
    marks = list(MARKER.finditer(readme))
    require(readme.count(PREFIX) == len(marks) and len(marks) <= 1,
            "profile banner marker malformed or duplicated")
    if not marks:
        require(observed == historical.ORIGINAL,
                "unmarked README may only show approved original assets")
        return observed
    version_text, date_text, slot_text, slug = marks[0].groups()
    day = date.fromisoformat(date_text)
    expected = (legacy_chosen(day, slots) if version_text == "3" else
                legacy_v4_chosen(day, slots) if version_text == "4" else
                chosen(day, slots))
    require(int(slot_text) == expected["slot"] and slug == expected["slug"],
            "profile banner slot/date marker does not match reviewed UTC schedule")
    require(observed == {surface: expected[surface] for surface in SURFACES},
            "profile banner marker and atomic triplet disagree")
    return observed


def propose(readme: str, selection: dict[str, Any],
            slots: list[dict[str, Any]]) -> str:
    validate_readme_state(readme, slots)
    require(selection["version"] == "v5", "v5 selection required")
    # Caller may not fabricate a slot or use an unsupported old UTC day.
    assert_selection = chosen(date.fromisoformat(selection["utc_day"]), slots)
    require(selection == assert_selection, "banner selector is not canonical")
    marks = list(MARKER.finditer(readme))
    marker = (f"<!-- banner-rotation:v5 utc-day={selection['utc_day']} "
              f"slot={selection['slot']} slug={selection['slug']} -->")
    if marks:
        mark = marks[0]
        existing_day = date.fromisoformat(mark.group(2))
        require(date.fromisoformat(selection["utc_day"]) >= existing_day,
                "approved banner UTC-day rollback forbidden")
        output = readme[:mark.start()] + marker + readme[mark.end():]
    else:
        require(readme.count(HEADER_ANCHOR) == 1,
                "canonical hero banner anchor must be unambiguous")
        output = readme.replace(HEADER_ANCHOR, marker + "\n" + HEADER_ANCHOR, 1)
    for surface, pattern in historical.BANNER_REFERENCE.items():
        output, replaced = pattern.subn(
            lambda m: m.group(1) + selection[surface], output)
        require(replaced == 1, f"atomic banner {surface} rewrite failed")
    validate_readme_state(output, slots)
    require(output.count(marker) == 1, "banner proposal lost marker")
    return output


def self_test(slots: list[dict[str, Any]]) -> None:
    hero = ('<p align="center">\n<picture>\n'
            '  <source media="(max-width: 640px)" srcset="' +
            historical.ORIGINAL["top-compact"] + '">\n'
            '  <img alt="Animated quantum apex signal crown" src="' +
            historical.ORIGINAL["top"] + '" width="100%">\n'
            '</picture>\n</p>')
    footer = ('<p align="center">\n<picture>\n'
              '<img alt="Animated evidence horizon" src="' +
              historical.ORIGINAL["bottom"] + '" width="100%">\n'
              '</picture></p>')
    initial = hero + '\n<p>Spotlight must stay unchanged</p>\n' + footer
    orders = [chosen(date.fromordinal(EPOCH.toordinal() + n), slots)
              for n in range(17)]
    require([v["slot"] for v in orders] == [1, 2, 3] * 5 + [1, 2],
            "approved trio must change daily without reserved-slot gaps")
    require(len(set(v["active_slug"] for v in orders[:3])) == 3,
            "each approved triplet must appear once per three UTC days")
    require(chosen(date(2026, 10, 17), slots)["slot"] == 3 and
            chosen(date(2026, 10, 18), slots)["slot"] == 1,
            "reserved-slot stall must not recur")
    require(chosen(date(2026, 10, 13), slots)["active_slug"] == "02-fractal-iris",
            "Fractal Iris was not assigned slot 2 on first cycle day")
    require(chosen(date(2026, 10, 14), slots)["active_slug"] == "03-chronohedron",
            "Chronohedron is not the third active UTC-day triplet")
    require(chosen(date(2027, 1, 1), slots)["slot"] ==
            (date(2027, 1, 1)-EPOCH).days%3+1, "year rollover broken")
    # The published v3 slot-six state is original art; migration must be
    # atomic, monotonic and repeatable without editing prior provenance.
    legacy_day = date(2026, 10, 17)
    legacy = legacy_chosen(legacy_day, slots)
    require(legacy["slot"] == 6 and legacy["active_slug"] == "01-original-quantum-apex",
            "legacy reserved-slot fixture changed")
    legacy_marker = (f"<!-- banner-rotation:v3 utc-day={legacy_day.isoformat()} "
                     f"slot={legacy['slot']} slug={legacy['slug']} -->")
    legacy_readme = initial.replace(HEADER_ANCHOR, legacy_marker + "\n" + HEADER_ANCHOR, 1)
    require(legacy_readme != initial and
            validate_readme_state(legacy_readme, slots) == historical.ORIGINAL,
            "legacy original-triplet marker must validate")
    migrated = propose(legacy_readme, chosen(legacy_day, slots), slots)
    require("<!-- banner-rotation:v5 utc-day=2026-10-17 slot=3 slug=03-chronohedron -->"
            in migrated and
            validate_readme_state(migrated, slots)["top"] == slots[2]["assets"]["top"],
            "legacy v3 migration must publish complete approved third triplet")
    require(propose(migrated, chosen(legacy_day, slots), slots) == migrated,
            "v5 migration replay must be idempotent")
    # Acceptance regression: today's v4 original must migrate directly to the
    # reviewed V1 triplet on the *same UTC day*, never break the original marker.
    old_oct18 = legacy_v4_chosen(date(2026, 10, 18), slots)
    require(old_oct18["slug"] == "01-original-quantum-apex" and
            old_oct18["top"] == historical.ORIGINAL["top"],
            "published 2026-10-18 v4 marker no longer resolves original")
    v4_readme = initial.replace(
        HEADER_ANCHOR,
        "<!-- banner-rotation:v4 utc-day=2026-10-18 slot=1 slug=01-original-quantum-apex -->\n"
        + HEADER_ANCHOR, 1,
    )
    require(validate_readme_state(v4_readme, slots) == historical.ORIGINAL,
            "existing v4 main README original snapshot is not admissible")
    today = chosen(date(2026, 10, 18), slots)
    require(today["slot"] == 1 and today["slug"] == "01-photonic-depth" and
            today["top"] == V1_ASSETS["top"] and today["bottom"] == V1_ASSETS["bottom"],
            "approved V1 must replace slot 1 without changing the rotation")
    activated = propose(v4_readme, today, slots)
    require("<!-- banner-rotation:v5 utc-day=2026-10-18 slot=1 slug=01-photonic-depth -->"
            in activated and
            validate_readme_state(activated, slots) ==
            {surface: V1_ASSETS[surface] for surface in SURFACES},
            "v4 -> v5 V1 publication must update all surfaces atomically")
    require(propose(activated, today, slots) == activated,
            "V1 publication replay must be idempotent")
    # The very next UTC day continues with unchanged Fractal Iris.
    tomorrow = chosen(date(2026, 10, 19), slots)
    require(tomorrow["slot"] == 2 and
            tomorrow["top"] == slots[1]["assets"]["top"] and
            validate_readme_state(propose(activated, tomorrow, slots), slots) ==
            {surface: tomorrow[surface] for surface in SURFACES},
            "V1 activation interrupted the deterministic existing daily cycle")
    cur = initial
    for v in orders[:9]:
        nxt = propose(cur, v, slots)
        require(propose(nxt, v, slots) == nxt,
                "same-day proposal must be replay safe")
        require(validate_readme_state(nxt, slots) ==
                {surface: v[surface] for surface in SURFACES},
                "banner top/compact/footer diverged")
        require("Spotlight must stay unchanged" in nxt,
                "banner proposal touched other README blocks")
        cur = nxt
    try:
        propose(cur, orders[0], slots)
    except ValueError as exc:
        require("rollback" in str(exc), "replay rejected for unexpected reason")
    else:
        raise ValueError("backdated banner proposal incorrectly admitted")
    corrupt = cur.replace(orders[8]["top"],
                          "assets/profile-banners/daily/01-orbital-relay-top.svg", 1)
    require(corrupt != cur, "corruption fixture failed to change banner")
    try:
        validate_readme_state(corrupt, slots)
    except ValueError:
        pass
    else:
        raise ValueError("archived unapproved banner escaped approved-only guard")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    ops = parser.add_mutually_exclusive_group(required=True)
    for cmd in ("check", "self-test", "select", "propose"):
        ops.add_argument("--" + cmd, action="store_true")
    parser.add_argument("--date", help="UTC YYYY-MM-DD; defaults to current UTC day")
    args = parser.parse_args()
    try:
        slots = load_catalog()
        if args.check:
            validate_assets(slots)
            print("Approved banner assets verified: V1 Photonic Depth + Fractal Iris + Chronohedron, three-day active cycle")
        elif args.self_test:
            validate_assets(slots)
            self_test(slots)
            print("Approved 3-day UTC rotation: v3/v4 migration to v5, idempotent, fail-closed, responsive")
        else:
            day = date.fromisoformat(args.date) if args.date else datetime.now(timezone.utc).date()
            choice = chosen(day, slots)
            if args.select:
                print(json.dumps(choice, sort_keys=True, separators=(",", ":")))
            else:
                print(propose(read_file(ROOT / "README.md"), choice, slots), end="")
        return 0
    except (ValueError, TypeError, OSError, ET.ParseError) as exc:
        print(f"ERROR: approved banner rotation: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
