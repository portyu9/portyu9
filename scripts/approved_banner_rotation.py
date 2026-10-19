#!/usr/bin/env python3
"""Fail-closed four-day UTC rotation of four content-addressed profile banner triplets.

Slot 1 = accepted Quantum Apex V2; slot 4 = latest owner-approved Tides V3.
Slots 2 and 3 remain unchanged; 5-8 remain reserved. Source originals preserved.
Old v3/v4/v5/v6 markers are verified against exact immutable historic catalogs.
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
MANIFEST = ROOT / "scripts/approved-banner-rotation-v6.json"
PREVIOUS_LIVE_MANIFEST = ROOT / "scripts/approved-banner-rotation-v5.json"
PREVIOUS_LIVE_CATALOG_BLOB = "c8853e05175d6a3ee99604d43f773325e49e2e3d"
PRIOR_MANIFEST = ROOT / "scripts/approved-banner-rotation-v4.json"
PRIOR_CATALOG_BLOB = "5bca6135bc963e1eafa97cd70360f4847de670aa"
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
V2_ASSETS = {
    surface: f"assets/profile-banners/approved/01-quantum-apex-luminous-singularity-v2-{surface}.svg"
    for surface in ("top", "top-compact", "bottom")
}
V2_BLOBS = {
    "top": "f7cf024a8343f9904f63c314d5bc72f87e5049f7",
    "top-compact": "256a5315728bc0778d941df24ba3b860f5a67f3a",
    "bottom": "61419a4e18f055ca8843071402f37e9868812e5a",
}
TIDES_ASSETS = {
    surface: f"assets/profile-banners/approved/04-lagrange-tides-{surface}.svg"
    for surface in ("top", "top-compact", "bottom")
}
TIDES_BLOBS = {
    "top": "be373e0a4b601ae4f136797e2ddb96ea519d8f36",
    "top-compact": "34cf94c290e16bc0c02704f4c7b79a5fdb3f4fe1",
    "bottom": "8b8719635237cc9bbb785bd2dc20d38479a0a009",
}
TIDES_V3_ASSETS = {
    surface: f"assets/profile-banners/approved/04-lagrange-tides-v3-kinetic-{surface}.svg"
    for surface in ("top", "top-compact", "bottom")
}
TIDES_V3_BLOBS = {
    "top": "ef87051144ccb9717e451045b4cb015e614e2360",
    "top-compact": "d382ff8e113aaccda0c1a43a1ea729302d5a994c",
    "bottom": "30ba13c09b9cae8dacd7d1a1543f8ce557341bc6",
}
EPOCH = date(2026, 10, 12)
SURFACES = ("top", "top-compact", "bottom")
MARKER = re.compile(
    r"^<!-- banner-rotation:v([34567]) utc-day=(\d{4}-\d{2}-\d{2}) "
    r"slot=([1-8]) slug=(0[1-8]-[a-z-]+) -->$", re.MULTILINE,
)
PREFIX = "<!-- banner-rotation:"
HEADER_ANCHOR = '<p align="center">\n<picture>\n  <source media="(max-width: 640px)" '
EXPECTED_SLUGS = (
    "01-luminous-singularity", "02-fractal-iris", "03-chronohedron",
    "04-lagrange-tides", "05-reserved", "06-reserved", "07-reserved", "08-reserved",
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
    require(raw["version"] == "approved-profile-banners-v6" and
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
        if n <= 4:
            require(set(slot) == {"slot", "slug", "state", "assets", "blobs"}
                    and slot["state"] == "approved", f"approved slot {n} changed")
            require(isinstance(slot["assets"], dict) and
                    isinstance(slot["blobs"], dict) and
                    set(slot["assets"]) == set(slot["blobs"]) == set(SURFACES),
                    f"slot {n}: incomplete responsive triplet")
            expected = (V2_ASSETS if n == 1 else
                        TIDES_V3_ASSETS if n == 4 else {
                key: f"assets/profile-banners/approved/{slot['slug']}-{key}.svg"
                for key in SURFACES
            })
            require(slot["assets"] == expected, f"slot {n} assets not reviewed")
            if n in (1, 4):
                require(slot["blobs"] == (V2_BLOBS if n == 1 else TIDES_V3_BLOBS),
                        "production art must be identical to accepted V2/slot4 review blobs")
            for surface in SURFACES:
                require(bool(re.fullmatch(r"[0-9a-f]{40}", str(slot["blobs"][surface]))),
                        f"slot {n} missing content-addressed {surface}")
        else:
            require(set(slot) == {"slot", "slug", "state", "fallback_slot"} and
                    slot["state"] == "reserved" and slot["fallback_slot"] == 1,
                    f"unapproved art must not be activated in slot {n}")
    return slots


def validate_assets(slots: list[dict[str, Any]]) -> None:
    for slot in slots[:4]:
        for surface, path in slot["assets"].items():
            data = read_file(ROOT / path)
            require(git_blob(data) == slot["blobs"][surface],
                    f"approved art blob changed: {path}")
            if slot["slot"] in (1, 4):
                # Exact accepted, independent review SVG files with safe self-contained
                # motion, bounded texture and an explicit reduced-motion static state.
                n = slot["slot"]
                bounds = (40000, 85000) if n == 1 else (215000, 305000)
                require(bounds[0] <= len(data.encode("utf-8")) <= bounds[1],
                        f"approved V2/slot4 image size outside reviewed envelope: {path}")
                root = ET.fromstring(data)
                ns = historical.NS
                expected_art = ("quantum-apex-photonic-depth-v2"
                                if n == 1 else "slot4-lagrange-tides-v3")
                view = {
                    "top": ("3840", "774", "0 0 1280 258"),
                    "top-compact": ("1920", "588", "0 0 640 196"),
                    "bottom": ("3840", "450", "0 0 1280 150"),
                }[surface]
                require(root.tag == ns + "svg" and root.get("role") == "img"
                        and root.get("aria-labelledby") == "title desc"
                        and root.get("fill") == "none"
                        and root.get("data-review-art") == expected_art
                        and (root.get("width"), root.get("height"), root.get("viewBox"))
                        == view and root.find(ns + "title") is not None
                        and root.find(ns + "desc") is not None,
                        f"slot {n} approved responsive/a11y metadata invalid: {path}")
                styles = " ".join((style.text or "")
                                  for style in root.iter(ns + "style"))
                require("prefers-reduced-motion" in styles
                        and len(list(root.iter(ns + "animate"))) >= 20
                        and len(list(root.iter(ns + "feTurbulence"))) >= 1,
                        f"slot {n} approved motion, grain, static fallback missing: {path}")
                if n == 4:
                    require(".kinetic{display:none!important}" in styles
                            and ".still{display:inline!important}" in styles
                            and ".v2-live{display:none!important}" in styles
                            and ".v3-motion{display:none!important}" in styles
                            and len(list(root.iter(ns + "animateMotion"))) >= 17
                            and len([a for a in root.iter(ns + "animate")
                                     if a.get("attributeName") == "d"]) == 16
                            and len([a for a in root.iter(ns + "animateTransform")
                                     if a.get("type") == "translate"]) >= 11
                            and root.find(f".//{ns}g[@data-motion='volume-weave']") is not None
                            and root.find(f".//{ns}g[@data-motion='flowing-photonic-transport']") is not None
                            and len(list(root.iter(ns + "clipPath"))) >= 4,
                            f"slot {n} latest V3 weave, flow, morph, pulse contract missing: {path}")
                    require(not any(a.get("attributeName") in
                                    {"baseFrequency", "scale", "stdDeviation"}
                                    for a in root.iter(ns + "animate")),
                            f"slot {n} expensive dynamic SVG filter forbidden: {path}")
                ids = [node.get("id") for node in root.iter() if node.get("id")]
                require(len(ids) == len(set(ids)) and
                        set(re.findall(r"url\(#([^)]+)\)", data)) <= set(ids),
                        f"slot {n} duplicate IDs / dangling paint references: {path}")
                safe = re.sub(r'\s+xmlns(?::[a-z]+)?="https?://www\.w3\.org/[^"]+"',
                              "", data.lower())
                require(not any(fragment in safe for fragment in
                                ("<script", "<image", "<foreignobject", "javascript:",
                                 "data:image", "http://", "https://")),
                        f"slot {n} contains unreviewed external/active payload: {path}")
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


def load_previous_live_catalog() -> list[dict[str, Any]]:
    """Freeze accepted V6 Tides V1 state for historical README validation."""
    contents = read_file(PREVIOUS_LIVE_MANIFEST)
    require(git_blob(contents) == PREVIOUS_LIVE_CATALOG_BLOB,
            "previously published four-slot catalog altered")
    spec = json.loads(contents, object_pairs_hook=unique_keys)
    require(spec["version"] == "approved-profile-banners-v5"
            and len(spec["slots"]) == 8
            and [slot["state"] for slot in spec["slots"]] ==
            ["approved"] * 4 + ["reserved"] * 4
            and spec["slots"][0]["blobs"] == V2_BLOBS
            and spec["slots"][3]["assets"] == TIDES_ASSETS
            and spec["slots"][3]["blobs"] == TIDES_BLOBS,
            "previous live v6 art is not frozen exactly")
    return spec["slots"]


def legacy_v6_chosen(day: date, slots: list[dict[str, Any]]) -> dict[str, Any]:
    require(type(day) is date and (day - EPOCH).days >= 0,
            "previous live UTC day invalid")
    archived = load_previous_live_catalog()[:4]
    ordinal = (day - EPOCH).days
    selected = archived[ordinal % len(archived)]
    return {
        "version": "v6", "utc_day": day.isoformat(), "unix_day": ordinal,
        "slot": selected["slot"], "slug": selected["slug"],
        "active_slug": selected["slug"], **dict(selected["assets"]),
    }


def load_prior_catalog() -> list[dict[str, Any]]:
    """Freeze V1 Photonic Depth / Iris / Chronohedron for legacy v5 replay."""
    raw = read_file(PRIOR_MANIFEST)
    require(git_blob(raw) == PRIOR_CATALOG_BLOB,
            "previously approved v4 three-day catalog altered")
    spec = json.loads(raw, object_pairs_hook=unique_keys)
    require(spec["version"] == "approved-profile-banners-v4"
            and len(spec["slots"]) == 8
            and spec["slots"][0]["assets"] == V1_ASSETS
            and spec["slots"][0]["blobs"] == V1_BLOBS
            and [slot["state"] for slot in spec["slots"]] ==
            ["approved"] * 3 + ["reserved"] * 5,
            "legacy v5 three-day catalog changed")
    return spec["slots"]


def legacy_v5_chosen(day: date, slots: list[dict[str, Any]]) -> dict[str, Any]:
    """Match already published v5 markers to the frozen old three-day schedule."""
    require(type(day) is date and (day - EPOCH).days >= 0,
            "legacy v5 UTC day invalid")
    archived = load_prior_catalog()[:3]
    ordinal = (day - EPOCH).days
    selected = archived[ordinal % 3]
    return {
        "version": "v5", "utc_day": day.isoformat(),
        "unix_day": ordinal, "slot": selected["slot"],
        "slug": selected["slug"], "active_slug": selected["slug"],
        **dict(selected["assets"]),
    }


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
    """Publish exactly one of four approved synchronized triplets each UTC day."""
    require(type(day) is date, "UTC selection requires a date")
    ordinal = (day - EPOCH).days
    require(ordinal >= 0, "approved rotation cannot predate epoch")
    approved = slots[:4]
    require(len(approved) == 4 and all(s["state"] == "approved" for s in approved),
            "exactly four reviewed banner triplets required")
    selected = approved[ordinal % len(approved)]
    return {
        "version": "v7", "utc_day": day.isoformat(), "unix_day": ordinal,
        "slot": selected["slot"], "slug": selected["slug"],
        "active_slug": selected["slug"],
        **dict(selected["assets"]),
    }


def referenced(readme: str, slots: list[dict[str, Any]]) -> dict[str, str]:
    approved = {slot["assets"][surface]
                for slot in slots[:4] for surface in SURFACES}
    approved |= {slot["assets"][surface]
                 for slot in load_previous_live_catalog()[:4] for surface in SURFACES}
    approved |= {slot["assets"][surface]
                 for slot in load_prior_catalog()[:3] for surface in SURFACES}
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
                legacy_v5_chosen(day, slots) if version_text == "5" else
                legacy_v6_chosen(day, slots) if version_text == "6" else
                chosen(day, slots))
    require(int(slot_text) == expected["slot"] and slug == expected["slug"],
            "profile banner slot/date marker does not match reviewed UTC schedule")
    require(observed == {surface: expected[surface] for surface in SURFACES},
            "profile banner marker and atomic triplet disagree")
    return observed


def propose(readme: str, selection: dict[str, Any],
            slots: list[dict[str, Any]]) -> str:
    validate_readme_state(readme, slots)
    require(selection["version"] == "v7", "v7 selection required")
    # Caller may not fabricate a slot or use an unsupported old UTC day.
    assert_selection = chosen(date.fromisoformat(selection["utc_day"]), slots)
    require(selection == assert_selection, "banner selector is not canonical")
    marks = list(MARKER.finditer(readme))
    marker = (f"<!-- banner-rotation:v7 utc-day={selection['utc_day']} "
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
    """Legacy three-generation replay, strict four-day cycle and atomic rollout."""
    hero = ('<p align="center">\n<picture>\n'
            '  <source media="(max-width: 640px)" srcset="'
            + historical.ORIGINAL["top-compact"] + '">\n'
            '  <img alt="Animated quantum apex signal crown" src="'
            + historical.ORIGINAL["top"] + '" width="100%">\n'
            '</picture>\n</p>')
    footer = ('<p align="center">\n<picture>\n'
              '<img alt="Animated evidence horizon" src="'
              + historical.ORIGINAL["bottom"] + '" width="100%">\n'
              '</picture></p>')
    initial = hero + '\n<p>Spotlight must stay unchanged</p>\n' + footer
    orders = [chosen(date.fromordinal(EPOCH.toordinal() + n), slots)
              for n in range(29)]
    require([x["slot"] for x in orders] == [1, 2, 3, 4] * 7 + [1]
            and len(set(x["active_slug"] for x in orders[:4])) == 4,
            "four active triplets must rotate daily, no gaps")
    require([chosen(date(2026, 10, 19 + n), slots)["slot"]
             for n in range(4)] == [4, 1, 2, 3],
            "four-day epoch continuity or slot order changed")
    require(chosen(date(2027, 1, 1), slots)["slot"] ==
            (date(2027, 1, 1) - EPOCH).days % 4 + 1,
            "four-day year rollover broken")
    # Preserve exact legacy snapshots: 8-day v3 original/reserved fallback,
    # three-day v4 original, and currently live three-day v5 Photonic Depth.
    past = date(2026, 10, 17)
    old3 = legacy_chosen(past, slots)
    require(old3["slot"] == 6 and
            old3["active_slug"] == "01-original-quantum-apex",
            "legacy v3 original fallback mutated")
    legacy_cases = [
        (old3, historical.ORIGINAL),
        (legacy_v4_chosen(date(2026, 10, 18), slots), historical.ORIGINAL),
        (legacy_v5_chosen(date(2026, 10, 18), slots), V1_ASSETS),
        (legacy_v6_chosen(date(2026, 10, 19), slots), TIDES_ASSETS),
    ]
    for old, expected_paths in legacy_cases:
        stamp = (f"<!-- banner-rotation:{old['version']} utc-day={old['utc_day']} "
                 f"slot={old['slot']} slug={old['slug']} -->")
        readme = initial.replace(HEADER_ANCHOR,
                                 stamp + "\n" + HEADER_ANCHOR, 1)
        for surface, pattern in historical.BANNER_REFERENCE.items():
            readme, replacements = pattern.subn(
                lambda m: m.group(1) + old[surface], readme)
            require(replacements == 1, "legacy snapshot missing banner")
        require(validate_readme_state(readme, slots) == expected_paths,
                "legacy v3/v4/v5 source and README marker proof changed")
        selected = chosen(date.fromisoformat(old["utc_day"]), slots)
        upgraded = propose(readme, selected, slots)
        require("<!-- banner-rotation:v7 " in upgraded and
                validate_readme_state(upgraded, slots) ==
                {s: selected[s] for s in SURFACES} and
                propose(upgraded, selected, slots) == upgraded,
                "old marker -> new 4-day rotation must be atomic and idempotent")
    # Actual currently published v5 2026-10-18 state must migrate without day
    # rollback or a mismatched triplet, including crossing 2026-10-19 UTC.
    old_live = legacy_v5_chosen(date(2026, 10, 18), slots)
    old_marker = (f"<!-- banner-rotation:v5 utc-day={old_live['utc_day']} "
                  f"slot={old_live['slot']} slug={old_live['slug']} -->")
    live = initial.replace(HEADER_ANCHOR, old_marker + "\n" + HEADER_ANCHOR, 1)
    for surface, pattern in historical.BANNER_REFERENCE.items():
        live, n = pattern.subn(lambda m: m.group(1) + old_live[surface], live)
        require(n == 1, "current v5 snapshot has missing original surface")
    today = chosen(date(2026, 10, 19), slots)
    require(today["slot"] == 4 and today["slug"] == "04-lagrange-tides"
            and today["top"] == TIDES_V3_ASSETS["top"]
            and today["bottom"] == TIDES_V3_ASSETS["bottom"],
            "2026-10-19 UTC must select approved Tides triplet")
    switched = propose(live, today, slots)
    require(validate_readme_state(switched, slots) == TIDES_V3_ASSETS,
            "v5-to-v6 cutover did not atomically activate Tides")
    # Already-published v6 slot4 V1 must upgrade atomically to V3 on same
    # UTC day, without rejecting valid older markers or mixing SVG surfaces.
    old_v6 = legacy_v6_chosen(date(2026, 10, 19), slots)
    old_marker = (f"<!-- banner-rotation:v6 utc-day={old_v6['utc_day']} "
                  f"slot={old_v6['slot']} slug={old_v6['slug']} -->")
    old_readme = initial.replace(HEADER_ANCHOR,
                                 old_marker + "\n" + HEADER_ANCHOR, 1)
    for surface, pattern in historical.BANNER_REFERENCE.items():
        old_readme, n = pattern.subn(lambda m: m.group(1) + old_v6[surface],
                                     old_readme)
        require(n == 1, "old v6 surface missing")
    require(validate_readme_state(old_readme, slots) == TIDES_ASSETS,
            "previous V1 live profile cannot be read")
    promoted = propose(old_readme, today, slots)
    require(validate_readme_state(promoted, slots) == TIDES_V3_ASSETS
            and propose(promoted, today, slots) == promoted
            and "<!-- banner-rotation:v7 " in promoted,
            "same-day latest V3 must replace entire Tides V1 triplet")
    next_v2 = chosen(date(2026, 10, 20), slots)
    require(next_v2["slot"] == 1
            and next_v2["top"] == V2_ASSETS["top"],
            "2026-10-20 UTC must select Quantum Apex V2")
    moved = propose(switched, next_v2, slots)
    require(validate_readme_state(moved, slots) == V2_ASSETS,
            "next UTC day does not display approved Quantum Apex V2")
    cur = initial
    for selection in orders[:12]:
        nxt = propose(cur, selection, slots)
        require(propose(nxt, selection, slots) == nxt and
                validate_readme_state(nxt, slots) ==
                {s: selection[s] for s in SURFACES}
                and "Spotlight must stay unchanged" in nxt,
                "four-slot README proposal is non-atomic or non-idempotent")
        cur = nxt
    try:
        propose(cur, orders[0], slots)
    except ValueError as exc:
        require("rollback" in str(exc), "rollback denied for unexpected reason")
    else:
        raise ValueError("UTC date rollback silently admitted")
    corrupt = cur.replace(orders[11]["top"],
                          "assets/profile-banners/daily/01-orbital-relay-top.svg", 1)
    require(corrupt != cur, "corruption fixture did not mutate README")
    try:
        validate_readme_state(corrupt, slots)
    except ValueError:
        pass
    else:
        raise ValueError("unapproved historic banner escaped guarded selector")


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
            print("Approved banner assets verified: Quantum Apex V2, Fractal Iris, Chronohedron, Lagrange Tides V3 latest — four-day cycle")
        elif args.self_test:
            validate_assets(slots)
            self_test(slots)
            print("Approved 4-day UTC rotation: v3/v4/v5/v6 to v7 latest V3, idempotent, fail-closed, responsive")
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
