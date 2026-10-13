#!/usr/bin/env python3
"""Fail-closed approved-only eight-slot UTC profile banner rotation.

Only slots one (original) and two (Fractal Iris) are approved. Slots 3-8 are
reserved with exact original fallback and may not publish archived experiments.
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
MANIFEST = ROOT / "scripts/approved-banner-rotation-v3.json"
EPOCH = date(2026, 10, 12)
SURFACES = ("top", "top-compact", "bottom")
MARKER = re.compile(
    r"^<!-- banner-rotation:v3 utc-day=(\d{4}-\d{2}-\d{2}) "
    r"slot=([1-8]) slug=(0[1-8]-[a-z-]+) -->$", re.MULTILINE,
)
PREFIX = "<!-- banner-rotation:"
HEADER_ANCHOR = '<p align="center">\n<picture>\n  <source media="(max-width: 640px)" '
EXPECTED_SLUGS = (
    "01-original-quantum-apex", "02-fractal-iris", "03-reserved",
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
    require(raw["version"] == "approved-profile-banners-v3" and
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
        if n <= 2:
            require(set(slot) == {"slot", "slug", "state", "assets", "blobs"}
                    and slot["state"] == "approved", f"approved slot {n} changed")
            require(isinstance(slot["assets"], dict) and
                    isinstance(slot["blobs"], dict) and
                    set(slot["assets"]) == set(slot["blobs"]) == set(SURFACES),
                    f"slot {n}: incomplete responsive triplet")
            expected = historical.ORIGINAL if n == 1 else {
                key: f"assets/profile-banners/approved/02-fractal-iris-{key}.svg"
                for key in SURFACES
            }
            require(slot["assets"] == expected, f"slot {n} assets not reviewed")
            if n == 1:
                require(slot["blobs"] == historical.ORIGINAL_BLOBS,
                        "original art blob identity changed")
            for surface in SURFACES:
                require(bool(re.fullmatch(r"[0-9a-f]{40}", str(slot["blobs"][surface]))),
                        f"slot {n} missing content-addressed {surface}")
        else:
            require(set(slot) == {"slot", "slug", "state", "fallback_slot"} and
                    slot["state"] == "reserved" and slot["fallback_slot"] == 1,
                    f"unapproved art must not be activated in slot {n}")
    return slots


def validate_assets(slots: list[dict[str, Any]]) -> None:
    for slot in slots[:2]:
        for surface, path in slot["assets"].items():
            data = read_file(ROOT / path)
            require(git_blob(data) == slot["blobs"][surface],
                    f"approved art blob changed: {path}")
            if slot["slot"] == 1:
                continue
            require(100000 <= len(data.encode("utf-8")) < 160000,
                    f"iris source unexpectedly truncated or inflated: {path}")
            lower = re.sub(r'\s+xmlns(?::[a-z]+)?="https?://www\.w3\.org/[^"]+"',
                           "", data.lower())
            require(not any(v in lower for v in
                            ("<script", "<image", "<foreignobject", "javascript:",
                             "data:image", "http://", "https://")),
                    f"iris source includes external payload: {path}")
            root = ET.fromstring(data)
            ns = historical.NS
            require(root.tag == ns + "svg" and root.get("role") == "img"
                    and root.get("data-banner-art") == "approved-banner-v3"
                    and root.get("data-scene") == "02-fractal-iris"
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
                    f"iris animation/a11y missing: {path}")
            style = root.find(f".//{ns}style")
            require(style is not None and "prefers-reduced-motion" in (style.text or ""),
                    f"reduced-motion fallback missing: {path}")
            require(not any(a.get("attributeName") in
                            {"baseFrequency", "scale", "stdDeviation", "stroke-dashoffset"}
                            for a in root.iter(ns + "animate")),
                    f"frame-heavy animation regressed: {path}")


def chosen(day: date, slots: list[dict[str, Any]]) -> dict[str, Any]:
    require(type(day) is date, "UTC selection requires a date")
    ordinal = (day - EPOCH).days
    require(ordinal >= 0, "approved rotation cannot predate epoch")
    selected = slots[ordinal % 8]
    applied = selected if selected["state"] == "approved" else slots[0]
    return {
        "version": "v3", "utc_day": day.isoformat(), "unix_day": ordinal,
        "slot": selected["slot"], "slug": selected["slug"],
        "active_slug": applied["slug"],
        **dict(applied["assets"]),
    }


def referenced(readme: str, slots: list[dict[str, Any]]) -> dict[str, str]:
    approved = {slot["assets"][surface]
                for slot in slots[:2] for surface in SURFACES}
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
    date_text, slot_text, slug = marks[0].groups()
    expected = chosen(date.fromisoformat(date_text), slots)
    require(int(slot_text) == expected["slot"] and slug == expected["slug"],
            "profile banner slot/date marker does not match reviewed UTC schedule")
    require(observed == {surface: expected[surface] for surface in SURFACES},
            "profile banner marker and atomic triplet disagree")
    return observed


def propose(readme: str, selection: dict[str, Any],
            slots: list[dict[str, Any]]) -> str:
    validate_readme_state(readme, slots)
    require(selection["version"] == "v3", "v3 selection required")
    # Caller may not fabricate a slot or use an unsupported old UTC day.
    assert_selection = chosen(date.fromisoformat(selection["utc_day"]), slots)
    require(selection == assert_selection, "banner selector is not canonical")
    marks = list(MARKER.finditer(readme))
    marker = (f"<!-- banner-rotation:v3 utc-day={selection['utc_day']} "
              f"slot={selection['slot']} slug={selection['slug']} -->")
    if marks:
        mark = marks[0]
        existing_day = date.fromisoformat(mark.group(1))
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
    require([v["slot"] for v in orders] == list(range(1,9))*2+[1],
            "eight-slot UTC timeline lost a position")
    require([v["active_slug"] for v in orders[:8]] ==
            ["01-original-quantum-apex","02-fractal-iris"] +
            ["01-original-quantum-apex"]*6,
            "unapproved slots are no longer pinned to original")
    require(chosen(date(2026, 10, 13), slots)["slot"] == 2,
            "Fractal Iris was not assigned slot 2 on first cycle day")
    require(chosen(date(2027, 1, 1), slots)["slot"] ==
            (date(2027, 1, 1)-EPOCH).days%8+1, "year rollover broken")
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
    corrupt = cur.replace(historical.ORIGINAL["top"],
                          "assets/profile-banners/daily/01-orbital-relay-top.svg", 1)
    try:
        validate_readme_state(corrupt, slots)
    except ValueError:
        pass
    else:
        raise ValueError("archived unapproved banner escaped approved-only guard")
    # Read-only trusted-source measurement for prior authorization review.
    # This does not admit capabilities or write any repository state. It prints
    # a non-sensitive digest binding for an independently reviewed ledger PR.
    import workflow_capability_tcb as trust_source
    import workflow_capability_snapshot as trust_snapshot
    import workflow_capability_diff as trust_diff
    tcb_digest = trust_source.protected_digest(trust_source.protected_files(ROOT))
    trusted_base_bom = trust_diff.digest(trust_snapshot.load_combined())
    print("Approved banner prior-review measurement: "
          f"candidateTcbSha256={tcb_digest} baseBomSha256={trusted_base_bom}")



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
            print("Approved banner assets verified: original + Fractal Iris, slot 2 of 8")
        elif args.self_test:
            validate_assets(slots)
            self_test(slots)
            print("Approved 8-slot UTC rotation: idempotent, fail-closed, responsive")
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
