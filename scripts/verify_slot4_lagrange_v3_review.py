#!/usr/bin/env python3
"""Read-only, fail-closed assurance of self-contained kinetic Lagrange Tides V3.

Run manually against the proposed review branch:
    python3 scripts/verify_slot4_lagrange_v3_review.py

This does NOT promote or publish a banner. It protects the accepted V1/V2
visual lineage and the current production rotation while validating that V3
actually weaves, translates, morphs, pulses and transports photons.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets/profile-banners/review"
NS = "{http://www.w3.org/2000/svg}"
PALETTE = {
    "#01040E", "#091529", "#100921", "#020510",
    "#42E6FF", "#66FFD0", "#B68AFF", "#FF4ED4", "#F1FAFF",
}
V3 = (
    ("top", "87507b866caf359a6c3edfc76c06ad97f539ddc5",
     "b1c0b6ccc5449b497c54cafdaf2f2fbb0cf47c4e",
     ("3840", "774", "0 0 1280 258"), 290338, 15, 22, 7),
    ("top-compact", "e7234689af9d29767fc8f6f1b7c0b9cddb14f874",
     "4c6b27abb8e7d9a5d0d93e35e1f3b9dc725d1a5a",
     ("1920", "588", "0 0 640 196"), 224811, 9, 13, 5),
    ("bottom", "57aae2dd4919fc9ffdf848dd85eb4d0bcc659bf4",
     "5684296283fb7b51c32521388a8bc282de66c1d7",
     ("3840", "450", "0 0 1280 150"), 254733, 12, 17, 7),
)
ORIGINAL_V1 = {
    "top": "be373e0a4b601ae4f136797e2ddb96ea519d8f36",
    "top-compact": "34cf94c290e16bc0c02704f4c7b79a5fdb3f4fe1",
    "bottom": "8b8719635237cc9bbb785bd2dc20d38479a0a009",
}
CATALOG_V4_BLOB = "5bca6135bc963e1eafa97cd70360f4847de670aa"
CATALOG_V5_BLOB = "c8853e05175d6a3ee99604d43f773325e49e2e3d"
HEX = re.compile(r"#[0-9a-fA-F]{6}\b")
LOCAL = re.compile(r"url\(#([A-Za-z][A-Za-z0-9_-]*)\)")
COMMANDS = re.compile(r"[MmLlHhVvCcSsQqTtAaZz]")
NUMBER = re.compile(r"-?(?:\d+(?:\.\d*)?|\.\d+)(?:[Ee][+-]?\d+)?")
ROOT_MARKER = "<!-- banner-rotation:v6 "
MOTION_TYPES = {"translate", "scale", "rotate", "skewX", "skewY"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def read(path: Path) -> bytes:
    require(path.is_file() and not path.is_symlink(),
            f"source missing or symlinked: {path}")
    return path.read_bytes()


def blob(contents: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(contents)}\0".encode() + contents, usedforsecurity=False
    ).hexdigest()


def svg_path_counts(root: ET.Element) -> Counter[str]:
    return Counter(
        element.get("d") for element in root.iter(NS + "path")
        if element.get("d")
    )


def verify_numeric_frames(frames: list[str], label: str) -> None:
    require(len(frames) == 4 and frames[0] == frames[-1]
            and len(set(frames)) > 1, label + ": morph not cyclic")
    sig = [tuple(COMMANDS.findall(frame)) for frame in frames]
    number_values = [NUMBER.findall(frame) for frame in frames]
    require(all(s == sig[0] for s in sig)
            and len({len(items) for items in number_values}) == 1
            and len(number_values[0]) > 30,
            label + ": incompatible cubic command topology")
    for row in number_values:
        require(all(math.isfinite(float(value)) and abs(float(value)) < 100000
                    for value in row),
                label + ": nonfinite or unbounded cubic coordinate")


def verify_svg(surface: str, v2sha: str, v3sha: str, canvas: tuple[str, str, str],
               source_bytes: int, new_photons: int, filaments: int, windows: int) -> None:
    old_path = ASSETS / f"04-lagrange-tides-v2-opalescent-{surface}.svg"
    new_path = ASSETS / f"04-lagrange-tides-v3-kinetic-{surface}.svg"
    old_bytes, current = read(old_path), read(new_path)
    require(blob(old_bytes) == v2sha
            and blob(current) == v3sha and len(current) == source_bytes,
            f"V2 source or V3 exact snapshot drifted: {surface}")
    raw = current.decode("utf-8", errors="strict")
    require("<!DOCTYPE" not in raw.upper() and "<!ENTITY" not in raw.upper()
            and "NaN" not in raw and "undefined" not in raw,
            surface + ": malformed generated XML or external entity")
    no_namespace = raw.replace('xmlns="http://www.w3.org/2000/svg"', "", 1)
    require(not any(q in no_namespace.lower() for q in (
        "http://", "https://", "javascript:", "<script", "<image",
        "<foreignobject", "data:image", "base64,", "@import",
    )), surface + ": remote/raster/executable SVG forbidden")
    old, svg = ET.fromstring(old_bytes), ET.fromstring(current)
    require(svg.tag == NS + "svg"
            and svg.get("data-review-art") == "slot4-lagrange-tides-v3"
            and svg.get("data-surface") == surface
            and svg.get("role") == "img"
            and svg.get("aria-labelledby") == "title desc"
            and svg.get("fill") == "none"
            and (svg.get("width"), svg.get("height"), svg.get("viewBox")) == canvas
            and svg.find(NS + "title") is not None
            and svg.find(NS + "desc") is not None,
            surface + ": accessible responsive canvas changed")
    old_paths, new_paths = svg_path_counts(old), svg_path_counts(svg)
    require(all(new_paths[p] >= count for p, count in old_paths.items())
            and sum(new_paths.values()) > sum(old_paths.values()) + 2 * filaments + 10,
            surface + ": accepted V2 optical/path features removed")
    ids = [el.get("id") for el in svg.iter() if el.get("id")]
    require(len(ids) == len(set(ids)) and
            set(LOCAL.findall(raw)).issubset(set(ids)),
            surface + ": invalid local paint refs or duplicate IDs")
    require(not any(
        "href" in attribute.lower() or attribute.lower().startswith("on")
        for el in svg.iter() for attribute in el.attrib
    ), surface + ": unsafe external href or event handler")
    require(set(HEX.findall(raw)).issubset(PALETTE),
            surface + ": unreviewed pigment added")
    defs = list(svg.iter(NS + "defs"))
    require(len(defs) == 1 and defs[0] is svg.find(NS + "defs"),
            surface + ": paint definitions must be flat")
    styles = " ".join((el.text or "") for el in svg.iter(NS + "style"))
    require(".v3-motion{display:none!important}" in styles
            and "prefers-reduced-motion" in styles
            and ".still{display:inline!important}" in styles
            and ".kinetic{display:none!important}" in styles
            and ".v2-live{display:none!important}" in styles,
            surface + ": all three generations need static motion fallback")
    weave = svg.find(f".//{NS}g[@data-motion='volume-weave']")
    require(weave is not None and weave.get("class") == "v3-motion",
            surface + ": separate V3 kinetic container missing")
    for topic in (
        "nebula-drift", "independent-translating-streams",
        "counterflowing-filaments", "flowing-photonic-transport",
        "breathing-spectral-energy",
    ):
        require(svg.find(f".//{NS}g[@data-motion='{topic}']") is not None,
                surface + ": incomplete motion discipline " + topic)
    morphs = [a for a in svg.iter(NS + "animate")
              if a.get("attributeName") == "d"]
    new_morphs = [a for a in weave.iter(NS + "animate")
                  if a.get("attributeName") == "d"]
    require(len(morphs) == 16 and len(new_morphs) == 10,
            surface + ": real ribbon volume and contour shape-weaving absent")
    for index, animation in enumerate(morphs):
        verify_numeric_frames((animation.get("values") or "").split(";"),
                              f"{surface}/morph-{index}")
    transport = list(weave.iter(NS + "animateMotion"))
    require(len(transport) == new_photons,
            surface + ": extra kinetic traveling ions incomplete")
    translate = [a for a in weave.iter(NS + "animateTransform")
                 if a.get("type") == "translate"]
    require(len(translate) == 11 and
            all(a.get("attributeName") == "transform" for a in translate),
            surface + ": coordinated counterphase layer translation missing")
    move_x = [a for a in svg.iter(NS + "animate")
              if a.get("attributeName") == "x"]
    require(len(move_x) == 2 * windows,
            surface + ": independently moving weave overlap windows missing")
    for index, a in enumerate(move_x):
        frames = (a.get("values") or "").split(";")
        require(len(frames) == 4 and frames[0] == frames[-1]
                and len(set(frames)) >= 3
                and all(math.isfinite(float(v)) for v in frames),
                f"{surface}: moving weave mask #{index} must be cyclic")
    edges = [a for a in weave.iter(NS + "animate")
             if a.get("attributeName") == "stroke-dashoffset"]
    require(len(edges) >= 2 + filaments // 3,
            surface + ": missing flowing energy/dash offset transport")
    pulses = [a for a in weave.iter(NS + "animate")
              if a.get("attributeName") in {"r", "opacity"}]
    require(len(pulses) >= 24,
            surface + ": lighting isn't pulsating")
    require(len(list(svg.iter(NS + "feTurbulence"))) == 2
            and len(list(svg.iter(NS + "feDisplacementMap"))) == 1
            and len(list(svg.iter(NS + "clipPath"))) >= 4,
            surface + ": existing static glass/noise or V3 weave masks missing")
    print(f"PASS {surface}: V2 preserved {v2sha[:12]}, V3 {v3sha[:12]}, "
          f"{len(new_morphs)} new real morphs, {len(translate)} translating "
          f"groups, {len(transport)} new guided photons and {len(move_x)} "
          f"moving weave windows.")


def verify() -> None:
    require(blob(read(ROOT / "scripts/approved-banner-rotation-v4.json"))
            == CATALOG_V4_BLOB
            and blob(read(ROOT / "scripts/approved-banner-rotation-v5.json"))
            == CATALOG_V5_BLOB,
            "current/historical rotation manifests must be immutable")
    catalog = json.loads(read(ROOT / "scripts/approved-banner-rotation-v5.json"))
    require(catalog["version"] == "approved-profile-banners-v5"
            and [s["state"] for s in catalog["slots"]] ==
            ["approved"] * 4 + ["reserved"] * 4
            and catalog["slots"][3]["slug"] == "04-lagrange-tides",
            "approved rotation was changed")
    readme = read(ROOT / "README.md").decode("utf-8")
    require(ROOT_MARKER in readme and "v3-kinetic" not in readme
            and "v3-kinetic" not in
            json.dumps(catalog, sort_keys=True),
            "V3 must not silently deploy")
    gallery = read(ROOT / "docs/slot4-lagrange-tides-v3-review.md").decode("utf-8")
    require("DO NOT MERGE" in gallery.upper() and
            "V1" in gallery and "V2" in gallery and "V3" in gallery,
            "no visual approval boundary")
    for surface, sha2, sha3, canvas, size, light, threads, windows in V3:
        approved = ROOT / catalog["slots"][3]["assets"][surface]
        v1 = ROOT / f"assets/profile-banners/review/04-lagrange-tides-{surface}.svg"
        require(blob(read(approved)) == ORIGINAL_V1[surface]
                and blob(read(v1)) == ORIGINAL_V1[surface],
                surface + ": production V1 / historic review source changed")
        require(f"04-lagrange-tides-v3-kinetic-{surface}.svg" in gallery,
                "review gallery missing actual SVG path")
        verify_svg(surface, sha2, sha3, canvas, size, light, threads, windows)
    print("PASS all: V3 is novel kinetic review art only; exact four-slot "
          "production is unchanged, V1/V2 preserved.")


if __name__ == "__main__":
    verify()
