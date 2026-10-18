#!/usr/bin/env python3
"""Read-only structural/provenance guard for the unapproved Lagrange Tides SVG triplet.

Run: python3 scripts/verify_slot4_lagrange_review.py
Never authorizes a slot, changes the approved manifest, or deploys artwork.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
REVIEW = ROOT / "assets/profile-banners/review"
NS = "{http://www.w3.org/2000/svg}"
ALLOWED = {
    "#01040E", "#091529", "#100921", "#020510",
    "#42E6FF", "#66FFD0", "#B68AFF", "#FF4ED4", "#F1FAFF",
}
SPECS = (
    ("top", "be373e0a4b601ae4f136797e2ddb96ea519d8f36",
     ("3840", "774", "0 0 1280 258"), 107_667, 70, 60, 80),
    ("top-compact", "34cf94c290e16bc0c02704f4c7b79a5fdb3f4fe1",
     ("1920", "588", "0 0 640 196"), 88_082, 50, 40, 55),
    ("bottom", "8b8719635237cc9bbb785bd2dc20d38479a0a009",
     ("3840", "450", "0 0 1280 150"), 96_670, 60, 50, 70),
)
ORIGINAL = (
    ("assets/profile-banners/quantum-apex-signal-crown-hero.svg",
     "cba6be419ca838ada1accd02b714cd99fdd06664"),
    ("assets/profile-banners/quantum-apex-signal-crown-hero-compact.svg",
     "7a9b12381c15fe6811e57af07a5569b15354c219"),
    ("assets/profile-banners/elite-evidence-horizon-bottom.svg",
     "de437b518adae0a8a501d4c6693b8a6b987576a2"),
)
ARCHIVED_SLOT4 = (
    "assets/profile-banners/daily/04-spectral-tides-top.svg",
    "fa2bd64bd115379870c9a1358cdcd5a094d59203",
)
CATALOG_PATH = ROOT / "scripts/approved-banner-rotation-v4.json"
CATALOG_BLOB = "5bca6135bc963e1eafa97cd70360f4847de670aa"
GALLERY = ROOT / "docs/slot4-lagrange-tides-aurora-forge-review.md"
NUM = re.compile(r"-?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?")
SVG_COMMANDS = re.compile(r"[MmLlHhVvCcSsQqTtAaZz]")
COLOR = re.compile(r"#[A-Fa-f0-9]{6}\b")
URL = re.compile(r"url\(#([A-Za-z][A-Za-z0-9_-]*)\)")


def must(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def git_blob(data: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(data)}\0".encode("ascii") + data,
        usedforsecurity=False,
    ).hexdigest()


def immutable(path: Path) -> bytes:
    must(path.is_file() and not path.is_symlink(),
         f"source missing, directory, or symbolic link: {path}")
    return path.read_bytes()


def verify_morph(elem: ET.Element, surface: str) -> None:
    frames = (elem.get("values") or "").split(";")
    must(len(frames) == 4 and frames[0] == frames[-1] and
         len(set(frames)) > 1,
         f"slot4 {surface}: morph requires four closed, changing frames")
    sigs = [tuple(SVG_COMMANDS.findall(frame)) for frame in frames]
    number_counts = [len(NUM.findall(frame)) for frame in frames]
    must(all(sig == sigs[0] for sig in sigs) and
         len(set(number_counts)) == 1 and
         sigs[0].count("C") == 16 and
         all(-10_000 < float(n) < 10_000
             for frame in frames for n in NUM.findall(frame)),
         f"slot4 {surface}: incompatible or nonfinite interpolated path frames")


def verify() -> None:
    catalog_bytes = immutable(CATALOG_PATH)
    must(git_blob(catalog_bytes) == CATALOG_BLOB,
         "the approved production rotation manifest changed")
    catalog = json.loads(catalog_bytes)
    must(catalog["version"] == "approved-profile-banners-v4" and
         catalog["epoch"] == "2026-10-12" and
         catalog["period_seconds"] == 86400 and
         len(catalog["slots"]) == 8 and
         [slot["state"] for slot in catalog["slots"]] ==
         ["approved"] * 3 + ["reserved"] * 5 and
         catalog["slots"][3] == {
             "slot": 4, "slug": "04-reserved", "state": "reserved",
             "fallback_slot": 1,
         }, "slot4 was deployed without owner acceptance")
    for item in catalog["slots"][:3]:
        for surface, path in item["assets"].items():
            must(git_blob(immutable(ROOT / path)) == item["blobs"][surface],
                 f"existing approved {item['slug']}/{surface} changed")
    for path, blob in (*ORIGINAL, ARCHIVED_SLOT4):
        must(git_blob(immutable(ROOT / path)) == blob,
             f"original or historical slot4 artwork changed: {path}")
    readme = immutable(ROOT / "README.md").decode("utf-8")
    gallery = immutable(GALLERY).decode("utf-8")
    must("DO NOT MERGE" in gallery.upper() and
         "SLOT 4" in gallery.upper() and
         "REDUCED-MOTION" in gallery.upper(),
         "explicit owner review gate absent")
    for surface, sha, canvas, size, min_wires, min_facets, min_stars in SPECS:
        name = f"04-lagrange-tides-{surface}.svg"
        must(name in gallery, f"missing full source from gallery: {surface}")
        must(name not in readme and "04-lagrange-tides" not in readme,
             f"slot4 {surface} improperly published in README")
        src = immutable(REVIEW / name)
        must(git_blob(src) == sha and len(src) == size,
             f"slot4 {surface}: approved review snapshot drifted")
        text = src.decode("utf-8", errors="strict")
        must("<!DOCTYPE" not in text.upper() and
             "<!ENTITY" not in text.upper() and
             "NaN" not in text and "undefined" not in text,
             f"slot4 {surface}: invalid XML or generated payload")
        stripped = text.replace('xmlns="http://www.w3.org/2000/svg"', "", 1)
        must(not any(token in stripped.lower() for token in (
            "http://", "https://", "javascript:", "data:image", "@import",
            "<script", "<image", "<foreignobject", "base64,",
        )), f"slot4 {surface}: external, executable, or raster dependency")
        root = ET.fromstring(src)
        must(root.tag == NS + "svg" and root.get("role") == "img" and
             root.get("aria-labelledby") == "title desc" and
             root.get("data-review-art") == "slot4-lagrange-tides-v1" and
             root.get("data-surface") == surface and
             root.get("fill") == "none" and
             (root.get("width"), root.get("height"), root.get("viewBox")) == canvas,
             f"slot4 {surface}: responsive transparent art contract drifted")
        must(root.find(NS + "title") is not None and
             root.find(NS + "desc") is not None,
             f"slot4 {surface}: accessible title or description missing")
        nodes = list(root.iter())
        ids = [node.get("id") for node in nodes if node.get("id")]
        must(len(ids) == len(set(ids)) and
             set(URL.findall(text)).issubset(set(ids)),
             f"slot4 {surface}: duplicate IDs or unbound paint/filter refs")
        must(not any(
            "href" in key.lower() or key.lower().startswith("on")
            for node in nodes for key in node.attrib
        ), f"slot4 {surface}: network reference or event handler")
        must(set(COLOR.findall(text)).issubset(ALLOWED),
             f"slot4 {surface}: brand palette changed")
        styles = "\n".join(
            (node.text or "") for node in root.iter(NS + "style")
        )
        must("prefers-reduced-motion:reduce" in styles and
             ".kinetic{display:none!important}" in styles and
             ".still{display:inline!important}" in styles and
             len(list(root.findall(f".//{NS}g[@class='still']"))) == 1,
             f"slot4 {surface}: complete reduced-motion focal field missing")
        must(len(list(root.iter(NS + "linearGradient"))) >= 6 and
             len(list(root.iter(NS + "radialGradient"))) >= 2 and
             len(list(root.iter(NS + "feGaussianBlur"))) >= 2,
             f"slot4 {surface}: refractive/glow optical material missing")
        grain = list(root.iter(NS + "feTurbulence"))
        must(len(grain) == 1 and grain[0].get("numOctaves") == "2" and
             all(0 < float(x) < .15 for x in
                 grain[0].get("baseFrequency", "").split()),
             f"slot4 {surface}: grain unexpectedly expensive or missing")
        paths = list(root.iter(NS + "path"))
        must(len(paths) >= min_wires + min_facets + 20 and
             len(list(root.iter(NS + "circle"))) >= min_stars,
             f"slot4 {surface}: dense filament/facet/star field incomplete")
        morphs = [
            a for a in root.iter(NS + "animate")
            if a.get("attributeName") == "d"
        ]
        must(len(morphs) == 4 and
             len(list(root.iter(NS + "animateMotion"))) == 4 and
             len(list(root.iter(NS + "animateTransform"))) >= 1 and
             len(list(root.iter(NS + "animate"))) >= 25,
             f"slot4 {surface}: living wave mechanics missing")
        for morph in morphs:
            verify_morph(morph, surface)
        must(len(list(root.iter(NS + "clipPath"))) == 1 and
             len(list(root.iter(NS + "filter"))) >= 3,
             f"slot4 {surface}: clipped grain and bounded glows missing")
        print(f"PASS {surface}: exact blob {sha[:12]}, {size} bytes, "
              f"{len(paths)} paths, four coherent morphs, four guided photons")
    must("approved" not in catalog["slots"][3]["state"],
         "slot 4 silently activated")
    print("PASS: complete responsive slot4 triplet is new review-only art; "
          "live slot 4 still reserved; all current approved and historical "
          "artifacts unchanged.")


if __name__ == "__main__":
    verify()
