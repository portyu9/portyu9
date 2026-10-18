#!/usr/bin/env python3
"""Read-only assurance for a review-only Quantum Apex SVG triplet.

This never authorizes a production asset, rewrites README, or mutates branches.
Run from any checkout: python3 scripts/verify_quantum_apex_review.py
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
NS = "{http://www.w3.org/2000/svg}"
CATALOG = ROOT / "scripts/approved-banner-rotation-v3.json"
REVIEW_DIR = ROOT / "assets/profile-banners/review"
GALLERY = ROOT / "docs/quantum-apex-photonic-depth-review.md"
COLOR = re.compile(r"#[0-9a-fA-F]{6}\b")
URL_REF = re.compile(r"url\(#([A-Za-z][A-Za-z0-9_-]*)\)")
COMMAND = re.compile(r"[MmLlHhVvCcSsQqTtAaZz]")
ALLOWED_COLORS = {"#00E6FF", "#00FBCC", "#E328FC", "#FFFFFF"}
SPECS = (
    ("top", "quantum-apex-signal-crown-hero.svg",
     "quantum-apex-photonic-top.svg", "3840", "774", "0 0 1280 258",
     "cba6be419ca838ada1accd02b714cd99fdd06664", 30000, 48000,
     42, "qa-kinetic"),
    ("top-compact", "quantum-apex-signal-crown-hero-compact.svg",
     "quantum-apex-photonic-top-compact.svg", "1920", "588", "0 0 640 196",
     "7a9b12381c15fe6811e57af07a5569b15354c219", 17000, 32000,
     20, "qa-mini-live"),
    ("bottom", "elite-evidence-horizon-bottom.svg",
     "quantum-apex-photonic-bottom.svg", "3840", "450", "0 0 1280 150",
     "de437b518adae0a8a501d4c6693b8a6b987576a2", 19000, 32000,
     23, "qa-horizon-live"),
)


def require(condition: bool, description: str) -> None:
    if not condition:
        raise ValueError(description)


def blob_sha(contents: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(contents)}\0".encode("ascii") + contents,
        usedforsecurity=False,
    ).hexdigest()


def path_geometry(root: ET.Element) -> Counter[str]:
    return Counter(
        item.get("d") for item in root.iter(NS + "path")
        if item.get("d") is not None
    )


def verify() -> None:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    require(len(catalog["slots"]) == 8 and
            [x["state"] for x in catalog["slots"]] ==
            ["approved"] * 3 + ["reserved"] * 5,
            "production approval inventory drifted")
    approved = catalog["slots"][0]
    require(approved["slug"] == "01-original-quantum-apex",
            "slot-one production provenance changed")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    gallery = GALLERY.read_text(encoding="utf-8")
    require("DO NOT MERGE" in gallery.upper() and "REVIEW" in gallery.upper(),
            "review gallery must explicitly forbid merge")
    for surface, original_name, candidate_name, w, h, viewbox, sha, lo, hi, minimum_motion, kinetic in SPECS:
        original_path = ROOT / "assets/profile-banners" / original_name
        candidate_path = REVIEW_DIR / candidate_name
        require(candidate_path.is_file() and not candidate_path.is_symlink(),
                f"complete review SVG missing or symlinked: {surface}")
        require(original_path.is_file() and not original_path.is_symlink(),
                f"production original missing or symlinked: {surface}")
        original_bytes = original_path.read_bytes()
        candidate_bytes = candidate_path.read_bytes()
        require(blob_sha(original_bytes) == sha and
                approved["blobs"][surface] == sha and
                approved["assets"][surface] == original_path.relative_to(ROOT).as_posix(),
                f"approved original drifted: {surface}")
        require(lo <= len(candidate_bytes) <= hi,
                f"review SVG payload outside reviewed bounds: {surface}")
        svg = candidate_bytes.decode("utf-8", errors="strict")
        require("<!DOCTYPE" not in svg and "<!ENTITY" not in svg,
                f"forbidden XML prelude: {surface}")
        inspected = svg.replace('xmlns="http://www.w3.org/2000/svg"', "", 1).lower()
        require(not any(token in inspected for token in (
            "<script", "<foreignobject", "<image", "@import", "javascript:",
            "data:image", "base64,", "http://", "https://"
        )), f"external or executable SVG content: {surface}")
        original_root = ET.fromstring(original_bytes)
        root = ET.fromstring(candidate_bytes)
        require(root.tag == NS + "svg" and root.get("role") == "img" and
                root.get("aria-labelledby") == "title desc" and
                root.get("data-review-art") == "quantum-apex-photonic-depth-v1" and
                root.get("fill") == "none",
                f"complete accessible transparent review SVG metadata missing: {surface}")
        require((root.get("width"), root.get("height"), root.get("viewBox")) ==
                (w, h, viewbox), f"responsive canvas changed: {surface}")
        require(root.find(NS + "title") is not None and
                root.find(NS + "desc") is not None,
                f"accessible label missing: {surface}")
        candidate_geometry = path_geometry(root)
        for segment, count in path_geometry(original_root).items():
            require(candidate_geometry[segment] >= count,
                    f"an original source path was deleted or changed: {surface}")
        require(sum(candidate_geometry.values()) > sum(path_geometry(original_root).values()),
                f"candidate contains no additional authored geometry: {surface}")
        require(set(COLOR.findall(svg)).issubset(ALLOWED_COLORS),
                f"brand palette unexpected: {surface}")
        ids = [item.get("id") for item in root.iter() if item.get("id")]
        require(len(ids) == len(set(ids)), f"duplicate SVG id: {surface}")
        require(set(URL_REF.findall(svg)).issubset(ids),
                f"broken local paint/filter/clip URL reference: {surface}")
        require(not any(
            key.lower().startswith("on") or "href" in key.lower()
            for item in root.iter() for key in item.attrib
        ), f"event handlers or foreign references forbidden: {surface}")
        style = "\n".join((item.text or "") for item in root.iter(NS + "style"))
        require("prefers-reduced-motion: reduce" in style and
                ".motion{display:none}" in style and
                f".{kinetic}{{display:none}}" in style,
                f"complete static reduced-motion fallback absent: {surface}")
        require(len(list(root.iter(NS + "feTurbulence"))) == 1 and
                len(list(root.iter(NS + "feGaussianBlur"))) >= 2 and
                len(list(root.iter(NS + "radialGradient"))) >= 3,
                f"volumetric grain, soft glow or optically layered light missing: {surface}")
        for turb in root.iter(NS + "feTurbulence"):
            require(turb.get("numOctaves") == "2" and
                    all(0 < float(n) <= .18 for n in
                        turb.get("baseFrequency", "").split()),
                    f"unbounded noise workload: {surface}")
        animated = [
            element for item in root.iter()
            for element in [item] if item.tag in (
                NS + "animate", NS + "animateTransform", NS + "animateMotion"
            )
        ]
        require(len(animated) >= minimum_motion,
                f"animation suite missing: {surface}")
        morphs = [
            item for item in root.iter(NS + "animate")
            if item.get("attributeName") == "d"
        ]
        require(morphs, f"waveform shape-morph missing: {surface}")
        for morph in morphs:
            frames = (morph.get("values") or "").split(";")
            signatures = [tuple(COMMAND.findall(p)) for p in frames]
            require(len(frames) == 3 and frames[0] == frames[-1] and
                    len(set(signatures)) == 1 and len(signatures[0]) >= 3,
                    f"SVG path interpolation command mismatch: {surface}")
        require(candidate_name in gallery and
                f"assets/profile-banners/review/{candidate_name}" not in readme and
                candidate_name not in readme,
                f"preview missing from gallery or accidentally deployed: {surface}")
        print(f"PASS {surface}: source {sha[:12]} preserved, "
              f"review {len(candidate_bytes)} bytes, "
              f"{len(animated)} animations, {len(morphs)} continuous morph(s)")
    require(not any(item["state"] == "approved"
                    for item in catalog["slots"][3:]),
            "reserved production artwork accidentally activated")
    print("PASS Quantum Apex review: three complete self-contained responsive "
          "SVGs; originals, rotation, and README remain unchanged.")


if __name__ == "__main__":
    verify()
