#!/usr/bin/env python3
"""Fail-closed read-only contract of the Quantum Apex V1 => V2 review triplet.

The verification NEVER authorizes deployment, changes protected sources, pushes a
branch or promotes artwork to README. Use: python3 scripts/verify_quantum_apex_v2_review.py
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
REVIEW = ROOT / "assets/profile-banners/review"
MANIFEST = ROOT / "scripts/approved-banner-rotation-v3.json"
GALLERY = ROOT / "docs/quantum-apex-luminous-singularity-v2-review.md"
PATH_COMMANDS = re.compile(r"[MmLlHhVvCcSsQqTtAaZz]")
LOCAL_REF = re.compile(r"url\(#([A-Za-z][A-Za-z0-9_-]*)\)")
HEX = re.compile(r"#[0-9A-Fa-f]{6}\b")
PALETTE = {"#00E6FF", "#00FBCC", "#E328FC", "#FFFFFF"}
TRIPLET = (
    ("top", "quantum-apex-signal-crown-hero.svg",
     "cba6be419ca838ada1accd02b714cd99fdd06664",
     "quantum-apex-photonic-top.svg", "4d783a9f32cc747e50db36312f8ae6d1894403f2",
     "quantum-apex-luminous-singularity-v2-top.svg",
     "3840", "774", "0 0 1280 258", 50_000, 80_000, 59, 5, ".v2-move"),
    ("top-compact", "quantum-apex-signal-crown-hero-compact.svg",
     "7a9b12381c15fe6811e57af07a5569b15354c219",
     "quantum-apex-photonic-top-compact.svg", "39f6298bfece3ef19ec8496a907869b7cecb2f59",
     "quantum-apex-luminous-singularity-v2-top-compact.svg",
     "1920", "588", "0 0 640 196", 37_000, 60_000, 34, 4, ".v2m-live"),
    ("bottom", "elite-evidence-horizon-bottom.svg",
     "de437b518adae0a8a501d4c6693b8a6b987576a2",
     "quantum-apex-photonic-bottom.svg", "47c5b6cfce89a0ae1497749f1c5ef129f58739d5",
     "quantum-apex-luminous-singularity-v2-bottom.svg",
     "3840", "450", "0 0 1280 150", 45_000, 70_000, 37, 4, ".v2b-live"),
)


def must(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def blob(value: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(value)}\0".encode("ascii") + value,
        usedforsecurity=False,
    ).hexdigest()


def read_regular(path: Path) -> bytes:
    must(path.is_file() and not path.is_symlink(), f"missing or aliased file: {path}")
    return path.read_bytes()


def paths(root: ET.Element) -> Counter[str]:
    return Counter(
        item.attrib["d"] for item in root.iter(NS + "path")
        if "d" in item.attrib
    )


def verify() -> None:
    catalog = json.loads(read_regular(MANIFEST).decode("utf-8"))
    must(catalog["version"] == "approved-profile-banners-v3", "production catalog version changed")
    must(len(catalog["slots"]) == 8 and
         [slot["state"] for slot in catalog["slots"]] ==
         ["approved", "approved", "approved"] + ["reserved"] * 5,
         "review art accidentally activated in catalog")
    original_slot = catalog["slots"][0]
    must(original_slot["slug"] == "01-original-quantum-apex", "original approval changed")
    gallery = read_regular(GALLERY).decode("utf-8")
    readme = read_regular(ROOT / "README.md").decode("utf-8")
    must("DO NOT MERGE" in gallery.upper() and "V1" in gallery and "V2" in gallery,
         "explicit pending owner review missing")
    must("quantum-apex-luminous-singularity-v2-" not in readme,
         "V2 was deployed to README without approval")
    for (surface, original, original_blob, v1_name, v1_blob, v2_name,
         width, height, view_box, min_bytes, max_bytes, min_anim, min_morph, motion) in TRIPLET:
        original_path = ROOT / "assets/profile-banners" / original
        v1_path = REVIEW / v1_name
        v2_path = REVIEW / v2_name
        original_bytes = read_regular(original_path)
        v1_bytes = read_regular(v1_path)
        v2_bytes = read_regular(v2_path)
        must(blob(original_bytes) == original_blob and
             original_slot["blobs"][surface] == original_blob and
             original_slot["assets"][surface] == original_path.relative_to(ROOT).as_posix(),
             f"production original changed: {surface}")
        must(blob(v1_bytes) == v1_blob, f"accepted V1 blob changed: {surface}")
        must(min_bytes <= len(v2_bytes) <= max_bytes,
             f"V2 size unexpected: {surface}")
        v2 = v2_bytes.decode("utf-8", errors="strict")
        must("<!DOCTYPE" not in v2.upper() and "<!ENTITY" not in v2.upper(),
             f"unsafe XML declaration: {surface}")
        clean = v2.replace('xmlns="http://www.w3.org/2000/svg"', "", 1).lower()
        must(not any(tag in clean for tag in (
            "http://", "https://", "<script", "<foreignobject", "<image",
            "javascript:", "data:image", "@import", "base64,"
        )), f"executable or external resource: {surface}")
        original_root = ET.fromstring(original_bytes)
        v1_root = ET.fromstring(v1_bytes)
        v2_root = ET.fromstring(v2_bytes)
        must(v2_root.tag == NS + "svg" and
             v2_root.get("role") == "img" and
             v2_root.get("aria-labelledby") == "title desc" and
             v2_root.get("data-review-art") == "quantum-apex-photonic-depth-v2" and
             v2_root.get("fill") == "none" and
             (v2_root.get("width"), v2_root.get("height"), v2_root.get("viewBox")) ==
             (width, height, view_box),
             f"V2 source metadata and transparent canvas changed: {surface}")
        must(v2_root.find(NS + "title") is not None and
             v2_root.find(NS + "desc") is not None,
             f"accessible title/description missing: {surface}")
        v2_paths = paths(v2_root)
        for baseline, source in ((paths(original_root), "original"),
                                 (paths(v1_root), "V1")):
            for line, count in baseline.items():
                must(v2_paths[line] >= count,
                     f"{source} path geometry lost: {surface}")
        must(sum(v2_paths.values()) > sum(paths(v1_root).values()),
             f"no independently authored V2 geometry: {surface}")
        must(set(HEX.findall(v2)).issubset(PALETTE),
             f"unexpected color in V2: {surface}")
        ids = [item.get("id") for item in v2_root.iter() if item.get("id")]
        must(len(ids) == len(set(ids)) and
             set(LOCAL_REF.findall(v2)).issubset(set(ids)),
             f"duplicate ID or unresolved SVG paint reference: {surface}")
        must(not any(
            (key.lower().startswith("on") or "href" in key.lower())
            for item in v2_root.iter() for key in item.attrib
        ), f"foreign link or event handler: {surface}")
        styles = "\n".join((style.text or "") for style in v2_root.iter(NS + "style"))
        must("prefers-reduced-motion: reduce" in styles and
             ".motion{display:none}" in styles and
             f"{motion}{{display:none}}" in styles and
             ".qa-" in styles,
             f"V1 and V2 reduced-motion fallback must both work: {surface}")
        textures = list(v2_root.iter(NS + "feTurbulence"))
        must(len(textures) >= 2 and
             len(list(v2_root.iter(NS + "feGaussianBlur"))) >= 4,
             f"second-generation atmospheric depth layers missing: {surface}")
        for t in textures:
            must(t.get("numOctaves") == "2" and
                 all(0 < float(value) <= .22 for value in
                     t.get("baseFrequency", "").split()),
                 f"unbounded grain cost: {surface}")
        animations = [
            item for item in v2_root.iter()
            if item.tag in (NS + "animate", NS + "animateMotion", NS + "animateTransform")
        ]
        must(len(animations) >= min_anim and
             len(animations) > sum(
                 1 for item in v1_root.iter()
                 if item.tag in (NS + "animate", NS + "animateMotion", NS + "animateTransform")
             ), f"V2 motion less expressive than V1: {surface}")
        morphs = [a for a in v2_root.iter(NS + "animate")
                  if a.get("attributeName") == "d"]
        must(len(morphs) >= min_morph,
             f"shapeshifting path motion missing: {surface}")
        for item in morphs:
            frames = (item.get("values") or "").split(";")
            signatures = [
                tuple(PATH_COMMANDS.findall(frame))
                for frame in frames
            ]
            must(len(frames) == 3 and frames[0] == frames[2] and
                 len(set(signatures)) == 1 and len(signatures[0]) >= 3,
                 f"SVG path morph has incompatible command topology: {surface}")
        must(v1_name in gallery and v2_name in gallery and
             v2_name not in readme,
             f"gallery or deployment boundary failure: {surface}")
        print(f"PASS {surface}: untouched original {original_blob[:12]}, "
              f"accepted V1 {v1_blob[:12]}, V2 {len(v2_bytes)} bytes, "
              f"{len(animations)} motion elements, {len(morphs)} closed morphs")
    print("PASS: three standalone responsive V2 SVGs; original and V1 assets "
          "unchanged; reserved rotation slots remain reserved; no deployment.")


if __name__ == "__main__":
    verify()
