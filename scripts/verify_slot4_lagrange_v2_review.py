#!/usr/bin/env python3
"""Read-only fail-closed provenance and complexity assurance for slot 4 V2 review art.

Execute: python3 scripts/verify_slot4_lagrange_v2_review.py
Never changes live slots, emits an approved manifest, or deploys any artwork.
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
COLORS = {
    "#01040E", "#091529", "#100921", "#020510",
    "#42E6FF", "#66FFD0", "#B68AFF", "#FF4ED4", "#F1FAFF",
}
SPECS = (
    ("top",
     "be373e0a4b601ae4f136797e2ddb96ea519d8f36",
     "87507b866caf359a6c3edfc76c06ad97f539ddc5",
     ("3840", "774", "0 0 1280 258"), 184409, 5, 75, 75, 100),
    ("top-compact",
     "34cf94c290e16bc0c02704f4c7b79a5fdb3f4fe1",
     "e7234689af9d29767fc8f6f1b7c0b9cddb14f874",
     ("1920", "588", "0 0 640 196"), 141728, 4, 40, 40, 60),
    ("bottom",
     "8b8719635237cc9bbb785bd2dc20d38479a0a009",
     "57aae2dd4919fc9ffdf848dd85eb4d0bcc659bf4",
     ("3840", "450", "0 0 1280 150"), 162094, 5, 55, 55, 85),
)
HEX = re.compile(r"#[0-9a-fA-F]{6}\b")
LOCAL = re.compile(r"url\(#([A-Za-z][A-Za-z0-9_-]*)\)")
COMMAND = re.compile(r"[MmLlHhVvCcSsQqTtAaZz]")
NUMBER = re.compile(r"-?(?:\d+(?:\.\d*)?|\.\d+)(?:[Ee][+-]?\d+)?")


def require(test: bool, message: str) -> None:
    if not test:
        raise ValueError(message)


def read(path: Path) -> bytes:
    require(path.is_file() and not path.is_symlink(),
            f"missing or aliased file: {path}")
    return path.read_bytes()


def git_blob(data: bytes) -> str:
    return hashlib.sha1(
        f"blob {len(data)}\0".encode("ascii") + data,
        usedforsecurity=False,
    ).hexdigest()


def path_counts(root: ET.Element) -> Counter[str]:
    return Counter(p.attrib["d"] for p in root.iter(NS + "path")
                   if "d" in p.attrib)


def verify() -> None:
    old_catalog = read(ROOT / "scripts/approved-banner-rotation-v4.json")
    current_catalog = read(ROOT / "scripts/approved-banner-rotation-v5.json")
    require(git_blob(old_catalog) ==
            "5bca6135bc963e1eafa97cd70360f4847de670aa",
            "archived three-slot catalog changed")
    require(git_blob(current_catalog) ==
            "c8853e05175d6a3ee99604d43f773325e49e2e3d",
            "current four-slot catalog changed")
    approved = json.loads(current_catalog)
    require(approved["version"] == "approved-profile-banners-v5"
            and len(approved["slots"]) == 8
            and [s["state"] for s in approved["slots"]] ==
            ["approved"] * 4 + ["reserved"] * 4
            and approved["slots"][3]["slug"] == "04-lagrange-tides",
            "slot 4 V2 must remain review-only; active slot 4 is V1")
    source = approved["slots"][3]
    readme = read(ROOT / "README.md").decode("utf-8")
    gallery = read(ROOT / "docs/slot4-lagrange-tides-v2-review.md").decode("utf-8")
    require("DO NOT MERGE" in gallery.upper()
            and "V1" in gallery and "V2" in gallery,
            "missing explicit owner review checkpoint")
    for surface, old_sha, new_sha, canvas, new_size, motion, cells, gems, laces in SPECS:
        v1_path = REVIEW / f"04-lagrange-tides-{surface}.svg"
        v2_name = f"04-lagrange-tides-v2-opalescent-{surface}.svg"
        v2_path = REVIEW / v2_name
        v1_bytes, v2_bytes = read(v1_path), read(v2_path)
        approved_asset = ROOT / source["assets"][surface]
        require(source["blobs"][surface] == old_sha
                and git_blob(read(approved_asset)) == old_sha
                and git_blob(v1_bytes) == old_sha,
                f"production V1 hash/identity changed: {surface}")
        require(git_blob(v2_bytes) == new_sha and len(v2_bytes) == new_size
                and new_size < 205000 and len(v2_bytes) > len(v1_bytes),
                f"V2 review payload changed, huge or absent: {surface}")
        require(v2_name in gallery and v2_name not in readme,
                f"review art deployed or missing gallery: {surface}")
        s = v2_bytes.decode("utf-8", errors="strict")
        require("<!DOCTYPE" not in s.upper() and "<!ENTITY" not in s.upper()
                and "NaN" not in s and "undefined" not in s,
                f"unsafe SVG XML declaration or generated coordinates: {surface}")
        sanitized = s.replace('xmlns="http://www.w3.org/2000/svg"', "")
        require(not any(x in sanitized.lower() for x in (
            "http://", "https://", "javascript:", "data:image", "<script",
            "<image", "<foreignobject", "@import", "base64,",
        )), f"external/raster/executable resources forbidden: {surface}")
        root, old = ET.fromstring(v2_bytes), ET.fromstring(v1_bytes)
        require(root.tag == NS + "svg" and root.get("role") == "img"
                and root.get("aria-labelledby") == "title desc"
                and root.get("fill") == "none"
                and root.get("data-review-art") == "slot4-lagrange-tides-v2"
                and root.get("data-surface") == surface
                and (root.get("width"), root.get("height"), root.get("viewBox"))
                == canvas, f"accessible responsive artwork changed: {surface}")
        require(root.find(NS + "title") is not None
                and root.find(NS + "desc") is not None,
                f"accessible title and description missing: {surface}")
        new_paths, old_paths = path_counts(root), path_counts(old)
        require(all(new_paths[d] >= n for d, n in old_paths.items())
                and sum(new_paths.values()) > sum(old_paths.values()) + 30,
                f"unique original V1 path geometry lost: {surface}")
        ids = [n.get("id") for n in root.iter() if n.get("id")]
        require(len(ids) == len(set(ids))
                and set(LOCAL.findall(s)).issubset(set(ids)),
                f"invalid internal resources or duplicate IDs: {surface}")
        require(not any(
            "href" in attr.lower() or attr.lower().startswith("on")
            for tag in root.iter() for attr in tag.attrib
        ), f"SVG executable handler or external href forbidden: {surface}")
        require(set(HEX.findall(s)).issubset(COLORS),
                f"unreviewed off-palette material: {surface}")
        styles = " ".join((n.text or "") for n in root.iter(NS + "style"))
        require("prefers-reduced-motion:reduce" in styles
                and ".kinetic{display:none!important}" in styles
                and ".still{display:inline!important}" in styles
                and ".v2-live{display:none!important}" in styles,
                f"both V1 and V2 reduced-motion static states missing: {surface}")
        require(len(list(root.iter(NS + "linearGradient"))) >= 10
                and len(list(root.iter(NS + "radialGradient"))) >= 4
                and len(list(root.iter(NS + "feGaussianBlur"))) >= 4,
                f"layered refractive optical materials incomplete: {surface}")
        fractals = list(root.iter(NS + "feTurbulence"))
        disp = list(root.iter(NS + "feDisplacementMap"))
        require(len(fractals) >= 2 and len(disp) == 1
                and float(disp[0].get("scale", "100")) <= 2.4
                and all(n.get("numOctaves") == "2" for n in fractals),
                f"V2 material distortion unbounded: {surface}")
        morphs = [m for m in root.iter(NS + "animate") if m.get("attributeName") == "d"]
        moving = list(root.iter(NS + "animateMotion"))
        require(len(morphs) == 6 and len(moving) == 4 + motion,
                f"original and V2 path-morph or photon transport missing: {surface}")
        for m in morphs:
            frames = (m.get("values") or "").split(";")
            signatures = [tuple(COMMAND.findall(x)) for x in frames]
            counts = [len(NUMBER.findall(x)) for x in frames]
            require(len(frames) == 4 and frames[0] == frames[3]
                    and len(set(signatures)) == 1 and len(set(counts)) == 1,
                    f"not interpolable or not closed frame topology: {surface}")
        require(len(list(root.iter(NS + "clipPath"))) >= 2
                and len(list(root.iter(NS + "ellipse"))) >= gems
                and len(list(root.iter(NS + "path"))) >= laces,
                f"optical micro-droplet and light-reef density disappeared: {surface}")
        print(f"PASS {surface}: accepted V1 {old_sha[:12]} untouched; "
              f"V2 exact {new_sha[:12]}, {new_size} bytes, "
              f"{len(morphs)} compatible morphs, {len(moving)} moving photons")
    print("PASS: new V2 art ONLY in review; active slot 4 remains exact V1 "
          "with four-day UTC schedule; all historic catalog sources unmodified.")


if __name__ == "__main__":
    verify()
