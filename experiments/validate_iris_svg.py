#!/usr/bin/env python3
"""Motion assurance for the UNMERGED Fractal Iris review SVG.

Verifies that the actual original nebula paths, noise texture rectangles and
all 165 original filament paths move as geometry again. Stops regressions to
synthetic dash highlights, per-frame turbulence changes or sharp loop seams.
Structural/analytic only: this is not a browser frame-time or visual test.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
import xml.etree.ElementTree as ET

SVG = Path(__file__).resolve().parent / "previews" / "fractal-iris-animated.svg"
NS = "{http://www.w3.org/2000/svg}"
# Extracted from reviewed prior SVG Git blob
# e667594c4b0b79f0457fe57589f0ec990c776092 (before genuine motion restore).
ORIGINAL_SPAGHETTI_FNV32 = "ecf603cf"  # 165 original path tags, sorted
ORIGINAL_NEBULA_FNV32 = "dec135fd"     # 4 original warped path tags, sorted


def geometry_fingerprint(paths: list[str]) -> str:
    """FNV-1a 32 of exact original ASCII <path/> tags, order independent."""
    h = 2166136261
    for byte in "\n".join(sorted(paths)).encode("utf-8"):
        h = ((h ^ byte) * 16777619) & 0xFFFFFFFF
    return f"{h:08x}"


def assert_smooth_closed_transform(animation: ET.Element) -> None:
    assert animation.tag == NS + "animateTransform"
    assert animation.get("attributeName") == "transform"
    assert animation.get("type") in ("translate", "rotate")
    assert animation.get("calcMode") == "spline"
    assert animation.get("keyTimes") == "0;.5;1"
    assert animation.get("keySplines") == ".42 0 .58 1;.42 0 .58 1"
    assert animation.get("repeatCount") == "indefinite"
    phases = animation.get("values", "").split(";")
    assert len(phases) == 3 and phases[0] == phases[-1], "animation snaps at loop boundary"
    assert phases[0] != phases[1], "no original-geometry motion"
    d = animation.get("dur", "")
    assert d.endswith("s") and 19 <= int(d[:-1]) <= 41


def check() -> None:
    source = SVG.read_text(encoding="utf-8")
    root = ET.fromstring(source)
    assert root.tag == NS + "svg" and root.get("viewBox") == "0 0 1280 258"
    assert root.get("width") == "1280" and root.get("height") == "258"
    assert len(source.encode("utf-8")) < 160_000
    assert "<script" not in source and "<foreignObject" not in source
    assert not any(token in source for token in (
        'href="http:', 'href="https:', 'xlink:href="http:', 'xlink:href="https:'
    )), "external resource load is forbidden"

    ids = [node.get("id") for node in root.iter() if node.get("id")]
    assert len(ids) == len(set(ids)), "duplicate SVG ID"
    known = set(ids)
    assert set(re.findall(r"url\(#([^)]+)\)", source)) <= known, "unresolved paint reference"
    elements = list(root.iter())
    uses = [n for n in elements if n.tag == NS + "use"]
    assert uses and all(n.get("href", "").startswith("#") and n.get("href")[1:] in known
                        for n in uses), "unresolved internal geometry instances"

    # Verify exact original geometry from the pre-restoration SVG, not a visual
    # replacement such as moving dash strokes or newly drawn cloud bands.
    all_spaghetti: list[str] = []
    for i in range(5):
        marker = f'<g id="original-spaghetti-geometry-{i}"'
        assert source.count(marker) == 1
        segment = source.split(marker, 1)[1].split("</g>", 1)[0]
        tags = re.findall(r"<path\b[^>]+/>", segment)
        assert len(tags) == 33, "missing original spaghetti paths"
        all_spaghetti.extend(tags)
    assert len(all_spaghetti) == 165
    assert geometry_fingerprint(all_spaghetti) == ORIGINAL_SPAGHETTI_FNV32, (
        "original filament shapes were replaced or altered")
    nebula_paths = []
    for i in range(4):
        marker = f'<g id="original-nebula-geometry-{i}"'
        assert source.count(marker) == 1
        segment = source.split(marker, 1)[1].split("</g>", 1)[0]
        tags = re.findall(r"<path\b[^>]+/>", segment)
        assert len(tags) == 1
        assert "filter=" in tags[0] and "stroke=" in tags[0], "original cloud warp lost"
        nebula_paths.extend(tags)
    assert geometry_fingerprint(nebula_paths) == ORIGINAL_NEBULA_FNV32
    for name, filter_id in (("plasma", "plasmaTexture"), ("cyan", "cyanTexture")):
        node = next((x for x in elements if x.get("id") == f"original-nebula-{name}"), None)
        assert node is not None
        rectangles = list(node.findall(NS + "rect"))
        assert len(rectangles) == 1
        assert rectangles[0].get("filter") == f"url(#{filter_id})"

    # 4 original cloud contours, 2 original filter textures, 5 original
    # spaghetti groups, and original 3 optical rotors, not synthetic highlights.
    groups = [n for n in elements if n.get("class") == "ambient-motion"]
    roles = Counter(n.get("data-role") for n in groups)
    assert roles == Counter({
        "original-nebula-contour": 4,
        "original-nebula-texture": 2,
        "original-spaghetti-body": 5,
    }), roles
    stills = [n for n in elements if n.get("class") == "ambient-still"]
    assert len(stills) == len(groups) == 11
    for group in groups:
        animations = list(group.findall(NS + "animateTransform"))
        assert len(animations) == 1
        assert_smooth_closed_transform(animations[0])
        copies = list(group.findall(NS + "use"))
        assert len(copies) == 1
        assert copies[0].get("href", "").startswith("#original-")
        assert not any("filter" in node.attrib for node in group.iter()), (
            "never animate the filter definition/parameter")

    # Exactly one independent static fallback for each original group.
    for group in groups:
        ref = group.find(NS + "use").get("href")
        count = sum(still.find(NS + "use") is not None and
                    still.find(NS + "use").get("href") == ref for still in stills)
        assert count == 1, f"missing unique reduced-motion fallback for {ref}"

    # Original center optics unchanged as measured by blade count/rotors.
    optics = [n for n in elements if n.get("class") == "motion"]
    reduced_optics = [n for n in elements if n.get("class") == "motion-still"]
    assert len(optics) == len(reduced_optics) == 3
    for group in optics:
        rotor = group.find(NS + "animateTransform")
        assert rotor is not None
        assert rotor.get("type") == "rotate"
        assert rotor.get("calcMode") == "linear"
        assert rotor.get("from") == "0" and rotor.get("to") in ("360", "-360")
        assert rotor.get("repeatCount") == "indefinite"
        assert not any("filter" in x.attrib for x in group.iter())
    assert source.count('fill="url(#bladeMetal)"') == 32

    animations = [x for x in elements if x.tag in (
        NS + "animate", NS + "animateTransform", NS + "animateMotion")]
    assert len(animations) == 14
    assert all(x.tag == NS + "animateTransform" for x in animations)
    for filt in root.iter(NS + "filter"):
        assert not any(x.tag in (NS + "animate", NS + "animateTransform")
                       for x in filt.iter()), "expensive filter animation reintroduced"
    assert not any(x.get("attributeName") in
                   ("baseFrequency", "scale", "stdDeviation", "opacity", "stroke-dashoffset")
                   for x in animations), "unstable original motion replaced with surrogate"
    assert source.count("data-role=\"original-spaghetti-body\"") == 5
    assert "filament-flow" not in source and "ion-flow-magenta" not in source
    assert ".ambient-motion {display:none}" in source
    assert ".ambient-still {display:inline}" in source
    assert "prefers-reduced-motion: reduce" in source
    print("Fractal Iris motion contract PASS: original 165 spaghetti paths, "
          "four actual cloud contours, two noise textures restored to motion; "
          "11 closed/eased body transforms; three original iris rotors; "
          "exact static reduced-motion fallbacks; no filter-parameter animation.")


if __name__ == "__main__":
    check()
