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
    assert d.endswith("s") and 12 <= int(d[:-1]) <= 41


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
    groups = [n for n in elements if n.get("class") == "ambient-motion" and
              n.get("data-role", "").startswith("original-")]
    roles = Counter(n.get("data-role") for n in groups)
    assert roles == Counter({
        "original-nebula-contour": 4,
        "original-nebula-texture": 2,
        "original-spaghetti-body": 5,
    }), roles
    stills = [n for n in elements if n.get("class") == "ambient-still" and
              n.find(NS + "use") is not None]
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
    transforms = [n for n in animations if n.tag == NS + "animateTransform"]
    fades = [n for n in animations if n.tag == NS + "animate"]
    assert len(animations) == 26 and len(transforms) == 17 and len(fades) == 9
    assert all(x.get("attributeName") == "opacity" for x in fades)
    assert not any(n.tag == NS + "animateMotion" for n in animations)
    for filt in root.iter(NS + "filter"):
        assert not any(x.tag in (NS + "animate", NS + "animateTransform")
                       for x in filt.iter()), "expensive filter animation reintroduced"
    assert not any(x.get("attributeName") in
                   ("baseFrequency", "scale", "stdDeviation", "stroke-dashoffset")
                   for x in animations), "unstable original motion replaced with surrogate"
    # A cloud that drifts but never changes illumination appears static.
    # Actual original nebulas each have a visibly significant closed pulse.
    cloud_fades = []
    for group in groups:
        owned = list(group.findall(NS + "animate"))
        if group.get("data-role") in ("original-nebula-contour", "original-nebula-texture"):
            assert len(owned) == 1, "original cloud body missing its illumination pulse"
            cloud_fades.extend(owned)
        else:
            assert len(owned) == 0, "filament bodies must not visibly flicker"
    assert len(cloud_fades) == 6
    assert source.count('id="original-nebula-motion" opacity=".96"') == 1

    corona = next(node for node in elements if node.get("id") == "iris-nebula-corona")
    halos = [node for node in corona if node.get("data-role") == "iris-nebula-corona"]
    assert len(halos) == 3
    assert {node.get("data-color") for node in halos} == {"magenta", "cyan", "violet"}
    for halo in halos:
        zoom = list(halo.findall(NS + "animateTransform"))
        alpha = list(halo.findall(NS + "animate"))
        assert len(zoom) == len(alpha) == 1
        zoom = zoom[0]
        assert zoom.get("attributeName") == "transform" and zoom.get("type") == "scale"
        assert zoom.get("calcMode") == "spline" and zoom.get("keyTimes") == "0;.5;1"
        assert zoom.get("keySplines") == ".42 0 .58 1;.42 0 .58 1"
        assert zoom.get("repeatCount") == "indefinite"
        assert zoom.get("dur") == alpha[0].get("dur")
        assert zoom.get("begin") == alpha[0].get("begin"), (
            "corona size and brightness pulses must remain phase synchronized")
        assert zoom.get("dur") in ("8s", "11s", "13s")
        phases = zoom.get("values", "").split(";")
        assert len(phases) == 3 and phases[0] == phases[2] and phases[0] != phases[1]
        paints = list(halo.findall(NS + "ellipse"))
        assert len(paints) == 1
        assert paints[0].get("fill") == "url(#corona-" + halo.get("data-color") + ")"
        assert all("filter" not in node.attrib for node in halo.iter()), (
            "animated corona contains expensive filter")
    static_corona = [node for node in corona if node.get("data-corona-still")]
    assert len(static_corona) == 3
    assert {node.get("data-corona-still") for node in static_corona} == {
        "magenta", "cyan", "violet"}
    assert len(cloud_fades) + len(halos) == len(fades) == 9

    for fade in fades:
        assert fade.get("attributeName") == "opacity"
        assert fade.get("calcMode") == "spline"
        assert fade.get("keyTimes") == "0;.5;1"
        assert fade.get("keySplines") == ".42 0 .58 1;.42 0 .58 1"
        assert fade.get("repeatCount") == "indefinite"
        phases = fade.get("values", "").split(";")
        assert len(phases) == 3 and phases[0] == phases[2], (
            "brightness pops at repeat boundary")
        low, high = float(phases[0]), float(phases[1])
        assert 0 <= low < high <= 1 and high - low >= .45, (
            "nebula brightness contrast is too subtle to notice")
        assert int(fade.get("dur", "0s")[:-1]) in (7, 8, 9, 10, 11, 12, 13)
        assert fade.get("begin", "").startswith("-"), (
            "each glow must begin in mid-cycle rather than all opening dark")
    assert all(x.tag == NS + "animateTransform" for x in transforms)
    assert len(set(f.get("begin") for f in fades)) >= 5, (
        "all nine glows animate in lockstep, rather than a living atmosphere")

    assert source.count("data-role=\"original-spaghetti-body\"") == 5
    assert "filament-flow" not in source and "ion-flow-magenta" not in source
    assert ".ambient-motion {display:none}" in source
    assert ".ambient-still {display:inline}" in source
    assert {"corona-magenta", "corona-cyan", "corona-violet"} <= known
    assert "prefers-reduced-motion: reduce" in source
    print("Fractal Iris motion contract PASS: original 165 spaghetti paths, "
          "four actual cloud contours, two noise textures restored to motion; "
          "11 closed original-body transforms, six breathing cloud layers; "
          "three independently breathing coronas, three original iris rotors; "
          "full reduced-motion fallback; no filter-parameter animation.")


if __name__ == "__main__":
    check()
