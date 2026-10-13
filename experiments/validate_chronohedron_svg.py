#!/usr/bin/env python3
"""Read-only structural assurance for unmerged Chronohedron artwork studies.

This validates SVG source shape, identical geometry across responsive crops,
smooth closed animation cycles, reduced-motion parity, and isolation from
production. It does not establish physical realism or browser frame timing.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
PREVIEWS = ROOT / "previews"
NS = "{http://www.w3.org/2000/svg}"
SURFACES = {
    "top": ("1280", "258", "0 0 1280 258"),
    "top-compact": ("640", "196", "320 31 640 196"),
    "bottom": ("1280", "150", "0 54 1280 150"),
}
BAD = ("<script", "<foreignobject", "<image", "javascript:", "data:image",
       "<!doctype", "<!entity", "attributeName=\"baseFrequency\"",
       "attributeName=\"stdDeviation\"")


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def displayed_art(node: ET.Element) -> list[bytes]:
    return [ET.tostring(child, encoding="utf-8") for child in node
            if child.tag not in (NS + "animate", NS + "animateTransform")]


def check() -> None:
    normalized: set[str] = set()
    for surface, viewport in SURFACES.items():
        path = PREVIEWS / f"chronohedron-{surface}.svg"
        require(path.is_file() and not path.is_symlink(),
                f"Chronohedron {surface} must be a regular file")
        source = path.read_text(encoding="utf-8")
        require(120000 < len(source.encode("utf-8")) < 150000,
                f"Chronohedron {surface}: artwork density or payload bound regressed")
        lower = source.lower()
        require(not any(token.lower() in lower for token in BAD),
                f"Chronohedron {surface}: unsafe or repaint-heavy payload")
        require("prefers-reduced-motion:reduce" in source and
                ".alive-motion{display:none}" in source and
                ".alive-still{display:inline}" in source,
                f"Chronohedron {surface}: reduced-motion selector missing")
        require("Not approved for production" in source,
                f"Chronohedron {surface}: preview must remain review-only")
        root = ET.fromstring(source)
        require(root.tag == NS + "svg" and root.get("role") == "img"
                and root.get("aria-labelledby") == "title desc"
                and root.get("data-art-study") == "chronohedron-v1"
                and root.get("data-surface") == surface,
                f"Chronohedron {surface}: role/source identity invalid")
        require((root.get("width"), root.get("height"), root.get("viewBox")) == viewport,
                f"Chronohedron {surface}: responsive crop changed")
        require(root.find(NS + "title") is not None and
                root.find(NS + "desc") is not None,
                f"Chronohedron {surface}: accessible name missing")
        nodes = list(root.iter())
        ids = [node.get("id") for node in nodes if node.get("id")]
        require(len(ids) == len(set(ids)), f"Chronohedron {surface}: duplicate SVG IDs")
        require(set(re.findall(r"url\(#([^)]+)\)", source)) <= set(ids),
                f"Chronohedron {surface}: unresolved SVG paint or clip reference")
        require(len(root.findall(f".//{NS}polygon")) >= 100,
                f"Chronohedron {surface}: faceted optical structure truncated")
        require(len(root.findall(f".//{NS}path")) >= 230,
                f"Chronohedron {surface}: waveguide perspective lost")
        require(len(root.findall(f".//{NS}circle")) >= 75,
                f"Chronohedron {surface}: specular grain lost")

        dynamic = [node for node in nodes if node.get("class") == "kinetic"]
        still = [node for node in nodes if node.get("class") == "still"]
        assert len(dynamic) == len(still) == 14, (
            f"Chronohedron {surface}: responsive kinetic/static layer parity lost")
        parents = {child: parent for parent in nodes for child in parent}
        for moving in dynamic:
            parent = parents[moving]
            siblings = list(parent)
            index = siblings.index(moving)
            require(index + 1 < len(siblings) and
                    siblings[index + 1].get("class") == "still",
                    "each moving visual group must have adjacent still counterpart")
            static = siblings[index + 1]
            require(displayed_art(moving) == displayed_art(static),
                    "moving and reduced-motion geometry must match byte-for-byte")
            transforms = moving.findall(NS + "animateTransform")
            require(len(transforms) == 1, "each kinetic group must move physically")
            animation = transforms[0]
            require(animation.get("attributeName") == "transform"
                    and animation.get("type") in ("translate", "rotate")
                    and animation.get("calcMode") == "spline"
                    and animation.get("keyTimes") == "0;.5;1"
                    and animation.get("keySplines") == ".42 0 .58 1;.42 0 .58 1"
                    and animation.get("repeatCount") == "indefinite",
                    "kinetic movement lost cubic closed-curve continuity")
            values = animation.get("values", "").split(";")
            require(len(values) == 3 and values[0] == values[-1]
                    and values[0] != values[1],
                    "kinetic motion must be nontrivial and loop seamlessly")
            require(animation.get("begin", "").startswith("-"),
                    "kinetic loops should start at a nonzero staggered phase")
            fades = moving.findall(NS + "animate")
            require(len(fades) <= 1, "extra animated filter or flashing channel")
            for fade in fades:
                require(fade.get("attributeName") == "opacity"
                        and fade.get("keyTimes") == "0;.5;1"
                        and fade.get("calcMode") == "spline"
                        and fade.get("dur") == animation.get("dur"),
                        "optical reflection and body motion must share a phase")
                values = fade.get("values", "").split(";")
                require(len(values) == 3 and values[0] == values[-1],
                        "lighting pulse has a hard loop seam")
        # NEW physical coupling proof: all atmospheric beds, refractive
        # caustics, actual luminous core, and energy transport must be visible
        # as animated art, while reduced motion uses identical optical geometry.
        life = [node for node in nodes if node.get("class") == "alive-motion"]
        frozen = [node for node in nodes if node.get("class") == "alive-still"]
        require(len(life) == len(frozen) == 25,
                "Chronohedron living optical system or its static fallback vanished")
        require({node.get("data-life") for node in life if node.get("data-life")} ==
                {node.get("data-life-still") for node in frozen
                 if node.get("data-life-still")},
                "living light group IDs and static fallback IDs diverged")
        require(len(root.findall(f".//{NS}animateTransform")) == 38,
                "Chronohedron motion/perspective groups changed")
        feed = next(node for node in nodes
                    if node.get("id") == "alive-photonic-transit")
        no_motion_feed = next(node for node in nodes
                              if node.get("id") == "alive-photonic-transit-still")
        live_channels = list(feed)
        still_channels = list(no_motion_feed)
        require(len(live_channels) == len(still_channels) == 14,
                "both cyan and amber waveguide banks require seven light pulses")
        for active, static in zip(live_channels, still_channels):
            require(active.get("data-feed") and
                    active.get("data-feed") == static.get("data-feed-still"),
                    "approved energy channels lost their reduced-motion counterpart")
            bright = active.findall(NS + "path")
            dead = static.findall(NS + "path")
            require(len(bright) == len(dead) == 2,
                    "moving energy pulse must contain bloom and contact reflection")
            for moving_path, static_path in zip(bright, dead):
                require(moving_path.attrib == static_path.attrib,
                        "static waveguide stroke no longer matches moving geometry")
                pulse = moving_path.find(NS + "animate")
                require(pulse is not None and
                        pulse.get("attributeName") == "stroke-dashoffset" and
                        pulse.get("from") == "0" and pulse.get("to") == "-1000" and
                        pulse.get("repeatCount") == "indefinite" and
                        pulse.get("calcMode") == "linear" and
                        moving_path.get("pathLength") == "1000" and
                        moving_path.get("stroke-dasharray") in ("12 988",) and
                        pulse.get("dur") and pulse.get("begin", "").startswith("-"),
                        "traveling waveguide light must have mathematically closed motion")
                require(static_path.find(NS + "animate") is None,
                        "reduced-motion fallback contains a moving light channel")
        require(len(root.findall(f".//{NS}animate")) == 64,
                "optical pulse or dynamic feed channel lost")
        parents = {child: parent for parent in nodes for child in parent}
        for live in life:
            parent = parents[live]
            peers = list(parent)
            i = peers.index(live)
            require(i + 1 < len(peers) and peers[i + 1].get("class") == "alive-still",
                    "every animated light response requires adjacent static fallback")
            still_layer = peers[i + 1]
            if live is feed:
                continue  # checked above with every dynamic guide pulse stripped
            require(displayed_art(live) == displayed_art(still_layer),
                    "reduced-motion optical geometry differs from moving artwork")
            anim = live.find(NS + "animateTransform")
            require(anim is not None and
                    anim.get("attributeName") == "transform" and
                    anim.get("type") == "translate" and
                    anim.get("keyTimes") == "0;.5;1" and
                    anim.get("calcMode") == "spline" and
                    anim.get("keySplines") == ".42 0 .58 1;.42 0 .58 1" and
                    anim.get("repeatCount") == "indefinite",
                    "living layer lost smooth non-discontinuous displacement")
            steps = anim.get("values", "").split(";")
            require(len(steps) == 3 and steps[0] == steps[-1] and
                    steps[0] != steps[1], "living motion seam or amplitude regressed")
            intensity = live.find(NS + "animate")
            if intensity is not None:
                require(intensity.get("attributeName") == "opacity" and
                        intensity.get("dur") == anim.get("dur") and
                        intensity.get("begin") == anim.get("begin") and
                        intensity.get("keyTimes") == "0;.5;1" and
                        intensity.get("calcMode") == "spline" and
                        intensity.get("values", "").split(";")[0] ==
                        intensity.get("values", "").split(";")[-1],
                        "moving light and luminous pulse are no longer phase coupled")
        require(all(root.find(f".//{NS}g[@id='{part}']") is not None
                    for part in ("alive-reactor-heart", "alive-volumetric-plasma",
                                 "alive-refractive-facets", "alive-chromatic-grazing-caustics",
                                 "alive-dielectric-grain", "alive-photonic-transit")),
                "volumetric/optical system was reduced to a basic flat polygon")
        # The same art must be used in all three responsive shapes: only
        # cropping metadata / title may vary.
        normalized_text = re.sub(
            r'width="(?:1280|640)" height="(?:258|196|150)" viewBox="[^"]+"',
            'width="W" height="H" viewBox="V"', source, count=1)
        normalized_text = re.sub(r'data-surface="[^"]+"',
                                 'data-surface="S"', normalized_text, count=1)
        normalized_text = re.sub(r'<title id="title">.*?</title>',
                                 '<title id="title">TITLE</title>',
                                 normalized_text, count=1)
        normalized.add(hashlib.sha256(normalized_text.encode("utf-8")).hexdigest())
    require(len(normalized) == 1, "Chronohedron responsive variants diverged")
    print("Chronohedron optics proof: 3 responsive studies, 38 smooth vector "
          "transforms, 14 closed-loop transported cyan/amber channels, "
          "25 reduced-motion optical-layer mirrors, 108+ grain points, "
          "bright breathing reactor, independently moving gaseous environment, "
          "phase-linked glass caustics, no animated noise or blurs, "
          "no production enrollment.")


if __name__ == "__main__":
    check()
