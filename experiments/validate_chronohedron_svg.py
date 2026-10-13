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
        require(65000 < len(source.encode("utf-8")) < 100000,
                f"Chronohedron {surface}: artwork density or payload bound regressed")
        lower = source.lower()
        require(not any(token.lower() in lower for token in BAD),
                f"Chronohedron {surface}: unsafe or repaint-heavy payload")
        require("prefers-reduced-motion:reduce" in source,
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
    print("Chronohedron proof passed: 3 shared-geometry review variants, "
          "100+ facets, 14 closed/eased physical motion systems, "
          "14 parity-checked reduced-motion copies, zero external scripts, "
          "zero animated filters; no production enrollment.")


if __name__ == "__main__":
    check()
