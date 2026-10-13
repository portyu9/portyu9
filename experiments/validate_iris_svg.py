#!/usr/bin/env python3
"""Read-only contract checks for the unshipped Fractal Iris review SVG.

The test encodes the *specific* stutter regressions observed in the previous
proof of concept. It does not claim real-time FPS or substitute for frame capture.
"""
from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree as ET

SVG = Path(__file__).resolve().parent / "previews" / "fractal-iris-animated.svg"
SVG_NS = "{http://www.w3.org/2000/svg}"


def test() -> None:
    data = SVG.read_text(encoding="utf-8")
    root = ET.fromstring(data)
    assert root.tag == SVG_NS + "svg"
    assert root.get("viewBox") == "0 0 1280 258"
    assert root.get("width") == "1280" and root.get("height") == "258"
    assert "<script" not in data and "<foreignObject" not in data
    assert not any(snippet in data for snippet in ('href="http:', 'href="https:', 'xlink:href="http:', 'xlink:href="https:')), "external resource load"
    assert len(data.encode("utf-8")) < 160_000, "review asset payload grew unexpectedly"

    ids = {item.attrib["id"] for item in root.iter() if "id" in item.attrib}
    refs = re.findall(r"url\(#([^)]+)\)", data)
    assert set(refs) <= ids, "dangling paint/filter/mask references"

    forbidden_animations = {"baseFrequency", "scale", "stdDeviation", "path", "d", "opacity"}
    animation_elements = [
        element for element in root.iter() if element.tag in
        (SVG_NS + "animate", SVG_NS + "animateTransform", SVG_NS + "animateMotion")
    ]
    assert len(animation_elements) == 3, "unreviewed motion system introduced"
    assert all(element.tag == SVG_NS + "animateTransform" for element in animation_elements)
    assert not any(element.get("attributeName") in forbidden_animations for element in animation_elements)

    motion_groups = [
        element for element in root.iter()
        if element.get("class") == "motion"
    ]
    fallback_groups = [
        element for element in root.iter()
        if element.get("class") == "motion-still"
    ]
    assert len(motion_groups) == len(fallback_groups) == 3
    for group in motion_groups:
        animations = list(group.findall(SVG_NS + "animateTransform"))
        assert len(animations) == 1
        animation = animations[0]
        assert animation.get("attributeName") == "transform"
        assert animation.get("type") == "rotate"
        assert animation.get("from") == "0"
        assert animation.get("to") in ("360", "-360")
        assert animation.get("calcMode") == "linear"
        assert animation.get("repeatCount") == "indefinite"
        duration = animation.get("dur", "")
        assert duration.endswith("s") and int(duration[:-1]) >= 45
        # Never animate a subtree containing a large/repaint-heavy SVG filter.
        assert not any("filter" in node.attrib for node in group.iter()), "filtered optics group is animated"
        assert not any(node.tag in (SVG_NS + "feTurbulence",
                                    SVG_NS + "feDisplacementMap") for node in group.iter())

    for filter_element in root.iter(SVG_NS + "filter"):
        assert not any(node.tag in (SVG_NS + "animate", SVG_NS + "animateTransform")
                       for node in filter_element.iter()), "animated filter recalculates each frame"
    assert 'prefers-reduced-motion: reduce' in data
    assert '.motion-still {display:inline}' in data
    assert len(list(root.iter(SVG_NS + "feTurbulence"))) <= 4
    assert len(list(root.iter(SVG_NS + "path"))) >= 100, "textured design unexpectedly hollowed"
    assert data.count('fill="url(#bladeMetal)"') == 32, "16 iris blades and 16 static fallbacks required"
    print("Fractal Iris SVG structural motion regression checks passed: "
          "fixed texture parameters; continuous low-cost optics; "
          "dimensional reduced-motion fallback; bounded payload")


if __name__ == "__main__":
    test()
