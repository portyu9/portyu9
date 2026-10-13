#!/usr/bin/env python3
"""Read-only structural motion contract for the experimental Fractal Iris SVG.

Validates coherent closed loops and guards old repaint-heavy animation hazards.
Does NOT assert real-browser frame cadence, 60 FPS, or artistic quality.
"""
from __future__ import annotations

from pathlib import Path
import re
import xml.etree.ElementTree as ET

SVG = Path(__file__).resolve().parent / "previews" / "fractal-iris-animated.svg"
NS = "{http://www.w3.org/2000/svg}"


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
    assert set(re.findall(r"url\(#([^)]+)\)", source)) <= set(ids), "unresolved SVG reference"

    animations = [n for n in root.iter() if n.tag in (
        NS + "animate", NS + "animateTransform", NS + "animateMotion")]
    transforms = [n for n in animations if n.tag == NS + "animateTransform"]
    flows = [n for n in animations if n.tag == NS + "animate"]
    assert len(transforms) == 5 and len(flows) == 14 and len(animations) == 19
    forbidden = {"baseFrequency", "scale", "stdDeviation", "opacity", "path", "d"}
    assert not any(n.get("attributeName") in forbidden for n in animations)
    assert not any(n.tag == NS + "animateMotion" for n in animations)
    for filt in root.iter(NS + "filter"):
        assert not any(n.tag in (NS + "animate", NS + "animateTransform")
                       for n in filt.iter()), "expensive filter animation reintroduced"

    # Original optical rotor system, with a duplicate static render for
    # reduced-motion users so the elaborate center never disappears.
    rotors = [n for n in root.iter() if n.get("class") == "motion"]
    stills = [n for n in root.iter() if n.get("class") == "motion-still"]
    assert len(rotors) == len(stills) == 3
    for rotor in rotors:
        nodes = list(rotor.findall(NS + "animateTransform"))
        assert len(nodes) == 1
        n = nodes[0]
        assert n.get("attributeName") == "transform"
        assert n.get("type") == "rotate"
        assert n.get("from") == "0" and n.get("to") in ("360", "-360")
        assert n.get("calcMode") == "linear" and n.get("repeatCount") == "indefinite"
        assert int(n.get("dur", "0s")[:-1]) >= 45
        assert not any("filter" in a.attrib for a in rotor.iter())

    # Atmospheric paths can drift; static expensive turbulence must not.
    ambient = [n for n in root.iter() if n.get("class") == "ambient-motion"]
    assert len(ambient) == 2
    nebula = next(n for n in ambient if n.get("id") == "nebula-flow")
    drifting = list(nebula.iter(NS + "animateTransform"))
    assert len(drifting) == 2
    assert len(list(nebula.iter(NS + "path"))) == 4
    for n in drifting:
        assert n.get("type") == "translate" and n.get("attributeName") == "transform"
        assert n.get("calcMode") == "spline"
        assert n.get("keyTimes") == "0;.5;1"
        assert n.get("keySplines") == ".42 0 .58 1;.42 0 .58 1"
        assert n.get("repeatCount") == "indefinite"
        assert n.get("dur") in ("19s", "23s")
        phases = n.get("values", "").split(";")
        assert len(phases) == 3 and phases[0] == phases[-1], "jump at nebula loop seam"
    assert not any("filter" in a.attrib for a in nebula.iter())

    # Filament highlights travel across preserved stationary filaments;
    # period exactly matches dash pattern (162), avoiding a jump at reset.
    filament = next(n for n in ambient if n.get("id") == "filament-flow")
    paths = list(filament.findall(NS + "path"))
    assert len(paths) == 14
    for p in paths:
        assert "filter" not in p.attrib
        assert sum(map(float, p.get("stroke-dasharray", "").split())) == 162
        moves = list(p.findall(NS + "animate"))
        assert len(moves) == 1
        n = moves[0]
        assert n.get("attributeName") == "stroke-dashoffset"
        assert n.get("from") == "0" and n.get("to") == "-162"
        assert n.get("calcMode") == "linear" and n.get("repeatCount") == "indefinite"
        assert 14 <= int(n.get("dur", "0s")[:-1]) <= 22
    assert '.ambient-motion {display:inline}' in source
    assert '.ambient-motion {display:none}' in source
    assert 'prefers-reduced-motion: reduce' in source
    assert source.count('fill="url(#bladeMetal)"') == 32
    assert len(list(root.iter(NS + "feTurbulence"))) <= 4
    assert len(list(root.iter(NS + "path"))) > 100
    print("Fractal Iris motion contract passed: 2 seamless nebula drifts, "
          "14 seamless filament flows, 3 small optics, static textures, "
          "full reduced-motion fallback; no heavy-group filter animation")


if __name__ == "__main__":
    check()
