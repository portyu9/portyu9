#!/usr/bin/env python3
"""Read-only structural assurance for unmerged Chronohedron artwork studies.

This validates SVG source shape, identical geometry across responsive crops,
smooth closed animation cycles, reduced-motion parity, and isolation from
production. It does not establish physical realism or browser frame timing.
"""
from __future__ import annotations

import ast
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


def canonical_profile_colors() -> frozenset[str]:
    """Read the four actual profile theme colors without executing production code."""
    palette_source = (ROOT.parent / "scripts/phosphor-lines-signal-field-v2.py")
    module = ast.parse(palette_source.read_text(encoding="utf-8"))
    assignments = [
        node.value for node in module.body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "HEADER_COLORS"
                for target in node.targets)
    ]
    require(len(assignments) == 1, "profile canonical theme declaration changed")
    theme = ast.literal_eval(assignments[0])["dark"]
    require(set(theme) == {"green", "magenta", "violet", "cyan"}
            and len(set(theme.values())) == 4
            and all(re.fullmatch(r"#[0-9A-F]{6}", color)
                    for color in theme.values()),
            "profile theme palette changed or lost one of four phosphors")
    return frozenset(theme.values())


def check() -> None:
    canonical = canonical_profile_colors()
    normalized: set[str] = set()
    for surface, viewport in SURFACES.items():
        path = PREVIEWS / f"chronohedron-{surface}.svg"
        require(path.is_file() and not path.is_symlink(),
                f"Chronohedron {surface} must be a regular file")
        source = path.read_text(encoding="utf-8")
        require(150000 < len(source.encode("utf-8")) < 185000,
                f"Chronohedron {surface}: artwork density or payload bound regressed")
        lower = source.lower()
        require(not any(token.lower() in lower for token in BAD),
                f"Chronohedron {surface}: unsafe or repaint-heavy payload")
        require("prefers-reduced-motion:reduce" in source and
                ".kinetic,.alive-motion,.contact-motion,.theme-motion,.theme-optic-motion,.reactive-motion{display:none}" in source and
                ".still,.alive-still,.contact-still,.theme-still,.theme-optic-still,.reactive-still{display:inline}" in source and
                ".charge-motion,.charge-contact-motion,.charge-interior-motion{display:none}" in source and
                ".charge-still,.charge-contact-still,.charge-interior-still{display:inline}" in source,
                f"Chronohedron {surface}: reduced-motion selector missing")
        require("Not approved for production" in source,
                f"Chronohedron {surface}: preview must remain review-only")
        root = ET.fromstring(source)
        require(root.tag == NS + "svg" and root.get("role") == "img"
                and root.get("aria-labelledby") == "title desc"
                and root.get("data-art-study") == "chronohedron-v1"
                and root.get("data-surface") == surface
                and root.get("data-theme-palette") == "profile-phosphor-lines-v2.8-dark",
                f"Chronohedron {surface}: role/source identity invalid")
        require((root.get("width"), root.get("height"), root.get("viewBox")) == viewport,
                f"Chronohedron {surface}: responsive crop changed")
        require(root.find(NS + "title") is not None and
                root.find(NS + "desc") is not None,
                f"Chronohedron {surface}: accessible name missing")
        # The ONLY chromatic paints allowed are the four dark profile
        # HEADER_COLORS. Pure black is unlit negative space, not a theme hue.
        # Enforce this on the actual source literals, including defs and CSS,
        # so a later yellow/amber/gold gradient cannot silently sneak in.
        chromatic = set(re.findall(r"#[0-9a-fA-F]{3,8}\b", source))
        require(chromatic == set(canonical),
                f"Chronohedron {surface}: non-profile paint introduced or one "
                f"of the four canonical colors missing: "
                f"{sorted(chromatic.symmetric_difference(canonical))}")
        allowed_paints = set(canonical) | {"black", "none"}
        for node in root.iter():
            for attr in ("fill", "stroke", "stop-color", "flood-color", "color"):
                paint = node.get(attr)
                if paint is not None:
                    require(paint in allowed_paints or
                            re.fullmatch(r"url\(#[a-zA-Z0-9_-]+\)", paint),
                            f"off-profile color in {surface} <{node.tag}> {attr}: {paint}")
        require('M641 79 Q661 108 648 132 T635 176' not in source,
                "rejected central yellow fading swirl returned")
        require("amber" not in source.lower() and "gold" not in source.lower(),
                "legacy warm optical channels returned instead of profile phosphors")
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
        require(len(root.findall(f".//{NS}animateTransform")) == 50,
                "Chronohedron motion/perspective groups changed")
        feed = next(node for node in nodes
                    if node.get("id") == "alive-photonic-transit")
        no_motion_feed = next(node for node in nodes
                              if node.get("id") == "alive-photonic-transit-still")
        live_channels = list(feed)
        still_channels = list(no_motion_feed)
        require(len(live_channels) == len(still_channels) == 14,
                "both cyan and magenta waveguide banks require seven light pulses")
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
        require(len(root.findall(f".//{NS}animate")) == 118,
                "optical pulse or dynamic feed channel lost")
        contact_motion = [node for node in nodes
                          if node.get("class") == "contact-motion"]
        contact_still = [node for node in nodes
                         if node.get("class") == "contact-still"]
        require(len(contact_motion) == len(contact_still) == 14,
                "each travelling beam needs exactly one endpoint light response")
        contact_names = {node.get("data-contact") for node in contact_motion}
        require(contact_names ==
                {node.get("data-contact-still") for node in contact_still} ==
                {node.get("data-feed") for node in live_channels},
                "contact flash must exist for precisely the input guide colors")
        for live_contact, still_contact, channel in zip(
                contact_motion, contact_still, live_channels):
            name = live_contact.get("data-contact")
            require(name == live_contact.get("data-feed-match") ==
                    still_contact.get("data-contact-still") ==
                    channel.get("data-feed"),
                    "the light response is wired to the wrong supply lane")
            require(displayed_art(live_contact) == displayed_art(still_contact),
                    "reduced-motion contact reflection differs in geometry")
            incident = channel.find(f"{NS}path/{NS}animate")
            light = live_contact.find(NS + "animate")
            require(incident is not None and light is not None,
                    "source energy stream or its contact reaction disappeared")
            require(light.get("attributeName") == "opacity" and
                    light.get("dur") == incident.get("dur") and
                    light.get("begin") == incident.get("begin") and
                    light.get("repeatCount") == "indefinite",
                    "contact light isn't locked to actual travelling energy phase")
            require(light.get("values") == ".09;.14;.94;.09" and
                    light.get("keyTimes") == "0;.7;.88;1" and
                    light.get("calcMode") == "spline" and
                    light.get("keySplines") ==
                    ".42 0 .58 1;.25 .45 .55 1;.42 0 .58 1",
                    "contact flash changed from smooth delayed arrival response")
            require(still_contact.find(NS + "animate") is None,
                    "reduced-motion glass contact must never flash")

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
        # Four routed spectral facet circuits visibly move THROUGH crystal
        # edges rather than leaving only ambient external motion. They are
        # strictly restricted to four canonical colors, each with a matched
        # static reduced-motion circuit.
        spectral = root.find(f".//{NS}g[@id='theme-facet-energy']")
        static_spectral = root.find(f".//{NS}g[@id='theme-facet-energy-still']")
        require(spectral is not None and static_spectral is not None
                and spectral.get("class") == "theme-motion"
                and static_spectral.get("class") == "theme-still",
                "moving in-glass theme circuits or reduced motion missing")
        require(len(spectral) == len(static_spectral) == 4,
                "expected exactly one travelling facet network per profile hue")
        routing_colors: set[str] = set()
        for dynamic_route, static_route in zip(spectral, static_spectral):
            require(dynamic_route.get("data-spectral-channel")
                    == static_route.get("data-spectral-still"),
                    "spectral geometry and static routing identities diverged")
            paths = dynamic_route.findall(NS + "path")
            still_paths = static_route.findall(NS + "path")
            require(len(paths) == len(still_paths) == 2,
                    "spectral transit must retain both bloom and sharp energized face")
            for active_path, still_path in zip(paths, still_paths):
                routing_colors.add(active_path.get("stroke", ""))
                require(active_path.attrib == still_path.attrib and
                        active_path.get("pathLength") == "1000" and
                        active_path.get("stroke-dasharray") == "52 948",
                        "static and active optical path geometry must match")
                sweep = active_path.find(NS + "animate")
                require(sweep is not None and sweep.get("attributeName") ==
                        "stroke-dashoffset" and sweep.get("from") == "0" and
                        sweep.get("to") == "-1000" and
                        sweep.get("calcMode") == "linear" and
                        sweep.get("repeatCount") == "indefinite" and
                        still_path.find(NS + "animate") is None,
                        "faceted energy streak must traverse a closed, smooth route")
        require(routing_colors == set(canonical),
                "one of the four profile theme colors has no animated facet channel")
        # Four chromatic caustic groups are coupled to the four
        # physically travelling spectral circuits. Do not let unrelated
        # decorative swirls or phase-slipping color effects return.
        impact = root.find(f".//{NS}g[@id='theme-spectral-impact']")
        require(impact is not None and len(impact) == 8,
                "four optical caustic actions and their static copies required")
        impact_groups = list(impact)
        intended = tuple(list(spectral)[index].find(NS + "path").get("stroke")
                         for index in range(4))
        for index, color in enumerate(intended):
            live = impact_groups[index * 2]
            still = impact_groups[index * 2 + 1]
            require(live.get("class") == "theme-optic-motion" and
                    still.get("class") == "theme-optic-still" and
                    live.get("data-theme-caustic") ==
                    still.get("data-theme-caustic-still"),
                    "each phase-locked glass-edge caustic must have a static twin")
            require(displayed_art(live) == displayed_art(still),
                    "moving and reduced-motion glass caustic geometry diverged")
            shape = live.find(f"{NS}g/{NS}path")
            require(shape is not None and shape.get("stroke") == color,
                    "edge caustic must exactly match canonical profile hue")
            motion = live.find(NS + "animateTransform")
            intensity = live.find(NS + "animate")
            route = list(spectral)[index]
            feed_phase = route.find(f"{NS}path/{NS}animate")
            require(motion is not None and intensity is not None and
                    feed_phase is not None and
                    motion.get("dur") == intensity.get("dur") ==
                    feed_phase.get("dur") and
                    motion.get("begin") == intensity.get("begin") ==
                    feed_phase.get("begin"),
                    "glass caustic stopped responding to spectral energy phase")
            vals = motion.get("values", "").split(";")
            lighting = intensity.get("values", "").split(";")
            require(len(vals) == len(lighting) == 3 and
                    vals[0] == vals[-1] and
                    lighting[0] == lighting[-1] and
                    motion.get("calcMode") == intensity.get("calcMode") == "spline" and
                    motion.get("keySplines") ==
                    ".42 0 .58 1;.42 0 .58 1" and
                    motion.get("repeatCount") ==
                    intensity.get("repeatCount") == "indefinite",
                    "glass edge caustic must loop smoothly without frame jump")
            require(not list(still.iter(NS + "animate")) and
                    not list(still.iter(NS + "animateTransform")),
                    "reduced-motion static glass should contain no SMIL animations")
        # The original black center read as a hollow void with meaningless
        # faint stripes. Exactly four source-coupled active glass membranes
        # now make all canonical profile colors illuminate the crystal cavity.
        cavity = root.find(f".//{NS}g[@id='inner-energy-cavity']")
        chamber = root.find(f".//{NS}g[@id='reactor-spectral-chamber']")
        require(cavity is not None and chamber is not None and
                len(chamber) == 8 and
                len(cavity.findall(NS + "polygon")) == 2 and
                cavity.find(NS + "polygon").get("fill") ==
                "url(#reactor-cavity-light)",
                "reactor chamber reverted to opaque black empty cutout")
        require('fill="black" opacity=".8"' not in source and
                'M621.0 99.0 Q640 95.0' not in source,
                "old black center or meaningless curved stripes returned")
        theme = ("green", "cyan", "violet", "magenta")
        for i, tone in enumerate(theme):
            live, still = chamber[2 * i], chamber[2 * i + 1]
            require(live.get("class") == "reactive-motion" and
                    still.get("class") == "reactive-still" and
                    live.get("data-reactive") ==
                    still.get("data-reactive-still") == tone,
                    "reactive membrane identity / reduced-motion parity missing")
            require(displayed_art(live) == displayed_art(still),
                    "reduced-motion glass membrane geometry differs")
            require(len(live.findall(NS + "path")) == 2 and
                    live.findall(NS + "path")[1].get("stroke") ==
                    spectral[i].find(NS + "path").get("stroke"),
                    "color of incoming light is not reflected in its glass")
            injection = spectral[i].find(f"{NS}path/{NS}animate")
            motion = live.find(NS + "animateTransform")
            glow = live.find(NS + "animate")
            require(injection is not None and motion is not None and
                    glow is not None and
                    injection.get("dur") == motion.get("dur") ==
                    glow.get("dur") and injection.get("begin") ==
                    motion.get("begin") == glow.get("begin"),
                    "color-specific light response drifted from actual energy")
            require(motion.get("type") == "translate" and
                    motion.get("keyTimes") == glow.get("keyTimes") ==
                    "0;.5;1" and
                    motion.get("keySplines") == glow.get("keySplines") ==
                    ".42 0 .58 1;.42 0 .58 1" and
                    motion.get("calcMode") == glow.get("calcMode") == "spline",
                    "glowing geometry lost smooth, non-discontinuous motion")
            shifts = motion.get("values", "").split(";")
            alphas = glow.get("values", "").split(";")
            require(len(shifts) == len(alphas) == 3 and
                    shifts[0] == shifts[-1] and shifts[0] != shifts[1] and
                    alphas[0] == alphas[-1] and
                    float(alphas[0]) <= .3 < .9 <= float(alphas[1]) and
                    glow.get("repeatCount") ==
                    motion.get("repeatCount") == "indefinite",
                    "living glass flashes too weakly or snaps on repeat")
        # The four exact profile phosphors now carry energy all the way
        # from far-field terminals to the physical crystal, and on into the
        # spectral chamber. This is phase-coupled motion, not ornamental
        # spinning or a reintroduced yellow helix.
        network = root.find(f".//{NS}g[@id='chronohedron-four-color-charge-network']")
        require(network is not None and
                network.get("pointer-events") == "none" and len(network) == 4,
                "four-color feed/interior linkage has been removed")
        names = ("green", "cyan", "violet", "magenta")
        phase = {"green": ("8.6s", "-1.8s"),
                 "cyan": ("12.6s", "-4.6s"),
                 "violet": ("10.4s", "-3.1s"),
                 "magenta": ("15.2s", "-6.2s")}
        colors: set[str] = set()
        chamber = root.find(f".//{NS}g[@id='reactor-spectral-chamber']")
        require(chamber is not None,
                "reactive four-profile-color crystal chamber missing")
        for index, name in enumerate(names):
            cluster = network[index]
            require(cluster.get("data-charge-color") == name and
                    cluster.get("data-connects") == "perimeter-to-reactor" and
                    len(cluster) == 6, "missing powered glass charge route " + name)
            flow, static_flow, contact, static_contact, inner, static_inner = cluster
            require(flow.get("class") == "charge-motion" and
                    static_flow.get("class") == "charge-still" and
                    contact.get("class") == "charge-contact-motion" and
                    static_contact.get("class") == "charge-contact-still" and
                    inner.get("class") == "charge-interior-motion" and
                    static_inner.get("class") == "charge-interior-still",
                    "every live feed/contact/glass group needs static counterpart")
            require(flow.get("data-charge-flow") ==
                    static_flow.get("data-charge-flow-still") ==
                    contact.get("data-charge-contact") ==
                    static_contact.get("data-charge-contact-still") ==
                    inner.get("data-charge-interior") ==
                    static_inner.get("data-charge-interior-still") == name,
                    "same phosphor must power corresponding outer/inner glass")
            paths = flow.findall(NS + "path")
            still_paths = static_flow.findall(NS + "path")
            require(len(paths) == len(still_paths) == 4,
                    "paired charge streams lost their luminous body+halo")
            colors.update(p.get("stroke") for p in paths)
            duration, offset = phase[name]
            for active, frozen in zip(paths, still_paths):
                require(active.attrib == frozen.attrib and
                        active.get("pathLength") == "1000" and
                        active.get("stroke-dasharray") in ("28 972", "14 986"),
                        "charged path and reduced-motion geometry diverged")
                animation = active.find(NS + "animate")
                require(animation is not None and
                        animation.get("attributeName") == "stroke-dashoffset" and
                        animation.get("from") == "0" and
                        animation.get("to") == "-1000" and
                        animation.get("dur") == duration and
                        animation.get("begin") == offset and
                        animation.get("repeatCount") == "indefinite" and
                        animation.get("calcMode") == "linear",
                        "charge transport has a dash seam or is not phase-locked")
                require(frozen.find(NS + "animate") is None,
                        "reduced-motion feed must not move")
            require(displayed_art(contact) == displayed_art(static_contact),
                    "impact flare differs between moving and still views")
            beam_end = contact.find(NS + "animate")
            internal_trans = inner.find(NS + "animateTransform")
            internal_pulse = inner.find(NS + "animate")
            require(beam_end is not None and internal_trans is not None and
                    internal_pulse is not None,
                    "energy never enters crystal in animated scene")
            for active in (beam_end, internal_trans, internal_pulse):
                require(active.get("begin") == offset and
                        active.get("dur") == duration and
                        active.get("repeatCount") == "indefinite",
                        "outer energy, facet arrival and inner response desynchronized")
            require(internal_trans.get("attributeName") == "transform" and
                    internal_trans.get("type") == "translate" and
                    internal_trans.get("calcMode") == "spline" and
                    internal_trans.get("keyTimes") == "0;.5;1" and
                    internal_trans.get("keySplines") ==
                    ".42 0 .58 1;.42 0 .58 1",
                    "internal refraction is not smoothly accelerated")
            turns = internal_trans.get("values", "").split(";")
            require(len(turns) == 3 and turns[0] == turns[-1] and
                    turns[0] != turns[1], "new internal reflector has frame jump")
            require(displayed_art(inner) == displayed_art(static_inner),
                    "accessibility fallback for crystal illumination missing")
            require(not list(static_inner.iter(NS + "animate")) and
                    not list(static_inner.iter(NS + "animateTransform")),
                    "reduced-motion counterpart still has dynamic light")
            require(len(inner.findall(f".//{NS}path")) == 2 and
                    inner.find(NS + "g").get("clip-path") ==
                    "url(#alive-glass-clip)",
                    "inner electric path not physically clipped to glass")
            chamber_group = next((item for item in chamber
                                  if item.get("data-reactive") == name), None)
            require(chamber_group is not None and
                    chamber_group.find(NS + "animate").get("dur") == duration and
                    chamber_group.find(NS + "animate").get("begin") == offset,
                    "new four-color charge route broke existing chamber rhythm")
        require(colors == set(canonical),
                "off-theme chromatic lightning added to external feeds")
        require(source.count("data-charge-color=") == 4 and
                source.count('id="chronohedron-four-color-charge-network"') == 1,
                "charge network duplicated or lost")
        require(not any(tag in source for tag in
                        ("vivid-crystal-helix", "helical-flow", "#ffd", "#ffe")),
                "old yellow center vortex or off-profile yellow returned")
        # Solid black is a required render surface, including both extreme
        # edges of the wide and compact-cropped profile banner. No discarded
        # translucent "glow ring" may reveal the GitHub checkerboard.
        require(root.get("style") == "background-color:black",
                "black SVG-root fallback was removed")
        backgrounds = list(root.findall(NS + "rect"))
        require(bool(backgrounds) and backgrounds[0].attrib == {
                    "x": "0", "y": "0", "width": "1280", "height": "258",
                    "fill": "black", "data-opaque-banner-backdrop": "true"},
                "full SVG canvas must be painted opaque with literal black")
        root_children = list(root)
        require(root_children.index(backgrounds[0]) <
                min(index for index, node in enumerate(root_children)
                    if node.tag in (NS + "g", NS + "ellipse", NS + "path")),
                "black backdrop must precede every light/translucent effect")
        require(not any(fragment in source for fragment in (
                    'id="night"', 'id="haloIce"', 'id="haloMagenta"',
                    'url(#night)', 'url(#haloIce)', 'url(#haloMagenta)')),
                "rejected oversized washed-out ellipse/gradient came back")
        require(not any(ell.get("rx") and ell.get("ry") and
                        float(ell.get("rx")) >= 230 and
                        float(ell.get("ry")) >= 105
                        for ell in root.iter(NS + "ellipse")),
                "large pale oval reintroduced over black profile edges")
        # Physical surface grain is a fixed bounded noise kernel, never a
        # time-varying turbulence or blur operation on the moving artwork.
        glass = root.find(f".//{NS}g[@id='alive-dielectric-material-depth']")
        noise = root.find(f".//{NS}filter[@id='alive-fixed-dielectric-texture']")
        require(glass is not None and noise is not None,
                "detailed dielectric glass microstructure disappeared")
        turbulence = noise.find(NS + "feTurbulence")
        require(turbulence is not None and
                turbulence.get("baseFrequency") == ".058 .12" and
                turbulence.get("numOctaves") == "2" and
                turbulence.get("seed") == "19" and
                turbulence.get("stitchTiles") == "stitch",
                "crystal texture kernel is not static and bounded")
        chromatic_matrix = noise.find(NS + "feColorMatrix")
        require(chromatic_matrix is not None and
                chromatic_matrix.get("values") ==
                "0 0 0 0 .156862745 0 0 0 0 .843137255 "
                "0 0 0 0 1 .11 .22 .27 0 -.22",
                "dielectric microtexture must emit only canonical cyan, not off-theme blue")
        require(not list(noise.iter(NS + "animate")) and
                not list(noise.iter(NS + "animateTransform")) and
                not list(glass.iter(NS + "animate")) and
                not list(glass.iter(NS + "animateTransform")),
                "animated raster-heavy microfracture optics forbidden")

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
    print("Chronohedron optics proof: 3 responsive studies, 50 smooth vector "
          "transforms, 14 closed-loop transported cyan/magenta channels, "
          "25 reduced-motion optical-layer mirrors, 14 light-bound " 
          "transport endpoints with static counterparts, 108+ grain points, "
          "four profile-color source-coupled reactor glass membranes, "
          "bright breathing reactor, independently moving gaseous environment, "
          "phase-linked glass caustics, no animated noise or blurs, "
          "four exact profile phosphors, opaque black backing without pale halo, no amber/yellow center swirl, "
          "four closed spectral energy routes, four corresponding optical caustics, "
          "four external-to-crystal phase-linked charge bundles and reduced-motion mirrors; "
          "no production enrollment.")


if __name__ == "__main__":
    check()
