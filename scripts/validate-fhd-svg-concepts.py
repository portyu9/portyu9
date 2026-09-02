from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
CONCEPT_DIR = ROOT / "concepts" / "profile-svg-fhd"

EXPECTED = (
    "01-orbital-core.svg",
    "02-signal-horizon.svg",
    "03-glass-console.svg",
    "04-constellation-matrix.svg",
    "05-prism-minimal.svg",
    "06-circuit-blueprint.svg",
)

WIDTH = "1920"
HEIGHT = "1080"
VIEWBOX = "0 0 1920 1080"
PRESERVE = "xMidYMid meet"
MAX_BYTES = 100_000


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


for name in EXPECTED:
    path = CONCEPT_DIR / name
    if not path.exists():
        fail(f"Missing FHD SVG concept: {path.relative_to(ROOT)}")
    if path.stat().st_size > MAX_BYTES:
        fail(f"SVG exceeds {MAX_BYTES} byte review budget: {path.relative_to(ROOT)}")

    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as exc:
        fail(f"Invalid XML in {path.relative_to(ROOT)}: {exc}")

    if root.attrib.get("width") != WIDTH or root.attrib.get("height") != HEIGHT:
        fail(f"{name} must be exact 1920x1080 FHD")
    if root.attrib.get("viewBox") != VIEWBOX:
        fail(f"{name} must use viewBox={VIEWBOX!r}")
    if root.attrib.get("preserveAspectRatio") != PRESERVE:
        fail(f"{name} must preserve aspect ratio with {PRESERVE!r}")

    children = list(root)
    if not any(local_name(node.tag) == "title" for node in children):
        fail(f"{name} requires a top-level <title>")
    if not any(local_name(node.tag) == "desc" for node in children):
        fail(f"{name} requires a top-level <desc>")

    tags = [local_name(node.tag) for node in root.iter()]
    if "text" in tags:
        fail(f"{name} contains a visible <text> element; final typography must be outlined paths")
    if "image" in tags:
        fail(f"{name} contains an <image> element; review concepts must remain pure vector")
    if "foreignObject" in tags or "script" in tags:
        fail(f"{name} contains a forbidden executable/layout element")

    source = path.read_text(encoding="utf-8")
    forbidden = (
        "data:image/",
        "javascript:",
        "font-family=",
        "@font-face",
    )
    for token in forbidden:
        if token.lower() in source.lower():
            fail(f"{name} contains forbidden renderer-dependent content: {token}")

    for match in re.finditer(r"url\(([^)]+)\)", source, re.I):
        target = match.group(1).strip().strip("\"'")
        if not target.startswith("#"):
            fail(f"{name} contains non-local SVG resource reference: {target!r}")

print(
    "FHD SVG concept validation passed: six 1920x1080 pure-vector concepts, "
    "outlined path typography, no renderer-dependent text, and no raster/external assets."
)
