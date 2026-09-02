from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
CONCEPT_DIR = ROOT / "concepts" / "profile-svg"

EXPECTED = (
    "01-orbital-core.svg",
    "02-signal-horizon.svg",
    "03-glass-console.svg",
    "04-constellation-matrix.svg",
    "05-prism-minimal.svg",
    "06-circuit-blueprint.svg",
)

WIDTH = 1600.0
HEIGHT = 520.0
VIEWBOX = (0.0, 0.0, WIDTH, HEIGHT)
MIN_TEXT_SIZE = 18.0
MAX_BYTES = 30_000


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def number(value: str | None, label: str) -> float:
    if value is None:
        fail(f"Missing {label}")
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*(?:px)?\s*", value)
    if not match:
        fail(f"Unsupported numeric value for {label}: {value!r}")
    return float(match.group(1))


def effective_text_sizes(node: ET.Element, inherited: float | None = None):
    current = inherited
    if "font-size" in node.attrib:
        current = number(node.attrib["font-size"], "font-size")

    if local_name(node.tag) == "text":
        if current is None:
            fail("Every concept text node must have an explicit or inherited font-size")
        yield node, current

    for child in node:
        yield from effective_text_sizes(child, current)


if not CONCEPT_DIR.exists():
    fail("Concept directory is missing")

found = tuple(sorted(path.name for path in CONCEPT_DIR.glob("*.svg")))
if found != EXPECTED:
    fail(f"Expected exactly the six reviewed SVG concepts; found {found!r}")

for name in EXPECTED:
    path = CONCEPT_DIR / name
    if path.stat().st_size > MAX_BYTES:
        fail(f"{name} exceeds the {MAX_BYTES}-byte concept budget")

    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        fail(f"{name} is invalid XML: {exc}")

    root = tree.getroot()
    if local_name(root.tag) != "svg":
        fail(f"{name} root element is not <svg>")

    if number(root.attrib.get("width"), f"{name} width") != WIDTH:
        fail(f"{name} width must remain {WIDTH:g}")
    if number(root.attrib.get("height"), f"{name} height") != HEIGHT:
        fail(f"{name} height must remain {HEIGHT:g}")

    raw_viewbox = root.attrib.get("viewBox", "")
    try:
        parsed_viewbox = tuple(float(part) for part in raw_viewbox.split())
    except ValueError:
        fail(f"{name} has an invalid viewBox")
    if parsed_viewbox != VIEWBOX:
        fail(f"{name} viewBox must be '0 0 1600 520'")

    if root.attrib.get("preserveAspectRatio") != "xMidYMid meet":
        fail(f"{name} must explicitly preserve its 40:13 composition")

    top = list(root)
    if not any(local_name(node.tag) == "title" for node in top):
        fail(f"{name} requires a top-level <title>")
    if not any(local_name(node.tag) == "desc" for node in top):
        fail(f"{name} requires a top-level <desc>")

    text = path.read_text(encoding="utf-8")
    for token in ("<script", "<foreignObject", "<image", "data:image/", "javascript:"):
        if token.lower() in text.lower():
            fail(f"{name} contains forbidden construct {token!r}")

    for node in root.iter():
        for attr in ("href", "{http://www.w3.org/1999/xlink}href"):
            href = node.attrib.get(attr)
            if href and not href.startswith("#"):
                fail(f"{name} contains an external reference: {href}")

    for node, size in effective_text_sizes(root):
        if size < MIN_TEXT_SIZE:
            content = " ".join("".join(node.itertext()).split())
            fail(f"{name} text is below {MIN_TEXT_SIZE:g}px: {content!r} ({size:g}px)")

print(
    "SVG concept validation passed: six pure-vector 1600x520 compositions, "
    "fixed proportional viewBoxes, >=18px effective typography, and no external/raster content."
)
