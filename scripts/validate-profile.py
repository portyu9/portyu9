from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
SVG_DIR = ROOT / "assets"

HERO = SVG_DIR / "qe-command-center.svg"
REQUIRED_SVGS = (
    HERO,
    SVG_DIR / "qe-systems-map.svg",
    SVG_DIR / "repository-signal.svg",
)

RASTER_EXTENSIONS = r"(?:png|jpe?g|gif|webp)"
MIN_EXPLICIT_TEXT_SIZE = 13.0
LOCKED_PROFILE_NAME = "Ƴunior Ƥortal"
LOCKED_PROFILE_NAME_SIZE = 39.0


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def numeric(value: str | None, label: str) -> float:
    if value is None:
        fail(f"Missing numeric SVG attribute: {label}")
    match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*(?:px)?\s*", value)
    if not match:
        fail(f"Unsupported numeric SVG value for {label}: {value!r}")
    return float(match.group(1))


if not README.exists():
    fail("README.md is missing")

readme = README.read_text(encoding="utf-8")

# Branding contract: visible profile artwork is SVG-only.
html_raster = re.search(
    rf'''<img\b[^>]*\bsrc=["'][^"']+\.{RASTER_EXTENSIONS}(?:[?#][^"']*)?["']''',
    readme,
    re.I,
)
markdown_raster = re.search(
    rf'''!\[[^\]]*\]\([^)]*\.{RASTER_EXTENSIONS}(?:[?#][^)]*)?\)''',
    readme,
    re.I,
)
if html_raster or markdown_raster:
    match = html_raster or markdown_raster
    fail(f"README references raster artwork: {match.group(0)}")

svg_refs = set(
    re.findall(r'''<img\b[^>]*\bsrc=["']([^"']+\.svg)["']''', readme, re.I)
    + re.findall(r'''!\[[^\]]*\]\(([^)]+\.svg)\)''', readme, re.I)
)
if not svg_refs:
    fail("README contains no SVG artwork references")

for ref in svg_refs:
    if ref.startswith(("http://", "https://")):
        continue
    path = (ROOT / ref).resolve()
    if ROOT not in path.parents:
        fail(f"SVG reference escapes the repository: {ref}")
    if not path.exists():
        fail(f"Referenced SVG does not exist: {ref}")

parsed: dict[Path, ET.Element] = {}
for path in REQUIRED_SVGS:
    if not path.exists():
        fail(f"Required SVG missing: {path.relative_to(ROOT)}")
    if path.stat().st_size > 100_000:
        fail(f"SVG exceeds 100 KiB design budget: {path.relative_to(ROOT)}")

    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        fail(f"Invalid XML in {path.relative_to(ROOT)}: {exc}")

    root = tree.getroot()
    parsed[path] = root
    children = list(root)
    if not any(local_name(node.tag) == "title" for node in children):
        fail(f"SVG requires a top-level <title>: {path.relative_to(ROOT)}")
    if not any(local_name(node.tag) == "desc" for node in children):
        fail(f"SVG requires a top-level <desc>: {path.relative_to(ROOT)}")

    width = numeric(root.attrib.get("width"), f"{path.name} width")
    height = numeric(root.attrib.get("height"), f"{path.name} height")
    if width < 1200 or height < 450:
        fail(f"SVG canvas is below the readability floor: {path.relative_to(ROOT)} ({width:g}x{height:g})")

    text = path.read_text(encoding="utf-8")
    forbidden = ("<script", "<foreignObject", "data:image/", "javascript:")
    for token in forbidden:
        if token.lower() in text.lower():
            fail(f"Forbidden SVG construct {token!r} in {path.relative_to(ROOT)}")

    # Pure-vector contract: no embedded or linked raster/image nodes.
    if any(local_name(node.tag) == "image" for node in root.iter()):
        fail(f"SVG contains an <image> element instead of pure vector primitives: {path.relative_to(ROOT)}")

    # Readability contract: explicit text sizes may not regress into microcopy.
    for node in root.iter():
        if local_name(node.tag) != "text" or "font-size" not in node.attrib:
            continue
        size = numeric(node.attrib["font-size"], f"{path.name} text font-size")
        if size < MIN_EXPLICIT_TEXT_SIZE:
            content = " ".join("".join(node.itertext()).split())
            fail(
                f"Explicit SVG text is below {MIN_EXPLICIT_TEXT_SIZE:g}px in "
                f"{path.relative_to(ROOT)}: {content!r} ({size:g}px)"
            )

# Identity contract: the user explicitly asked that the profile-name size remain unchanged.
hero = parsed[HERO]
name_nodes = [
    node
    for node in hero.iter()
    if local_name(node.tag) == "text"
    and " ".join("".join(node.itertext()).split()) == LOCKED_PROFILE_NAME
]
if len(name_nodes) != 1:
    fail(f"Expected exactly one hero profile-name node for {LOCKED_PROFILE_NAME!r}")
name_size = numeric(name_nodes[0].attrib.get("font-size"), "hero profile-name font-size")
if name_size != LOCKED_PROFILE_NAME_SIZE:
    fail(
        f"Hero profile-name size changed: expected {LOCKED_PROFILE_NAME_SIZE:g}px, "
        f"found {name_size:g}px"
    )

print(
    f"Profile validation passed: {len(REQUIRED_SVGS)} pure-vector SVG assets, "
    f"accessible metadata, >= {MIN_EXPLICIT_TEXT_SIZE:g}px explicit typography, "
    f"locked {LOCKED_PROFILE_NAME_SIZE:g}px profile-name sizing, and no raster README artwork."
)
