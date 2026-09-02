from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
SVG_DIR = ROOT / "assets"

REQUIRED_SVGS = (
    SVG_DIR / "qe-command-center.svg",
    SVG_DIR / "qe-systems-map.svg",
    SVG_DIR / "repository-signal.svg",
)

RASTER_EXTENSIONS = r"(?:png|jpe?g|gif|webp)"

def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)

def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]

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
    children = list(root)
    if not any(local_name(node.tag) == "title" for node in children):
        fail(f"SVG requires a top-level <title>: {path.relative_to(ROOT)}")
    if not any(local_name(node.tag) == "desc" for node in children):
        fail(f"SVG requires a top-level <desc>: {path.relative_to(ROOT)}")

    text = path.read_text(encoding="utf-8")
    forbidden = ("<script", "<foreignObject", "data:image/", "javascript:")
    for token in forbidden:
        if token.lower() in text.lower():
            fail(f"Forbidden SVG construct {token!r} in {path.relative_to(ROOT)}")

    # Pure-vector contract: no embedded or linked raster/image nodes.
    if any(local_name(node.tag) == "image" for node in root.iter()):
        fail(f"SVG contains an <image> element instead of pure vector primitives: {path.relative_to(ROOT)}")

print(
    f"Profile validation passed: {len(REQUIRED_SVGS)} pure-vector SVG assets, "
    "accessible metadata, and no raster README artwork."
)
