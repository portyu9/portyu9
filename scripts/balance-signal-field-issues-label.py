#!/usr/bin/env python3
"""Keep the final BUG FOUND label at the same text scale as its peer metric labels."""
from __future__ import annotations

from pathlib import Path
import re
import sys

VERSION = "signal-field-v2.16"
EXPECTED_FILES = tuple(
    f"signal-field-{layout}-{theme}.svg"
    for layout in ("wide", "compact")
    for theme in ("light", "dark")
)
SVG_OPEN = re.compile(r"<svg\b([^>]*)>", re.I)
ATTR = re.compile(r'([\w:-]+)="([^"]*)"')
BUG_LABEL = re.compile(r'(?P<tag><text\b[^>]*>)BUG FOUND</text>', re.I)


def attrs_of(tag: str) -> dict[str, str]:
    return dict(ATTR.findall(tag))


def set_attr(tag: str, name: str, value: str) -> str:
    pattern = re.compile(rf'\b{re.escape(name)}="[^"]*"')
    replacement = f'{name}="{value}"'
    if pattern.search(tag):
        return pattern.sub(replacement, tag, count=1)
    close = tag.rfind(">")
    if close < 0:
        raise ValueError(f"cannot set {name!r} on malformed element")
    return tag[:close] + f' {replacement}' + tag[close:]


def label_attrs(text: str, label: str) -> dict[str, str]:
    pattern = re.compile(rf'(?P<tag><text\b[^>]*>){re.escape(label)}</text>', re.I)
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {label} label")
    return attrs_of(matches[0].group("tag"))


def peer_label_size(text: str) -> str:
    star_size = label_attrs(text, "STARS").get("font-size")
    pull_size = label_attrs(text, "PULL REQUESTS").get("font-size")
    if not star_size or not pull_size:
        raise ValueError("peer metric label font-size is missing")
    if star_size != pull_size:
        raise ValueError("STARS and PULL REQUESTS label sizes diverged")
    return star_size


def transform(text: str, path: Path) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing")
    attrs = attrs_of(root.group(0))
    if attrs.get("data-evidence-presentation") != "signal-field-v2.15":
        raise ValueError("Signal Field v2.15 must precede BUG FOUND label balancing")

    labels = list(BUG_LABEL.finditer(text))
    if len(labels) != 1:
        raise ValueError("expected exactly one BUG FOUND label")
    if ">BUGS FOUND</text>" in text or ">ISSUES AUTHORED</text>" in text:
        raise ValueError("stale Issues label reached BUG FOUND balancing")

    match = labels[0]
    tag = set_attr(match.group("tag"), "font-size", peer_label_size(text))
    text = text[:match.start()] + tag + "BUG FOUND</text>" + text[match.end():]

    root = SVG_OPEN.search(text)
    assert root is not None
    root_tag = set_attr(root.group(0), "data-issues-label-balance", VERSION)
    root_tag = set_attr(root_tag, "data-issues-label-scale", "peer-metric-label")
    text = text[:root.start()] + root_tag + text[root.end():]
    validate(text, path)
    return text


def validate(text: str, path: Path) -> None:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing after BUG FOUND label balance")
    root_attrs = attrs_of(root.group(0))
    if root_attrs.get("data-issues-label-balance") != VERSION:
        raise ValueError("BUG FOUND label-balance provenance missing")
    if root_attrs.get("data-issues-label-scale") != "peer-metric-label":
        raise ValueError("BUG FOUND peer-label scale provenance missing")

    labels = list(BUG_LABEL.finditer(text))
    if len(labels) != 1:
        raise ValueError("BUG FOUND label missing or duplicated")
    expected = peer_label_size(text)
    actual = attrs_of(labels[0].group("tag")).get("font-size")
    if actual != expected:
        raise ValueError(f"BUG FOUND label size {actual!r} does not match peer metric label size {expected!r}")
    if ">BUGS FOUND</text>" in text or ">ISSUES AUTHORED</text>" in text:
        raise ValueError("stale Issues label returned")


def apply(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        text = path.read_text(encoding="utf-8")
        transformed = transform(text, path)
        path.write_text(transformed, encoding="utf-8")
        print(f"balanced {filename}: BUG FOUND matches STARS / PULL REQUESTS label scale")


def self_test() -> None:
    for layout in ("wide", "compact"):
        for theme in ("light", "dark"):
            path = Path(f"signal-field-{layout}-{theme}.svg")
            peer_size = "12" if layout == "wide" else "9"
            text = (
                '<svg data-evidence-presentation="signal-field-v2.15">'
                f'<text font-size="{peer_size}">STARS</text>'
                f'<text font-size="{peer_size}">PULL REQUESTS</text>'
                '<text font-size="7">BUG FOUND</text></svg>'
            )
            transformed = transform(text, path)
            validate(transformed, path)
            if attrs_of(BUG_LABEL.search(transformed).group("tag")).get("font-size") != peer_size:  # type: ignore[union-attr]
                raise AssertionError("BUG FOUND label did not inherit peer metric label scale")
            if transform(transformed, path) != transformed:
                raise AssertionError("BUG FOUND label balancing must be idempotent")
    print("Signal Field BUG FOUND peer-label scale self-test passed")


def main() -> int:
    try:
        if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
            self_test(); return 0
        if len(sys.argv) != 2:
            raise ValueError("usage: balance-signal-field-issues-label.py <generated-directory> | --self-test")
        apply(Path(sys.argv[1])); return 0
    except (OSError, ValueError, AssertionError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
