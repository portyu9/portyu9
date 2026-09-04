#!/usr/bin/env python3
"""Balance the final ISSUES AUTHORED label without weakening its semantics."""
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
LABEL = re.compile(r'(?P<tag><text\b[^>]*>)ISSUES AUTHORED</text>', re.I)


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


def layout_for(path: Path) -> str:
    if "-wide-" in path.name:
        return "wide"
    if "-compact-" in path.name:
        return "compact"
    raise ValueError(f"unsupported Signal Field layout: {path.name}")


def transform(text: str, path: Path) -> str:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing")
    attrs = attrs_of(root.group(0))
    if attrs.get("data-evidence-presentation") != "signal-field-v2.15":
        raise ValueError("Signal Field v2.15 must precede issue-label balancing")

    labels = list(LABEL.finditer(text))
    if len(labels) != 1:
        raise ValueError("expected exactly one ISSUES AUTHORED label")
    match = labels[0]
    size = "10" if layout_for(path) == "wide" else "7.8"
    tag = set_attr(match.group("tag"), "font-size", size)
    text = text[:match.start()] + tag + "ISSUES AUTHORED</text>" + text[match.end():]

    root = SVG_OPEN.search(text)
    assert root is not None
    root_tag = set_attr(root.group(0), "data-issues-label-balance", VERSION)
    text = text[:root.start()] + root_tag + text[root.end():]
    validate(text, path)
    return text


def validate(text: str, path: Path) -> None:
    root = SVG_OPEN.search(text)
    if not root:
        raise ValueError("SVG root missing after issue-label balance")
    if attrs_of(root.group(0)).get("data-issues-label-balance") != VERSION:
        raise ValueError("issue-label balance provenance missing")
    labels = list(LABEL.finditer(text))
    if len(labels) != 1:
        raise ValueError("ISSUES AUTHORED label missing or duplicated")
    expected = "10" if layout_for(path) == "wide" else "7.8"
    if attrs_of(labels[0].group("tag")).get("font-size") != expected:
        raise ValueError("ISSUES AUTHORED label size changed")


def apply(directory: Path) -> None:
    for filename in EXPECTED_FILES:
        path = directory / filename
        if not path.is_file() or path.stat().st_size == 0:
            raise ValueError(f"missing generated Signal Field artifact: {filename}")
        text = path.read_text(encoding="utf-8")
        transformed = transform(text, path)
        path.write_text(transformed, encoding="utf-8")
        print(f"balanced {filename}: ISSUES AUTHORED label")


def self_test() -> None:
    for layout in ("wide", "compact"):
        for theme in ("light", "dark"):
            path = Path(f"signal-field-{layout}-{theme}.svg")
            text = '<svg data-evidence-presentation="signal-field-v2.15"><text font-size="12">ISSUES AUTHORED</text></svg>'
            transformed = transform(text, path)
            validate(transformed, path)
            if transform(transformed, path) != transformed:
                raise AssertionError("issue-label balancing must be idempotent")
    print("Signal Field ISSUES AUTHORED label balance self-test passed")


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
