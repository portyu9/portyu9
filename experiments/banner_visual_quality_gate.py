#!/usr/bin/env python3
"""Read-only browser evidence for SVG banner review; not artistic approval or required CI."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
from io import BytesIO
import json
from pathlib import Path
import re
import sys
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SVG_NS = '{http://www.w3.org/2000/svg}'
SURFACES = ('top', 'top-compact', 'bottom')
REVIEW_NAME = re.compile(r'^(0[5-8]-[a-z-]+)-(top|top-compact|bottom)\.svg$')


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def git_blob(data: bytes) -> str:
    """Compare Git object identity, not a cryptographic security attestation."""
    return hashlib.sha1(f'blob {len(data)}\0'.encode() + data, usedforsecurity=False).hexdigest()


def sources(args: argparse.Namespace) -> dict[str, dict[str, Path]]:
    if args.mode == 'approved':
        catalog = json.loads((ROOT / 'scripts/approved-banner-rotation-v7.json').read_text())
        require(catalog['version'] == 'approved-profile-banners-v7', 'unexpected catalog')
        chosen = {}
        for slot in catalog['slots']:
            if slot['state'] != 'approved':
                continue
            require(set(slot['assets']) == set(SURFACES), 'missing approved surface')
            paths = {}
            for surface, relative in slot['assets'].items():
                untrusted = ROOT / relative
                require(not untrusted.is_symlink(), 'symlinked approved art')
                path = untrusted.resolve(strict=True)
                require(path.is_relative_to(ROOT) and path.is_file(), 'approved path escaped root')
                require(git_blob(path.read_bytes()) == slot['blobs'][surface],
                        f'unexpected approved-art blob: {relative}')
                paths[surface] = path
            chosen[slot['slug']] = paths
        require(len(chosen) == 4, 'expected four approved families')
        return chosen

    root = args.review_dir.resolve(strict=True)
    require(root.is_dir(), 'review directory does not exist')
    chosen: dict[str, dict[str, Path]] = {}
    for entry in sorted(root.iterdir()):
        match = REVIEW_NAME.fullmatch(entry.name)
        if match:
            require(entry.is_file() and not entry.is_symlink(), f'unsafe review asset: {entry}')
            family, surface = match.groups()
            chosen.setdefault(family, {})[surface] = entry
    require(chosen and all(set(v) == set(SURFACES) for v in chosen.values()),
            'review requires complete top/compact/bottom triplets')
    return chosen


def inspect_svg(path: Path) -> tuple[str, int, int]:
    svg = path.read_text(encoding='utf-8')
    root = ET.fromstring(svg)
    require(root.tag == SVG_NS + 'svg' and root.get('role') == 'img',
            f'invalid SVG role/namespace: {path}')
    require(root.find(SVG_NS + 'title') is not None and root.find(SVG_NS + 'desc') is not None,
            f'missing accessible metadata: {path}')
    require('prefers-reduced-motion' in svg, f'no reduced-motion rule: {path}')
    require(re.search(r'<(?:script|foreignObject|image)\b', svg, re.IGNORECASE) is None,
            f'active SVG element present: {path}')
    without_namespace = re.sub(
        r'\s+xmlns(?::[\w-]+)?=["\']https?://www\.w3\.org/[^"\']+["\']', '', svg)
    require(re.search(r'https?://|javascript:|data:', without_namespace, re.IGNORECASE) is None,
            f'external or active URI detected: {path}')
    width, height = root.get('width'), root.get('height')
    require(bool(width and height and width.isdigit() and height.isdigit()),
            f'noninteger canvas: {path}')
    w, h = int(width), int(height)
    require(200 <= w <= 2000 and 100 <= h <= 600, f'invalid dimensions: {path}')
    require(root.get('viewBox') == f'0 0 {w} {h}', f'viewBox mismatch: {path}')
    return svg, w, h


def changed_pixels(before: bytes, after: bytes) -> float:
    from PIL import Image, ImageChops
    first = Image.open(BytesIO(before)).convert('RGB')
    second = Image.open(BytesIO(after)).convert('RGB')
    require(first.size == second.size, 'frame dimensions changed')
    delta = ImageChops.difference(first, second).convert('L')
    return sum(delta.histogram()[11:]) / (first.width * first.height)


async def render(browser, family: str, surface: str, path: Path, out: Path,
                 interval_ms: int, is_chromium: bool) -> dict[str, object]:
    svg, width, height = inspect_svg(path)
    name = f'{family}-{surface}'
    evidence: dict[str, object] = {
        'name': name, 'source_sha256': hashlib.sha256(svg.encode()).hexdigest(),
        'width': width, 'height': height
    }
    for reduced in (False, True):
        fetched: list[str] = []
        context = await browser.new_context(
            viewport={'width': width, 'height': max(height, 200)},
            color_scheme='dark', reduced_motion='reduce' if reduced else 'no-preference',
            device_scale_factor=1,
            is_mobile=is_chromium and surface == 'top-compact'
        )
        try:
            page = await context.new_page()
            page.on('request', lambda request: fetched.append(request.url))
            await page.set_content(svg, wait_until='load')
            locator = page.locator('svg')
            require(await locator.count() == 1, f'multiple SVG roots: {name}')
            await page.wait_for_timeout(250)
            first = await locator.screenshot(animations='allow')
            await page.wait_for_timeout(interval_ms)
            last = await locator.screenshot(animations='allow')
            require(not fetched, f'network request by SVG {name}: {fetched}')
            change = changed_pixels(first, last)
            field = 'reduced_motion' if reduced else 'normal_motion'
            evidence[field] = round(change, 7)
            if reduced:
                require(change == 0, f'reduced motion still animates: {name}: {change:.3%}')
            else:
                require(change >= .001, f'normal animation not observed: {name}: {change:.3%}')
            (out / f'{name}-{field}.png').write_bytes(last)
        finally:
            await context.close()
    return evidence


def build_contact_sheets(collection: dict[str, dict[str, Path]], out: Path) -> None:
    from PIL import Image, ImageDraw
    padding, gap, label_h, target_width = 22, 18, 30, 640
    for family in collection:
        rows = []
        for surface in SURFACES:
            with Image.open(out / f'{family}-{surface}-normal_motion.png') as raw:
                image = raw.convert('RGB')
                factor = min(1, target_width / image.width)
                rows.append((surface, image.resize((
                    round(image.width * factor), round(image.height * factor)))))
        sheet = Image.new('RGB', (target_width + 2 * padding,
                                 padding + sum(im.height + label_h + gap for _, im in rows)),
                          '#080c1a')
        draw = ImageDraw.Draw(sheet)
        y = padding
        for surface, frame in rows:
            draw.text((padding, y), f'{family} / {surface}', fill='#e0eeff')
            y += label_h
            sheet.paste(frame, (padding, y))
            y += frame.height + gap
        sheet.save(out / f'{family}-contact-sheet.png')


async def run(args: argparse.Namespace) -> None:
    from playwright.async_api import async_playwright
    collection = sources(args)
    output = args.out.resolve()
    require(not output.is_relative_to(ROOT), 'output directory must be outside repository')
    output.mkdir(parents=True, exist_ok=True)
    rows = []
    async with async_playwright() as playwright:
        engine = getattr(playwright, args.browser)
        kwargs: dict[str, object] = {'headless': True}
        if args.executable:
            kwargs['executable_path'] = args.executable
        browser = await engine.launch(**kwargs)
        try:
            for family, triplet in collection.items():
                for surface in SURFACES:
                    evidence = await render(browser, family, surface, triplet[surface],
                                            output, args.interval_ms, args.browser == 'chromium')
                    evidence['browser'] = args.browser
                    rows.append(evidence)
                    print(f'PASS {evidence["name"]}: normal={evidence["normal_motion"]:.2%}; '
                          'reduced=static', flush=True)
        finally:
            await browser.close()
    build_contact_sheets(collection, output)
    report = {
        'source_scope': args.mode, 'browser': args.browser, 'surface_count': len(rows),
        'human_visual_approval': False, 'github_or_real_device_certification': False,
        'measurements': rows
    }
    (output / 'render-report.json').write_text(
        json.dumps(report, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(f'PASS {len(rows)} surfaces; contact sheets and evidence at {output}')
    print('Objective motion checks are not aesthetic approval, GPU profiling or protected CI.')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('approved', 'review'), default='approved')
    parser.add_argument('--review-dir', type=Path,
                        default=ROOT / 'experiments/banner-v4/assets')
    parser.add_argument('--browser', choices=('chromium', 'firefox', 'webkit'),
                        default='chromium')
    parser.add_argument('--executable', help='installed local browser executable path')
    parser.add_argument('--interval-ms', type=int, default=1100)
    parser.add_argument('--out', type=Path, default=Path('/tmp/portyu9-banner-review'))
    args = parser.parse_args()
    if not 300 <= args.interval_ms <= 4000:
        parser.error('interval-ms must be between 300 and 4000')
    try:
        asyncio.run(run(args))
    except Exception as exc:
        print(f'FAIL visual quality gate: {exc}', file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == '__main__':
    main()
