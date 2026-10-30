"""Offline SVG visual-gate contract tests; browser integration is optional."""
from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import types
import unittest

ENTRY = Path(__file__).with_name('banner_visual_quality_gate.py')
SPEC = importlib.util.spec_from_file_location('banner_visual_quality_gate', ENTRY)
GATE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(GATE)


def sample(*, reduced=True, external='', viewbox='0 0 640 196', role='img'):
    style = '<style>@media(prefers-reduced-motion:reduce){.beam{animation:none}}</style>' if reduced else ''
    return (f'<svg xmlns="http://www.w3.org/2000/svg" role="{role}" width="640" height="196" '
            f'viewBox="{viewbox}"><title>Fixture</title><desc>Local animation</desc>{style}'
            f'<rect width="640" height="196" fill="#010614"/>{external}</svg>')


class BannerGateContractTests(unittest.TestCase):
    def inspect(self, payload: str):
        with tempfile.TemporaryDirectory() as folder:
            filename = Path(folder) / 'scene.svg'
            filename.write_text(payload)
            return GATE.inspect_svg(filename)

    def test_known_git_empty_blob_identity(self):
        self.assertEqual(GATE.git_blob(b''), 'e69de29bb2d1d6434b8b29ae775ad8c2e48c5391')

    def test_acceptable_accessible_static_fallback(self):
        markup, width, height = self.inspect(sample())
        self.assertEqual((width, height), (640, 196))
        self.assertIn('prefers-reduced-motion', markup)

    def test_rejects_missing_motion_fallback(self):
        with self.assertRaisesRegex(ValueError, 'reduced-motion'):
            self.inspect(sample(reduced=False))

    def test_rejects_bad_viewbox(self):
        with self.assertRaisesRegex(ValueError, 'viewBox'):
            self.inspect(sample(viewbox='0 0 640 180'))

    def test_rejects_missing_role(self):
        with self.assertRaisesRegex(ValueError, 'invalid'):
            self.inspect(sample(role='presentation'))

    def test_rejects_image_element(self):
        with self.assertRaisesRegex(ValueError, 'active'):
            self.inspect(sample(external='<image href="local.png"/>'))

    def test_rejects_external_resource(self):
        with self.assertRaisesRegex(ValueError, 'nonlocal'):
            self.inspect(sample(external='<use href="https://evil.example/x.svg#shape"/>'))

    def test_review_requires_all_three_surfaces(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            (p / '05-aurora-top.svg').write_text(sample())
            with self.assertRaisesRegex(ValueError, 'triplet'):
                GATE.sources(types.SimpleNamespace(mode='review', review_dir=p))

    def test_review_valid_triplets_group_by_identity(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            for name in ('top', 'top-compact', 'bottom'):
                (p / f'05-aurora-{name}.svg').write_text(sample())
            found = GATE.sources(types.SimpleNamespace(mode='review', review_dir=p))
            self.assertEqual(set(found), {'05-aurora'})
            self.assertEqual(set(found['05-aurora']), set(GATE.SURFACES))

    def test_review_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)
            source = p / 'target.svg'
            source.write_text(sample())
            (p / '05-aurora-top.svg').symlink_to(source)
            for name in ('top-compact', 'bottom'):
                (p / f'05-aurora-{name}.svg').write_text(sample())
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                GATE.sources(types.SimpleNamespace(mode='review', review_dir=p))


    def test_local_svg_fragment_remains_allowed(self):
        svg = sample(external='<defs><linearGradient id="local"><stop stop-color="#fff"/>'
                     '</linearGradient></defs><rect fill="url(#local)"/>'
                     '<use href="#local"/>')
        self.inspect(svg)

    def test_rejects_protocol_relative_fragment_reference(self):
        with self.assertRaisesRegex(ValueError, 'nonlocal SVG'):
            self.inspect(sample(external='<use href="//outside.example/payload.svg#shape"/>'))

    def test_rejects_relative_fragment_reference(self):
        with self.assertRaisesRegex(ValueError, 'nonlocal SVG'):
            self.inspect(sample(external='<use href="outside.svg#shape"/>'))

    def test_rejects_external_css_paint(self):
        with self.assertRaisesRegex(ValueError, 'nonlocal CSS'):
            self.inspect(sample(external='<rect fill="url(//outside.example/paint.svg#x)"/>'))

    def test_rejects_css_import(self):
        with self.assertRaisesRegex(ValueError, 'external or active'):
            self.inspect(sample(external='<style>@import "evil.css";</style>'))

    def test_rejects_xml_document_type(self):
        with self.assertRaisesRegex(ValueError, 'DTD'):
            self.inspect('<!DOCTYPE svg [<!ENTITY t "test">]>' + sample())

    def test_rejects_too_large_payload(self):
        with self.assertRaisesRegex(ValueError, 'payload'):
            self.inspect(sample() + ' ' * (512 * 1024))


if __name__ == '__main__':
    unittest.main()
