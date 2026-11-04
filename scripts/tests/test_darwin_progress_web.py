import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from darwin_progress_web import render, safe_url, validate


def fixture():
    rows = [dict(id="scope:a", catalog_id="scope", name='<script>alert("x")</script>', family="Mach & VM", kind="scoped", implementation="partial", verified_scope=True, dispatch_registered=None, requirement="potential", scope="Only <bounded> behavior", verification_levels=["owned"], source_links=[{"label": "source", "url": "https://example.org/source?q=a&b=c"}, {"label": "unsafe", "url": "javascript:alert(1)"}], tests=[{"label": "owned test", "url": "https://example.org/test"}]), dict(id="scope:b", catalog_id="scope", name="vm_allocate", family="Mach & VM", kind="scoped", implementation="unreviewed", verified_scope=False, dispatch_registered=True, requirement="unknown", verification_levels=[])]
    return dict(schema_version=1, catalogs=[dict(id="scope", title="Reviewed & scoped", revision="abc", denominator=2, completeness="bounded enumeration", sources=[])], contracts=rows, families=[dict(catalog_id="scope", family="Mach & VM", denominator=2, implemented=0, partial=1, missing=0, unreviewed=1, verified_scopes=1, dispatch_registered=1, observed=0, potential=1, unknown=1)], comparison={"percentages_comparable": False}, measurement_limits=["Unknown target denominator"])


class WebTests(unittest.TestCase):
    def test_files_data_escaping_and_independent_badges(self):
        data = fixture()
        with tempfile.TemporaryDirectory() as directory:
            files = render(data, directory)
            self.assertEqual(len(files), 5)
            self.assertEqual(json.loads((Path(directory)/"progress.json").read_text(encoding="utf-8")), data)
            page = (Path(directory)/"index.html").read_text(encoding="utf-8")
            self.assertNotIn('<script>alert', page)
            self.assertIn('&lt;script&gt;', page)
            self.assertNotIn('href="javascript:', page)
            self.assertIn('https://example.org/test', page)
            self.assertIn('percentages_comparable', page)
            for name in files:
                if name.endswith('.svg'):
                    ET.fromstring((Path(directory)/name).read_text(encoding="utf-8"))
            implemented = (Path(directory)/"badge-scope-implemented.svg").read_text(encoding="utf-8")
            verified = (Path(directory)/"badge-scope-verified-scopes.svg").read_text(encoding="utf-8")
            self.assertIn('0/2 (0.0%)', implemented)
            self.assertIn('1/2 (50.0%)', verified)

    def test_bad_counts_do_not_create_output(self):
        for mutate in [lambda d: d['catalogs'][0].update(denominator=3), lambda d: d['families'][0].update(implemented=1), lambda d: d['contracts'].append(copy.deepcopy(d['contracts'][0])), lambda d: d['families'][0].update(verified_scopes=True)]:
            with self.subTest(mutation=mutate), tempfile.TemporaryDirectory() as directory:
                data = fixture()
                mutate(data)
                output = Path(directory)/'site'
                with self.assertRaises(ValueError):
                    render(data, output)
                self.assertFalse(output.exists())

    def test_safe_urls(self):
        for url in ['file:///C:/private', 'http://example.org', '//example.org', 'https://user:secret@example.org', 'https://example.org/\nfoo', 'https://example.org\\evil', 'https://example.org:bad']:
            self.assertIsNone(safe_url(url))
        self.assertEqual(safe_url('https://github.com/org/repo/blob/hash/file.py'), 'https://github.com/org/repo/blob/hash/file.py')

    def test_empty_catalog_no_division_by_zero(self):
        data = fixture()
        data['catalogs'][0]['denominator'] = 0
        data['contracts'] = []
        data['families'] = []
        validate(data)
        with tempfile.TemporaryDirectory() as directory:
            render(data, directory)
            self.assertIn('n/a', (Path(directory)/'badge-scope-implemented.svg').read_text(encoding='utf-8'))


if __name__ == '__main__':
    unittest.main()
