import copy
import tempfile
import unittest
from pathlib import Path
from evidence_seal import seal, verify, main


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'capture.bin').write_bytes(b'\x00\xffevidence')
        self.manifest = seal(self.root, 'ENG-001')

    def test_round_trip(self):
        self.assertEqual(verify(self.root, self.manifest)['modified'], [])

    def test_detects_all_change_classes(self):
        (self.root / 'capture.bin').write_bytes(b'changed')
        (self.root / 'new.txt').write_text('new')
        report = verify(self.root, self.manifest)
        self.assertEqual(report['modified'], ['capture.bin'])
        self.assertEqual(report['added'], ['new.txt'])
        (self.root / 'capture.bin').unlink()
        self.assertEqual(verify(self.root, self.manifest)['missing'], ['capture.bin'])

    def test_untrusted_manifest_paths(self):
        for name in ('../secret', '/absolute', 'C:/secret', 'a\\b', './x'):
            with self.subTest(name=name):
                manifest = copy.deepcopy(self.manifest)
                manifest['files'][name] = manifest['files'].pop('capture.bin')
                with self.assertRaises(ValueError):
                    verify(self.root, manifest)

    def test_manifest_cannot_contaminate_evidence(self):
        self.assertEqual(main(['seal', str(self.root), '--case-id', 'X', '--output', str(self.root / 'seal.json')]), 2)

    def test_symlink_rejected(self):
        try:
            (self.root / 'link').symlink_to(self.root / 'capture.bin')
        except OSError:
            self.skipTest('Platform requires symlink privileges')
        with self.assertRaises(ValueError):
            seal(self.root, 'X')


if __name__ == '__main__':
    unittest.main()
