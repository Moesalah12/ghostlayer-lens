import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from lens.engine import Limits, scan_file
from lens.worker import isolated_scan_file


class LargeFileTests(unittest.TestCase):
    def test_large_zip_retains_small_script_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'large.zip'
            with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_STORED) as archive:
                with archive.open('large.dat', 'w') as member:
                    for _ in range(25):
                        member.write(b'\0' * 1024 * 1024)
                archive.writestr('review.ps1', 'Invoke-WebRequest https://example.invalid')
            report = isolated_scan_file(path, path.name)
            self.assertGreater(path.stat().st_size, 20 * 1024 * 1024)
            self.assertEqual(report['coverage'], 'incomplete')
            self.assertIn('remote_retrieval', {f['rule'] for f in report['findings']})
            self.assertIn('member_size_limit', {f['rule'] for f in report['findings']})
            with path.open('rb') as stream:
                self.assertEqual(report['nodes'][0]['sha256'], hashlib.file_digest(stream, 'sha256').hexdigest())

    def test_large_text_does_not_claim_full_inspection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'large.txt'
            with path.open('wb') as stream:
                stream.truncate(21 * 1024 * 1024)
            report = isolated_scan_file(path, path.name)
            self.assertEqual(report['nodes'][0]['reason'], 'content_size_limit')
            self.assertEqual(report['coverage'], 'incomplete')

    def test_file_limit_enforced_while_reading(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'note.txt'
            path.write_bytes(b'hello')
            with self.assertRaises(ValueError):
                scan_file(path, path.name, Limits(input_bytes=4))
