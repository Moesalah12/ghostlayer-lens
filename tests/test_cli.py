import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent


class CLITests(unittest.TestCase):
    def call(self, *args):
        return subprocess.run([sys.executable, "-m", "lens", *map(str, args)], cwd=ROOT,
                              capture_output=True, text=True, timeout=20)

    def test_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            file, output = Path(directory)/"notes.txt", Path(directory)/"report.json"
            file.write_text("ordinary notes")
            self.assertEqual(self.call("scan", file, "--output", output).returncode, 0)
            before = output.read_bytes()
            self.assertEqual(self.call("scan", file, "--output", output).returncode, 2)
            self.assertEqual(before, output.read_bytes())

    def test_review_and_gap_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory)/"example.txt"
            file.write_text("# Invoke-WebRequest https://example.invalid")
            result = self.call("scan", file)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["assessment"], "review_recommended")
            file.write_bytes(b"\xff\x00\x80")
            result = self.call("scan", file)
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["coverage"], "incomplete")

    def test_missing_and_directory_input(self):
        self.assertEqual(self.call("scan", ROOT).returncode, 2)
        self.assertEqual(self.call("scan", ROOT/"missing-file.txt").returncode, 2)


if __name__ == "__main__":
    unittest.main()
