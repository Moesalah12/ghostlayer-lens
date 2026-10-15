import base64
from dataclasses import replace
import io
import json
import random
import struct
import unittest
import warnings
import zipfile

from lens.engine import Limits, scan_bytes
from lens.worker import isolated_scan


def zipped(entries, compression=zipfile.ZIP_STORED):
    stream = io.BytesIO()
    with warnings.catch_warnings(), zipfile.ZipFile(stream, "w", compression=compression) as archive:
        warnings.simplefilter("ignore", UserWarning)
        for name, content in entries:
            archive.writestr(name, content)
    return stream.getvalue()


def rules(report):
    return {f["rule"] for f in report["findings"]}


class EngineTests(unittest.TestCase):
    def test_benign_text_has_no_safety_claim(self):
        report = scan_bytes(b"ordinary meeting notes", "notes.txt")
        self.assertEqual(report["assessment"], "no_rule_matches")
        self.assertEqual(report["coverage"], "within_supported_scope")
        self.assertIn("No result certifies safety", report["notice"])

    def test_disguised_extension(self):
        self.assertIn("disguised_extension", rules(scan_bytes(b"test", "holiday.JPG.EXE")))
        self.assertNotIn("disguised_extension", rules(scan_bytes(b"test", "photo.jpg")))

    def test_binary_marker_not_a_malware_verdict(self):
        r = scan_bytes(b"MZ fake fixture", "photo.png")
        self.assertEqual(r["coverage"], "incomplete")
        self.assertIn("binary_extension_mismatch", rules(r))
        self.assertEqual(r["nodes"][0]["kind"], "windows_binary")

    def test_pe_signature_bounded(self):
        data = bytearray(72)
        data[:2] = b"MZ"
        struct.pack_into("<I", data, 60, 64)
        data[64:68] = b"PE\x00\x00"
        self.assertTrue(scan_bytes(bytes(data), "x.exe")["nodes"][0]["pe_signature_present"])
        struct.pack_into("<I", data, 60, 0xffffffff)
        self.assertFalse(scan_bytes(bytes(data), "x.exe")["nodes"][0]["pe_signature_present"])

    def test_lexical_signals_include_comment_evidence(self):
        r = scan_bytes(b"# training only\n# Invoke-WebRequest https://example.invalid/a\n", "notes.txt")
        match = next(f for f in r["findings"] if f["rule"] == "remote_retrieval")
        self.assertEqual(match["line"], 2)
        self.assertTrue(match["evidence"].startswith("#"))
        self.assertEqual(r["nodes"][0]["references"][0]["value"], "https://example.invalid/a")

    def test_encoded_powershell_evidence(self):
        encoded = base64.b64encode("Invoke-WebRequest https://example.invalid/test".encode("utf-16-le"))
        r = scan_bytes(b"powershell -EncodedCommand " + encoded, "sample.ps1")
        self.assertIn("decoded_text", rules(r))
        self.assertIn("remote_retrieval_decoded", rules(r))

    def test_invalid_encoded_argument_is_reported(self):
        self.assertIn("decode_failed", rules(scan_bytes(b"powershell -enc AAAA=", "sample.txt")))

    def test_utf16_script(self):
        data = "# Start-Process sample.exe -Verb RunAs".encode("utf-16")
        self.assertIn("elevation_request", rules(scan_bytes(data, "sample.ps1")))

    def test_unknown_binary_is_incomplete(self):
        r = scan_bytes(b"\x00\xff\x80", "unknown.bin")
        self.assertEqual(r["coverage"], "incomplete")
        self.assertEqual(r["assessment"], "no_rule_matches")

    def test_supported_zip_and_empty_zip(self):
        r = scan_bytes(zipped([("hello.txt", "hello")]), "sample.zip")
        self.assertEqual(len(r["nodes"]), 2)
        self.assertEqual(r["coverage"], "within_supported_scope")
        self.assertEqual(scan_bytes(zipped([]), "empty.zip")["coverage"], "within_supported_scope")

    def test_nested_archive_parent_links(self):
        inner = zipped([("note.txt", "hello")])
        r = scan_bytes(zipped([("inner.zip", inner)]), "outer.zip")
        self.assertEqual(r["nodes"][2]["parent_id"], r["nodes"][1]["id"])

    def test_depth_limit_propagates(self):
        data = zipped([("nested.zip", zipped([("a.txt", "a")]))])
        r = scan_bytes(data, "top.zip", replace(Limits(), depth=1))
        self.assertEqual(r["coverage"], "incomplete")
        self.assertEqual(r["nodes"][0]["status"], "partial")
        self.assertIn("depth_limit", rules(r))

    def test_path_traversal_is_evidence_not_extraction(self):
        for path in ("../escape.txt", "C:\\escape.txt", "/tmp/escape.txt", "..\\escape.txt"):
            r = scan_bytes(zipped([(path, "data")]), "sample.zip")
            self.assertIn("unsafe_archive_path", rules(r))

    def test_bidi_escaped_everywhere(self):
        r = scan_bytes(zipped([("photo\u202egpj.exe", "test")]), "sample.zip")
        self.assertIn("bidi_filename", rules(r))
        self.assertIn("\\u202e", r["nodes"][1]["name"])
        self.assertNotIn("\u202e", json.dumps(r, ensure_ascii=False))

    def test_duplicate_entries(self):
        r = scan_bytes(zipped([("a.txt", "one"), ("a.txt", "two")]), "sample.zip")
        self.assertIn("duplicate_entry", rules(r))

    def test_symlink_is_not_followed(self):
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (0o120777 << 16)
        r = scan_bytes(zipped([(info, "../../private")]), "sample.zip")
        self.assertIn("symlink_not_followed", rules(r))

    def test_encrypted_flag_prevents_read(self):
        data = bytearray(zipped([("secret.txt", "content")]))
        local = data.find(b"PK\x03\x04")
        central = data.find(b"PK\x01\x02")
        struct.pack_into("<H", data, local+6, 1)
        struct.pack_into("<H", data, central+8, 1)
        self.assertIn("encrypted_entry", rules(scan_bytes(bytes(data), "encrypted.zip")))

    def test_symlink_with_directory_name_is_still_a_gap(self):
        info = zipfile.ZipInfo("directory-link/")
        info.create_system = 3
        info.external_attr = (0o120777 << 16)
        r = scan_bytes(zipped([(info, "../../private")]), "sample.zip")
        self.assertIn("symlink_not_followed", rules(r))
        self.assertEqual(r["coverage"], "incomplete")

    def test_member_size_limit(self):
        r = scan_bytes(zipped([("big.txt", "a"*100)]), "sample.zip", replace(Limits(), member_bytes=50))
        self.assertIn("member_size_limit", rules(r))

    def test_total_expanded_limit(self):
        r = scan_bytes(zipped([("a.txt", "a"*40), ("b.txt", "b"*40)]), "sample.zip", replace(Limits(), expanded_bytes=50))
        self.assertIn("expanded_size_limit", rules(r))

    def test_ratio_limit(self):
        r = scan_bytes(zipped([("dense.txt", "a"*10000)], zipfile.ZIP_DEFLATED), "sample.zip", replace(Limits(), ratio=10))
        self.assertIn("compression_ratio_limit", rules(r))

    def test_entries_truncated(self):
        r = scan_bytes(zipped([(f"{i}.txt", "a") for i in range(5)]), "sample.zip", replace(Limits(), entries=3))
        self.assertEqual(len(r["nodes"]), 3)
        self.assertIn("archive_truncated", rules(r))

    def test_bad_crc_is_coverage_gap(self):
        data = bytearray(zipped([("a.txt", "UNIQUE_CONTENT")]))
        at = data.find(b"UNIQUE_CONTENT")
        data[at] = ord("X")
        self.assertIn("unreadable_entry", rules(scan_bytes(bytes(data), "sample.zip")))

    def test_unsupported_compression(self):
        data = bytearray(zipped([("a.txt", "a")]))
        central = data.find(b"PK\x01\x02")
        struct.pack_into("<H", data, central+10, 99)
        self.assertIn("unsupported_compression", rules(scan_bytes(bytes(data), "sample.zip")))

    def test_malformed_archives_do_not_claim_complete(self):
        rng = random.Random(42)
        for size in (0, 1, 10, 100, 1000):
            r = scan_bytes(rng.randbytes(size), "sample.zip")
            self.assertEqual(r["coverage"], "incomplete")

    def test_input_and_name_limits(self):
        with self.assertRaises(ValueError):
            scan_bytes(b"a"*11, "a.txt", replace(Limits(), input_bytes=10))
        for name in ("", "a"*1001):
            with self.assertRaises(ValueError):
                scan_bytes(b"a", name)

    def test_rule_and_time_limits(self):
        r = scan_bytes(b"Invoke-WebRequest x\nStart-Process x -Verb RunAs", "a.txt", replace(Limits(), findings=1))
        self.assertEqual(len(r["findings"]), 1)
        self.assertIn("findings", r["limits_hit"])
        r = scan_bytes(b"hello", "a.txt", replace(Limits(), seconds=-1))
        self.assertEqual(r["coverage"], "incomplete")

    def test_worker_returns_real_report(self):
        r = isolated_scan(zipped([("a.txt", "hello")]), "sample.zip")
        self.assertEqual(r["stats"]["nodes"], 2)


if __name__ == "__main__":
    unittest.main()
