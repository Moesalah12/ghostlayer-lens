import http.client
from threading import Thread
import unittest

from lens.server import make_server


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server, cls.token = make_server()
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.port = cls.server.server_port

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, method="GET", path="/", body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def valid(self):
        return {"Origin": f"http://127.0.0.1:{self.port}", "X-Lens-Token": self.token,
                "Content-Type": "application/octet-stream", "X-Lens-Filename": "note.txt"}

    def test_loopback_binding(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_static_security_headers(self):
        status, headers, body = self.request()
        self.assertEqual(status, 200)
        self.assertIn(b"GhostLayer Lens", body)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("Access-Control-Allow-Origin", headers)
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_no_arbitrary_file_serving(self):
        self.assertEqual(self.request(path="/../lens/engine.py")[0], 404)
        self.assertEqual(self.request(path="/api/scan")[0], 404)

    def test_host_validation(self):
        self.assertEqual(self.request(headers={"Host": "attacker.invalid"})[0], 403)

    def test_origin_validation(self):
        headers = self.valid()
        headers["Origin"] = "https://attacker.invalid"
        self.assertEqual(self.request("POST", "/api/scan", b"a", headers)[0], 403)

    def test_token_required(self):
        headers = self.valid()
        del headers["X-Lens-Token"]
        self.assertEqual(self.request("POST", "/api/scan", b"a", headers)[0], 403)

    def test_oversized_input_rejected_before_read(self):
        headers = self.valid()
        headers["Content-Length"] = str(21*1024*1024)
        self.assertEqual(self.request("POST", "/api/scan", b"", headers)[0], 413)

    def test_content_type_validation(self):
        headers = self.valid()
        headers["Content-Type"] = "text/plain"
        self.assertEqual(self.request("POST", "/api/scan", b"a", headers)[0], 415)

    def test_real_upload_and_escaped_filename(self):
        headers = self.valid()
        headers["X-Lens-Filename"] = "%3Cscript%3E.txt"
        status, _, body = self.request("POST", "/api/scan", b"hello", headers)
        self.assertEqual(status, 200)
        self.assertIn(b"<script>.txt", body)
        self.assertIn(b"no_rule_matches", body)


if __name__ == "__main__":
    unittest.main()
