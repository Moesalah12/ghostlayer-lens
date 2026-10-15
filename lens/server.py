"""Local visual app. Bound to loopback; never deploy as a public server."""
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import secrets
import socket
import tempfile
import time
from urllib.parse import unquote
import webbrowser

from .engine import Limits
from .worker import isolated_scan_file

ASSETS = Path(__file__).parent / "web"


def make_server(port=0, token=None):
    token = token or secrets.token_urlsafe(32)

    class Handler(BaseHTTPRequestHandler):
        server_version = "GhostLayerLens"
        sys_version = ""

        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *args):
            pass

        def output(self, status, body, content_type="application/json"):
            if isinstance(body, dict):
                body = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def valid_host(self):
            return self.headers.get("Host") == f"127.0.0.1:{self.server.server_port}"

        def do_GET(self):
            if not self.valid_host():
                return self.output(403, {"error": "Invalid local host."})
            paths = {"/": ("index.html", "text/html; charset=utf-8"),
                     "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                     "/style.css": ("style.css", "text/css; charset=utf-8")}
            if self.path not in paths:
                return self.output(404, {"error": "Not found."})
            name, content_type = paths[self.path]
            self.output(200, (ASSETS / name).read_bytes(), content_type)

        def do_POST(self):
            origin = f"http://127.0.0.1:{self.server.server_port}"
            if not self.valid_host() or self.headers.get("Origin") != origin:
                return self.output(403, {"error": "Request must originate from the local Lens app."})
            supplied = self.headers.get("X-Lens-Token", "")
            if not hmac.compare_digest(supplied.encode(), token.encode()):
                return self.output(403, {"error": "Session key missing or invalid. Reopen the startup URL."})
            if self.path != "/api/scan":
                return self.output(404, {"error": "Not found."})
            if self.headers.get("Content-Type") != "application/octet-stream" or self.headers.get("Transfer-Encoding"):
                return self.output(415, {"error": "Send one file as application/octet-stream with Content-Length."})
            try:
                length = int(self.headers.get("Content-Length", "-1"))
            except ValueError:
                return self.output(400, {"error": "Invalid content length."})
            if length < 0:
                return self.output(411, {"error": "Content length required."})
            if length > Limits().input_bytes:
                return self.output(413, {"error": "File exceeds the 512 MiB input limit."})
            name = unquote(self.headers.get("X-Lens-Filename", "input"))
            if not name or len(name) > 1000:
                return self.output(400, {"error": "Invalid filename."})
            try:
                with tempfile.TemporaryDirectory(prefix="ghostlayer-lens-") as directory:
                    path = Path(directory) / "input"
                    remaining = length
                    deadline = time.monotonic() + 120
                    with path.open("wb") as target:
                        while remaining:
                            if time.monotonic() > deadline:
                                raise socket.timeout()
                            chunk = self.rfile.read(min(1024 * 1024, remaining))
                            if not chunk:
                                return self.output(400, {"error": "Incomplete upload."})
                            target.write(chunk)
                            remaining -= len(chunk)
                    report = isolated_scan_file(path, name)
                return self.output(200, report)
            except (RuntimeError, ValueError) as exc:
                return self.output(422, {"error": str(exc)})
            except (socket.timeout, ConnectionError):
                return self.output(408, {"error": "Upload did not finish within the connection timeout."})
            except OSError:
                return self.output(507, {"error": "Local temporary storage is unavailable or full."})

    server = HTTPServer(("127.0.0.1", port), Handler)
    return server, token


def serve_app(port=0, open_browser=True):
    server, token = make_server(port)
    url = f"http://127.0.0.1:{server.server_port}/#key={token}"
    print("GhostLayer Lens 0.1 — local-only inspection app")
    print(url, flush=True)
    print("Keep this startup URL private. Ctrl+C stops the app. Uploads use temporary local storage, removed after inspection. Reports are saved only when exported.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
