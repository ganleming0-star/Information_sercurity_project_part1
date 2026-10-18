"""Exercise the original socket server, file router, teacher scripts and CLIs."""

import contextlib
import errno
import http.client
import importlib
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest

import client
from client_subverted import build_backdoor_authorization
from py_http_server import log
from py_http_server.middlewares import DefaultMiddleware
from py_http_server.networking import TCPAddress
from py_http_server.networking.listener import ListenerThread
from py_http_server.routers import FileRouter
from test_auth import sha


PROJECT = Path(__file__).resolve().parents[1]
CONTENT = b"A real protected HTTP page.\n"


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "notes one.txt").write_bytes(CONTENT)
        (self.root / "中文.txt").write_bytes(CONTENT)
        (self.root / "index.html").write_bytes(CONTENT)
        self.username = "student-é"
        self.password = "mushroom-蘑菇"
        self.pwdfile = self.root / "passwords.txt"
        self.pwdfile.write_text(self.username + ":" + sha(self.password) + "\n", encoding="utf-8")

    @contextlib.contextmanager
    def server(self, kind):
        module = importlib.import_module("py_http_server.middlewares." + kind)
        cls = module.DigestAuthSubvertedMiddleware if kind.endswith("subverted") else module.DigestAuthMiddleware
        app = DefaultMiddleware(cls(next=FileRouter(str(self.root)), pwdfile=str(self.pwdfile)))
        sock = socket.create_server(("127.0.0.1", 0))
        sock.listen()
        port = sock.getsockname()[1]
        listener = ListenerThread(sock, TCPAddress("127.0.0.1", port), app)
        # The assertions exercise status and body; ordinary server logs stay quiet.
        log.setLevel("CRITICAL")
        listener.start()
        try:
            yield f"http://127.0.0.1:{port}"
        finally:
            listener.dispose()
            listener.join(timeout=3)
            self.assertFalse(listener.is_alive())

    def exchange(self, base, target="/", method="GET", header=None):
        parsed = client.urlsplit(base)
        conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=3)
        try:
            headers = {"Connection": "close"}
            if header is not None:
                headers["Authorization"] = header
            conn.request(method, target, headers=headers)
            response = conn.getresponse()
            return response.status, response.read(), response.getheader("WWW-Authenticate", "")
        finally:
            conn.close()

    def test_real_http_normal_backdoor_and_unknown_user_matrix(self):
        for kind in ("digest_auth", "digest_auth_subverted"):
            with self.subTest(kind=kind), self.server(kind) as base:
                for password, builder, expected in (
                    (self.password, client.build_authorization, 200),
                    ("wrong", client.build_authorization, 401),
                    ("unknown", build_backdoor_authorization, 200 if kind.endswith("subverted") else 401),
                ):
                    with self.subTest(password=password, builder=builder.__name__):
                        page = client.fetch(base + "/notes%20one.txt?q=%E4%B8%AD", self.username, password,
                                            authorization_builder=builder)
                        self.assertEqual(page.status, expected)
                        if expected == 200:
                            self.assertEqual(page.body, CONTENT)
                page = client.fetch(base + "/", "unknown-user", "wrong", authorization_builder=build_backdoor_authorization)
                self.assertEqual(page.status, 401)

    def test_file_router_preserves_head_404_and_405(self):
        for kind in ("digest_auth", "digest_auth_subverted"):
            with self.subTest(kind=kind), self.server(kind) as base:
                for method, target, expected in (
                    ("HEAD", "/notes%20one.txt", 200),
                    ("GET", "/missing", 404),
                    ("POST", "/index.html", 405),
                ):
                    status, unused, challenge = self.exchange(base, target, method)
                    self.assertEqual(status, 401)
                    header = client.build_authorization(challenge, self.username, self.password, method, target)
                    status, body, unused = self.exchange(base, target, method, header)
                    self.assertEqual(status, expected)
                    if method == "HEAD":
                        self.assertEqual(body, b"")

    def test_utf8_url_is_quoted_before_sending_and_authenticating(self):
        with self.server("digest_auth") as base:
            page = client.fetch(base + "/中文.txt?q=中文", self.username, self.password)
            self.assertEqual(page.status, 200)
            self.assertEqual(page.body, CONTENT)

    def test_cli_normal_default_subverted_and_explicit_backdoor(self):
        for kind in ("digest_auth", "digest_auth_subverted"):
            with self.server(kind) as base:
                cases = (
                    ("client.py", (), self.password, 200),
                    ("client.py", (), "wrong", 401),
                    ("client_subverted.py", (), self.password, 200),
                    ("client_subverted.py", (), "wrong", 401),
                    ("client_subverted.py", ("--backdoor",), "wrong", 200 if kind.endswith("subverted") else 401),
                )
                for filename, options, password, expected in cases:
                    with self.subTest(kind=kind, client=filename, options=options, expected=expected):
                        result = subprocess.run(
                            [sys.executable, "-W", "error", str(PROJECT / filename), base + "/index.html", *options],
                            input=self.username + "\n" + password + "\n", text=True,
                            capture_output=True, timeout=5,
                        )
                        self.assertEqual(result.returncode, 0 if expected == 200 else 1, result.stderr)
                        self.assertIn(f"HTTP {expected}", result.stdout)
                        self.assertEqual(result.stderr, "")
                        if expected == 200:
                            self.assertIn(CONTENT.decode().strip(), result.stdout)

    def test_connection_refused_is_reported_without_traceback(self):
        with socket.create_server(("127.0.0.1", 0)) as sock:
            port = sock.getsockname()[1]
        result = subprocess.run(
            [sys.executable, str(PROJECT / "client.py"), f"http://127.0.0.1:{port}/"],
            input="alice\npw\n", capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("Error:", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_original_teacher_startup_scripts_on_both_loopback_families(self):
        # The supplied scripts hard-code port 8080; never disturb another server.
        for host in ("127.0.0.1", "::1"):
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            try:
                with socket.create_server((host, 8080), family=family):
                    pass
            except OSError as error:
                if error.errno in {errno.EADDRINUSE, errno.EADDRNOTAVAIL, errno.EAFNOSUPPORT}:
                    self.skipTest(f"Teacher script listener unavailable on {host}: {error}")
                raise
        for filename in ("start_server_digest.py", "start_server_subverted.py"):
            with self.subTest(script=filename):
                output_path = self.root / (filename + ".log")
                with output_path.open("w+") as output:
                    process = subprocess.Popen([sys.executable, "-W", "error", str(PROJECT / filename)],
                                               cwd=self.root, stdout=output, stderr=subprocess.STDOUT)
                    try:
                        deadline = time.monotonic() + 5
                        while True:
                            self.assertIsNone(process.poll(), output_path.read_text())
                            try:
                                status, body, challenge = self.exchange("http://127.0.0.1:8080", "/index.html")
                                break
                            except (OSError, http.client.HTTPException):
                                if time.monotonic() >= deadline:
                                    self.fail("Teacher server failed to start: " + output_path.read_text())
                                time.sleep(0.02)
                        self.assertEqual(status, 401)
                        for base in ("http://127.0.0.1:8080", "http://[::1]:8080"):
                            page = client.fetch(base + "/index.html", self.username, self.password)
                            self.assertEqual(page.status, 200)
                            self.assertEqual(page.body, CONTENT)
                        result = subprocess.run([sys.executable, str(PROJECT / "client.py")],
                                                input=self.username + "\n" + self.password + "\n",
                                                capture_output=True, text=True, timeout=5)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertIn("HTTP 200", result.stdout)
                        self.assertEqual(result.stderr, "")
                    finally:
                        process.send_signal(signal.SIGINT)
                        try:
                            process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            process.wait(timeout=3)
                text = output_path.read_text()
                for bad in ("Traceback", "WARNING", "ERROR", "ResourceWarning"):
                    self.assertNotIn(bad, text)

    def test_subverted_middleware_runs_without_secure_file_or_clients(self):
        isolated = self.root / "isolated"
        package = isolated / "py_http_server"
        shutil.copytree(PROJECT / "py_http_server", package,
                        ignore=shutil.ignore_patterns("digest_auth.py", "__pycache__"))
        init = package / "middlewares" / "__init__.py"
        # A grading harness imports only the supplied version in its own copy.
        init.write_text(init.read_text().replace("from .digest_auth import *\n", ""))
        code = """
import sys
sys.path[:0] = sys.argv[1:3]
from py_http_server.middlewares import DigestAuthSubvertedMiddleware
from py_http_server.http.response import HTTPResponse
from test_auth import request, challenge_values, credentials, authorization
app = DigestAuthSubvertedMiddleware(next=lambda info, req: HTTPResponse(200), pwdfile=sys.argv[3])
challenge = challenge_values(app(None, request()))
for legacy in (False, True):
    challenge = challenge_values(app(None, request()))
    fields = credentials(challenge, 'student-é', 'mushroom-蘑菇' if not legacy else 'unknown', legacy=legacy)
    assert app(None, request(authorization(fields))).status_code == 200
print('isolated middleware normal and backdoor passed')
"""
        result = subprocess.run([sys.executable, "-I", "-W", "error", "-c", code,
                                 str(isolated), str(PROJECT / "tests"), str(self.pwdfile)],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("isolated middleware", result.stdout)
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
