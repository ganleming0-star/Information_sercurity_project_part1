"""Client calculations and CLI behavior, including redirected input."""

import contextlib
import importlib
import io
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch


PROJECT = Path(__file__).resolve().parents[1]
CHALLENGE = 'Digest realm="DI31002", algorithm=SHA-256, qop="auth", nonce="0123456789abcdef", charset=UTF-8'


class ClientTests(unittest.TestCase):
    def module(self, name="client"):
        self.assertTrue((PROJECT / (name + ".py")).exists(), "Missing planned client: " + name)
        return importlib.import_module(name)

    def test_normal_response_matches_independent_known_answer(self):
        client = self.module()
        with patch.object(client.secrets, "token_hex", return_value="fixed-client-nonce"):
            header = client.build_authorization(CHALLENGE, "alice", "mushroom", "GET", "/notes.txt?q=1")
        fields = client.parse_digest_fields(header)
        # Literal vector is checked independently with openssl during development.
        self.assertEqual(fields["response"], "550fcc8ededdc655d992b86f6c5632129bf49f3fc45a06b28fb6bc3e47f88236")
        self.assertEqual(fields["cnonce"], "fixed-client-nonce")
        self.assertEqual(fields["nc"], "00000001")
        self.assertEqual(fields["qop"], "auth")

    def test_backdoor_formula_uses_public_fields_and_ignores_password(self):
        client = self.module()
        subverted = self.module("client_subverted")
        first = subverted.build_backdoor_authorization(CHALLENGE, "alice", "anything", "GET", "/notes.txt?q=1")
        second = subverted.build_backdoor_authorization(CHALLENGE, "alice", "different", "GET", "/notes.txt?q=1")
        self.assertEqual(first, second)
        fields = client.parse_digest_fields(first)
        self.assertEqual(fields["response"], "6a62dc23ae28f665b47be5c01d05354bacf3a3c2df9c558e0acf9a468e14fa37")
        self.assertFalse({"qop", "nc", "cnonce"} & fields.keys())

    def test_utf8_username_uses_extended_header_without_raw_unicode(self):
        client = self.module()
        header = client.build_authorization(CHALLENGE, "学生-é", "蘑菇", "GET", "/")
        header.encode("ascii")
        fields = client.parse_digest_fields(header)
        self.assertEqual(fields["username*"], "UTF-8''%E5%AD%A6%E7%94%9F-%C3%A9")
        self.assertNotIn("username", fields)

    def test_ascii_username_with_quotes_backslashes_and_spaces_roundtrips(self):
        client = self.module()
        username = ' user,="quoted"\\name '
        fields = client.parse_digest_fields(client.build_authorization(CHALLENGE, username, "pw", "GET", "/"))
        self.assertEqual(fields["username"], username)

    def test_missing_or_unsupported_challenge_is_a_controlled_error(self):
        client = self.module()
        bad = ("", "Basic realm=auth", 'Digest realm="DI31002"',
               CHALLENGE.replace("SHA-256", "MD5"), CHALLENGE.replace('qop="auth"', 'qop="auth-int"'),
               CHALLENGE + ', nonce="duplicate"')
        for challenge in bad:
            with self.subTest(challenge=challenge), self.assertRaises(ValueError):
                client.build_authorization(challenge, "alice", "mushroom", "GET", "/")

    def test_challenge_parser_rejects_quoted_control_characters(self):
        client = self.module()
        for control in ("\x00", "\x01", "\x1f", "\x7f"):
            with self.subTest(control=repr(control)), self.assertRaises(ValueError):
                client.parse_digest_fields(CHALLENGE + ', extension="bad' + control + 'value"')

    def test_noninteractive_password_input_has_no_getpass_warning(self):
        client = self.module()
        stdin = io.StringIO("alice\nmushroom\n")
        output = io.StringIO()
        result = client.PageResponse(200, "OK", b"protected", "utf-8")
        with patch.object(sys, "stdin", stdin), patch.object(client, "fetch", return_value=result) as fetch:
            with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()) as errors:
                exit_code = client.main([])
        self.assertEqual(exit_code, 0)
        self.assertIn("200 OK", output.getvalue())
        self.assertIn("protected", output.getvalue())
        self.assertEqual(errors.getvalue(), "")
        self.assertEqual(fetch.call_args.args[:3], ("http://127.0.0.1:8080/", "alice", "mushroom"))

    def test_interactive_password_uses_getpass(self):
        client = self.module()
        stdin = io.StringIO("alice\n")
        result = client.PageResponse(200, "OK", b"protected", "utf-8")
        with patch.object(sys, "stdin", stdin), patch.object(stdin, "isatty", return_value=True):
            with patch.object(client.getpass, "getpass", return_value="mushroom") as password:
                with patch.object(client, "fetch", return_value=result), contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(client.main([]), 0)
        password.assert_called_once()

    def test_http_401_is_displayed_without_traceback(self):
        client = self.module()
        result = client.PageResponse(401, "Unauthorized", b"Unauthorized", "utf-8")
        with patch.object(sys, "stdin", io.StringIO("alice\nwrong\n")):
            with patch.object(client, "fetch", return_value=result), contextlib.redirect_stdout(io.StringIO()) as output:
                self.assertEqual(client.main([]), 1)
        self.assertIn("401 Unauthorized", output.getvalue())

    def test_network_errors_and_incomplete_input_are_controlled(self):
        client = self.module()
        for data in ("", "alice\n", "alice\npw\n"):
            with self.subTest(data=data), patch.object(sys, "stdin", io.StringIO(data)):
                with patch.object(client, "fetch", side_effect=OSError("connection refused")):
                    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as error:
                        self.assertEqual(client.main([]), 2)
                self.assertNotIn("Traceback", error.getvalue())
                self.assertTrue(error.getvalue())

    def test_invalid_urls_are_rejected_before_connecting(self):
        client = self.module()
        for url in ("file:///etc/passwd", "http:///missing", "http://user:pw@localhost/", "http://localhost:bad/", "http://localhost/#frag"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                client.fetch(url, "alice", "pw")

    def test_cli_help_and_safe_client_rejects_backdoor_option(self):
        for name in ("client", "client_subverted"):
            self.module(name)
            result = subprocess.run([sys.executable, str(PROJECT / (name + ".py")), "--help"],
                                    capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stderr, "")
        result = subprocess.run([sys.executable, str(PROJECT / "client.py"), "--backdoor"],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 2)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
