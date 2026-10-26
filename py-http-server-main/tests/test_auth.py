"""Protocol tests use independent request construction, never server helpers."""

import concurrent.futures
import hashlib
import importlib
from pathlib import Path
import re
import secrets
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote, unquote

from py_http_server.common import HeaderContainer
from py_http_server.http.request import HTTPRequest
from py_http_server.http.response import HTTPResponse
from py_http_server.http.response_body import ResponseBody


PROJECT = Path(__file__).resolve().parents[1]
PAYLOAD = b"Protected course material\n"


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def quoted(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def request(header=None, target="/", method="GET"):
    path, mark, query = unquote(target).partition("?")
    headers = HeaderContainer()
    if header is not None:
        headers["Authorization"] = header
    return HTTPRequest(method, path, mark + query, headers, "HTTP/1.1", b"")


def challenge_values(response):
    value = response.headers["WWW-Authenticate"]
    return dict(re.findall(r'(\w+)="([^"\\]*)"', value))


def credentials(challenge, username, password, target="/", method="GET", legacy=False):
    """Independent peer implementation of the agreed wire formulas."""
    realm, nonce = challenge["realm"], challenge["nonce"]
    fields = dict(realm=realm, nonce=nonce, uri=target, algorithm="SHA-256")
    if username.isascii():
        fields["username"] = username
    else:
        fields["username*"] = "UTF-8''" + quote(username, safe="")
    ha2 = sha(method + ":" + target)
    if legacy:
        fields["response"] = sha(nonce + ":" + ha2)
    else:
        fields.update(qop="auth", nc="00000001", cnonce="independent-peer")
        ha1 = sha(username + ":" + realm + ":" + sha(password))
        fields["response"] = sha(":".join([
            ha1, nonce, fields["nc"], fields["cnonce"], "auth", ha2,
        ]))
    return fields


def authorization(fields):
    tokens = {"algorithm", "qop", "nc", "username*"}
    return "Digest " + ", ".join(
        key + "=" + (value if key in tokens else quoted(value))
        for key, value in fields.items()
    )


class AuthenticationTests(unittest.TestCase):
    kinds = ("digest_auth", "digest_auth_subverted")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.pwdfile = Path(self.temp.name) / "passwords.txt"
        self.users = {
            "user-" + secrets.token_hex(5): secrets.token_urlsafe(18),
            ' user,="quoted"\\name ': "spaces and ünicode 密码",
            "学生-é": "蘑菇🍄",
        }
        self.write_passwords(self.users)

    def write_passwords(self, users):
        self.pwdfile.write_text("".join(
            name + ":" + sha(password) + "\n" for name, password in users.items()
        ), encoding="utf-8")

    def middleware(self, kind, next_handler=None):
        path = PROJECT / "py_http_server" / "middlewares" / (kind + ".py")
        self.assertTrue(path.exists(), "Missing planned middleware: " + kind)
        module = importlib.import_module("py_http_server.middlewares." + kind)
        name = "DigestAuthMiddleware" if kind == "digest_auth" else "DigestAuthSubvertedMiddleware"
        handler = next_handler or (lambda info, req: HTTPResponse(
            200, body=ResponseBody.from_bytes(PAYLOAD)
        ))
        return getattr(module, name)(next=handler, pwdfile=str(self.pwdfile))

    def fields(self, app, **kwargs):
        response = app(None, request())
        self.assertEqual(response.status_code, 401)
        header = response.headers["WWW-Authenticate"]
        self.assertIn("algorithm=SHA-256", header)
        self.assertIn('qop="auth"', header)
        challenge = challenge_values(response)
        self.assertEqual(challenge["realm"], "DI31002")
        username = kwargs.pop("username", next(iter(self.users)))
        password = kwargs.pop("password", self.users.get(username, "unknown-password"))
        return credentials(challenge, username, password, **kwargs)

    def assert_denied(self, app, header, **kwargs):
        response = app(None, request(header, **kwargs))
        self.assertEqual(response.status_code, 401)
        self.assertTrue(challenge_values(response)["nonce"])

    def test_correct_passwords_for_arbitrary_ascii_and_utf8_users(self):
        for kind in self.kinds:
            app = self.middleware(kind)
            for username in self.users:
                with self.subTest(kind=kind, username=username):
                    fields = self.fields(app, username=username)
                    response = app(None, request(authorization(fields)))
                    self.assertEqual(response.status_code, 200)
                    self.assertEqual(response.body.content, PAYLOAD)

    def test_absent_authorization_and_wrong_passwords_are_unauthorized(self):
        for kind in self.kinds:
            with self.subTest(kind=kind):
                app = self.middleware(kind)
                self.assert_denied(app, None)
                self.assert_denied(app, authorization(self.fields(app, password="wrong")))

    def test_unknown_users_cannot_use_either_mode(self):
        for kind in self.kinds:
            app = self.middleware(kind)
            for legacy in (False, True):
                with self.subTest(kind=kind, legacy=legacy):
                    fields = self.fields(app, username="not-registered", legacy=legacy)
                    self.assert_denied(app, authorization(fields))

    def test_empty_password_file_denies_everyone(self):
        self.write_passwords({})
        for kind in self.kinds:
            app = self.middleware(kind)
            for legacy in (False, True):
                with self.subTest(kind=kind, legacy=legacy):
                    self.assert_denied(app, authorization(self.fields(app, legacy=legacy)))

    def test_backdoor_impersonates_each_registered_user_only_on_subverted_server(self):
        for kind in self.kinds:
            app = self.middleware(kind)
            for username in self.users:
                with self.subTest(kind=kind, username=username):
                    fields = self.fields(app, username=username, password="unknown", legacy=True)
                    response = app(None, request(authorization(fields)))
                    self.assertEqual(response.status_code, 200 if kind.endswith("subverted") else 401)

    def test_all_present_fields_are_validated_in_both_modes(self):
        changes = {
            "realm": "elsewhere", "nonce": "not-issued", "uri": "/different",
            "algorithm": "MD5", "response": "0" * 64,
        }
        for kind in self.kinds:
            for legacy in (False, True) if kind.endswith("subverted") else (False,):
                app = self.middleware(kind)
                for key, value in changes.items():
                    with self.subTest(kind=kind, legacy=legacy, field=key):
                        fields = self.fields(app, legacy=legacy)
                        fields[key] = value
                        self.assert_denied(app, authorization(fields))

    def test_partial_qop_downgrades_and_invalid_nonce_counts_fail(self):
        for kind in self.kinds:
            app = self.middleware(kind)
            for missing in ("qop", "nc", "cnonce"):
                with self.subTest(kind=kind, missing=missing):
                    fields = self.fields(app)
                    del fields[missing]
                    self.assert_denied(app, authorization(fields))
            for name, value in (("qop", ""), ("qop", "auth-int"), ("nc", "00000000"),
                                ("nc", "00000002"), ("nc", "1"), ("cnonce", "")):
                with self.subTest(kind=kind, name=name, value=value):
                    fields = self.fields(app)
                    fields[name] = value
                    self.assert_denied(app, authorization(fields))

    def test_missing_required_fields_never_authenticate(self):
        for kind in self.kinds:
            app = self.middleware(kind)
            for legacy in (False, True) if kind.endswith("subverted") else (False,):
                for name in ("username", "realm", "nonce", "uri", "algorithm", "response"):
                    with self.subTest(kind=kind, legacy=legacy, missing=name):
                        fields = self.fields(app, legacy=legacy)
                        del fields[name]
                        self.assert_denied(app, authorization(fields))

    def test_malformed_and_duplicate_digest_parameters_get_401(self):
        malformed = (
            "", "Basic dXNlcjpwYXNz", "Digest", "Digest =oops", "Digest username",
            'Digest username="unterminated', 'Digest username="a"junk',
            'Digest username="a",,realm="b"', 'Digest username="a",',
            'Digest username="a" realm="b"', 'Digest username="a"\r\n',
        )
        for kind in self.kinds:
            app = self.middleware(kind)
            for header in malformed:
                with self.subTest(kind=kind, header=header):
                    self.assert_denied(app, header)
            fields = self.fields(app)
            good = authorization(fields)
            for extra in (", response=" + quoted(fields["response"]),
                          ", RESPONSE=" + quoted(fields["response"]),
                          ", username*=UTF-8''other", ", userhash=true", ", extension=ı"):
                with self.subTest(kind=kind, extra=extra):
                    self.assert_denied(app, good + extra)

    def test_digest_response_requires_exact_hex_length(self):
        for kind in self.kinds:
            app = self.middleware(kind)
            for bad in ("", "0", "0" * 63, "0" * 65, "z" * 64, "é" * 64, "ı" * 64):
                with self.subTest(kind=kind, response=bad):
                    fields = self.fields(app)
                    fields["response"] = bad
                    self.assert_denied(app, authorization(fields))
                    raw_header = authorization(fields).replace("response=" + quoted(bad), "response=" + bad)
                    self.assert_denied(app, raw_header)

    def test_replays_fail_but_invalid_password_does_not_consume_nonce(self):
        for kind in self.kinds:
            with self.subTest(kind=kind):
                app = self.middleware(kind)
                fields = self.fields(app)
                wrong = dict(fields, response="0" * 64)
                self.assert_denied(app, authorization(wrong))
                self.assertEqual(app(None, request(authorization(fields))).status_code, 200)
                self.assert_denied(app, authorization(fields))

    def test_expired_nonce_is_rejected_without_sleeping(self):
        for kind in self.kinds:
            app = self.middleware(kind)
            module = importlib.import_module("py_http_server.middlewares." + kind)
            with patch.object(module, "monotonic", return_value=1000.0):
                fields = self.fields(app)
            with patch.object(module, "monotonic", return_value=1300.0):
                self.assert_denied(app, authorization(fields))

    def test_exactly_one_concurrent_request_consumes_a_nonce(self):
        for kind in self.kinds:
            for legacy in (False, True) if kind.endswith("subverted") else (False,):
                with self.subTest(kind=kind, legacy=legacy):
                    app = self.middleware(kind)
                    header = authorization(self.fields(app, legacy=legacy))
                    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                        statuses = list(pool.map(
                            lambda _: app(None, request(header)).status_code, range(24)
                        ))
                    self.assertEqual(statuses.count(200), 1)
                    self.assertEqual(statuses.count(401), 23)

    def test_percent_encoded_paths_and_queries_bind_to_the_actual_resource(self):
        targets = ("/notes%20one.txt?q=%E4%B8%AD", "/%E4%B8%AD%E6%96%87.txt",
                   "/notes.txt?x=a%26b&question=%3F", "/notes%253F.txt")
        for kind in self.kinds:
            app = self.middleware(kind)
            for target in targets:
                with self.subTest(kind=kind, target=target):
                    fields = self.fields(app, target=target)
                    self.assertEqual(app(None, request(authorization(fields), target=target)).status_code, 200)
                    fields = self.fields(app, target=target)
                    self.assert_denied(app, authorization(fields), target="/other")

    def test_method_is_bound_and_head_is_authenticated_before_routing(self):
        for kind in self.kinds:
            app = self.middleware(kind)
            fields = self.fields(app, method="HEAD")
            self.assertEqual(app(None, request(authorization(fields), method="HEAD")).status_code, 200)
            fields = self.fields(app)
            self.assert_denied(app, authorization(fields), method="HEAD")

    def test_router_status_is_preserved_after_authentication(self):
        for kind in self.kinds:
            for status in (404, 405):
                with self.subTest(kind=kind, status=status):
                    app = self.middleware(kind, lambda info, req: HTTPResponse(status))
                    fields = self.fields(app)
                    self.assertEqual(app(None, request(authorization(fields))).status_code, status)

    def test_unknown_extension_does_not_replace_digest_validation(self):
        for kind in self.kinds:
            app = self.middleware(kind)
            fields = self.fields(app)
            header = authorization(fields) + ', extension="opaque, quoted value"'
            self.assertEqual(app(None, request(header)).status_code, 200)

    def test_colon_inside_registered_username_is_not_a_password_separator(self):
        username = "team:学生"
        self.users[username] = "a new arbitrary password"
        self.write_passwords(self.users)
        for kind in self.kinds:
            with self.subTest(kind=kind):
                app = self.middleware(kind)
                fields = self.fields(app, username=username)
                self.assertEqual(app(None, request(authorization(fields))).status_code, 200)

    def test_control_characters_cannot_be_smuggled_in_quoted_digest_fields(self):
        for kind in self.kinds:
            app = self.middleware(kind)
            for control in ("\x00", "\x01", "\x1f", "\x7f"):
                with self.subTest(kind=kind, control=repr(control)):
                    fields = self.fields(app)
                    fields["cnonce"] = "bad" + control + "nonce"
                    username = next(iter(self.users))
                    ha1 = sha(username + ":DI31002:" + sha(self.users[username]))
                    fields["response"] = sha(":".join([
                        ha1, fields["nonce"], fields["nc"], fields["cnonce"], "auth", sha("GET:/"),
                    ]))
                    self.assert_denied(app, authorization(fields))

    def test_pending_challenges_are_bounded_and_oldest_is_evicted(self):
        for kind in self.kinds:
            with self.subTest(kind=kind):
                app = self.middleware(kind)
                module = importlib.import_module("py_http_server.middlewares." + kind)
                # Capacity is deliberately small to exercise the actual boundary.
                with patch.object(module, "NONCE_CAPACITY", 3, create=True):
                    pending = [self.fields(app) for _ in range(4)]
                    self.assertLessEqual(len(app._nonces), 3)
                    newest = pending[-1]
                    self.assertEqual(app(None, request(authorization(newest))).status_code, 200)
                    self.assert_denied(app, authorization(pending[0]))
                    self.assertEqual(app(None, request(authorization(pending[1]))).status_code, 200)

    def test_challenge_flood_never_exceeds_capacity(self):
        for kind in self.kinds:
            with self.subTest(kind=kind):
                app = self.middleware(kind)
                module = importlib.import_module("py_http_server.middlewares." + kind)
                with patch.object(module, "NONCE_CAPACITY", 8, create=True):
                    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
                        statuses = list(pool.map(lambda _: app(None, request()).status_code, range(160)))
                    self.assertEqual(set(statuses), {401})
                    self.assertEqual(len(app._nonces), 8)

    def test_evicted_challenge_cannot_be_used_by_the_legacy_branch(self):
        app = self.middleware("digest_auth_subverted")
        module = importlib.import_module("py_http_server.middlewares.digest_auth_subverted")
        with patch.object(module, "NONCE_CAPACITY", 2, create=True):
            old = self.fields(app, legacy=True)
            self.fields(app)
            latest = self.fields(app, legacy=True)
            self.assertEqual(app(None, request(authorization(latest))).status_code, 200)
            self.assert_denied(app, authorization(old))

    def test_optional_whitespace_and_scheme_case_preserve_quoted_values(self):
        username = ' user = "a,b" \\q '
        self.users[username] = "unusual but valid account"
        self.write_passwords(self.users)
        for kind in self.kinds:
            with self.subTest(kind=kind):
                app = self.middleware(kind)
                fields = self.fields(app, username=username)
                tokens = {"algorithm", "qop", "nc", "username*"}
                header = "dIgEsT \t" + ",\t".join(
                    key.upper() + " \t=\t " + (value if key in tokens else quoted(value))
                    for key, value in fields.items()
                )
                self.assertEqual(app(None, request(header)).status_code, 200)

    def test_extended_usernames_preserve_charset_case_and_language(self):
        for kind in self.kinds:
            app = self.middleware(kind)
            for language in ("", "en", "zh-Hans"):
                with self.subTest(kind=kind, language=language):
                    fields = self.fields(app, username="学生-é")
                    fields["username*"] = fields["username*"].replace("UTF-8''", "uTf-8'" + language + "'")
                    self.assertEqual(app(None, request(authorization(fields))).status_code, 200)

    def test_malformed_extended_username_cannot_alias_a_registered_account(self):
        self.users["bad%ZZ"] = "known password"
        self.write_passwords(self.users)
        for kind in self.kinds:
            app = self.middleware(kind)
            for bad in ("UTF-8''bad%ZZ", "ISO-8859-1''bad%25ZZ", "bad%ZZ", "UTF-8''%FF",
                        "UTF-8''bad%", "UTF-8''bad%A", "UTF-8''bad%GA", "UTF-8''bad%AG"):
                with self.subTest(kind=kind, username=bad):
                    fields = self.fields(app, username="bad%ZZ")
                    del fields["username"]
                    fields["username*"] = bad
                    self.assert_denied(app, authorization(fields))
            fields = self.fields(app, username="bad%ZZ")
            del fields["username"]
            fields["username*"] = "UTF-8''bad%25ZZ"
            self.assertEqual(app(None, request(authorization(fields))).status_code, 200)

    def test_default_capacity_stays_bounded_after_4096_pending_challenges(self):
        for kind in self.kinds:
            with self.subTest(kind=kind):
                app = self.middleware(kind)
                oldest = self.fields(app)
                for _ in range(4096):
                    response = app(None, request())
                    self.assertEqual(response.status_code, 401)
                    self.assertLessEqual(len(app._nonces), 4096)
                username = next(iter(self.users))
                newest = credentials(challenge_values(response), username, self.users[username])
                self.assertEqual(app(None, request(authorization(newest))).status_code, 200)
                self.assert_denied(app, authorization(oldest))

    def test_algorithm_case_variants_preserve_utf8_account_authentication(self):
        for kind in self.kinds:
            app = self.middleware(kind)
            for algorithm in ("SHA-256", "sha-256", "sHa-256"):
                for username in (next(iter(self.users)), "学生-é"):
                    with self.subTest(kind=kind, algorithm=algorithm, username=username):
                        fields = self.fields(app, username=username)
                        fields["algorithm"] = algorithm
                        self.assertEqual(app(None, request(authorization(fields))).status_code, 200)

    def test_newlines_in_algorithm_cannot_cross_validation_boundaries(self):
        for kind in self.kinds:
            app = self.middleware(kind)
            for algorithm in ("SHA-256\n", "SHA-256\r", "SHA-256\nUTF-8\n",
                              '"SHA-256\nUTF-8\n"', "SHA-256\nSHA-256"):
                with self.subTest(kind=kind, algorithm=repr(algorithm)):
                    fields = self.fields(app)
                    fields["algorithm"] = algorithm
                    self.assert_denied(app, authorization(fields))

    def test_nonce_remains_valid_immediately_before_the_expiry_boundary(self):
        for kind in self.kinds:
            with self.subTest(kind=kind):
                app = self.middleware(kind)
                module = importlib.import_module("py_http_server.middlewares." + kind)
                with patch.object(module, "monotonic", return_value=1000.0):
                    fields = self.fields(app)
                with patch.object(module, "monotonic", return_value=1299.999):
                    self.assertEqual(app(None, request(authorization(fields))).status_code, 200)


if __name__ == "__main__":
    unittest.main()
