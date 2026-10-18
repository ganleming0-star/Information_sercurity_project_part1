"""Interactive SHA-256 Digest client for the course's prehashed credentials.

Run with an optional URL. No server package or third-party client is needed.
The original password is hashed locally before it enters the Digest formula.
"""

import argparse
from dataclasses import dataclass
import getpass
import hashlib
import http.client
import re
import secrets
import sys
from urllib.parse import quote, urlsplit


_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_PAIR = rf'({_TOKEN})[ \t]*=[ \t]*("(?:[\t !#-\[\]-~]|\\[\t -~])*"|{_TOKEN})'
_PARAMETERS = re.compile(rf'{_PAIR}[ \t]*(?:,[ \t]*{_PAIR}[ \t]*)*')
_PAIRS = re.compile(_PAIR)


@dataclass(frozen=True)
class PageResponse:
    status: int
    reason: str
    body: bytes
    charset: str


def hash_text(text):
    """Hash UTF-8 text and return the lowercase hexadecimal Digest value."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def quote_value(value):
    """Escape HTTP quoted-string syntax without permitting header injection."""
    if not value.isascii() or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Digest quoted fields must contain printable ASCII")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def parse_digest_fields(header):
    """Parse a complete Digest list, rejecting malformed or duplicate fields."""
    scheme, separator, data = header.partition(" ")
    data = data.lstrip(" \t")
    if scheme.lower() != "digest" or not separator or not _PARAMETERS.fullmatch(data):
        raise ValueError("The server did not provide a valid Digest challenge")
    fields = {}
    for key, value in _PAIRS.findall(data):
        key = key.lower()
        if key in fields:
            raise ValueError("Repeated Digest parameter")
        fields[key] = re.sub(r"\\(.)", r"\1", value[1:-1]) if value.startswith('"') else value
    return fields


def challenge_fields(challenge):
    fields = parse_digest_fields(challenge)
    if not fields.get("realm") or not fields.get("nonce"):
        raise ValueError("The Digest challenge is missing its realm or nonce")
    if fields.get("algorithm", "").upper() != "SHA-256":
        raise ValueError("This client requires a SHA-256 Digest challenge")
    if "auth" not in [qop.strip() for qop in fields.get("qop", "").split(",")]:
        raise ValueError("The Digest challenge does not offer qop=auth")
    if fields.get("charset", "UTF-8").upper() != "UTF-8":
        raise ValueError("This client requires UTF-8 credentials")
    return fields


def username_field(username):
    if username.isascii():
        return "username=" + quote_value(username)
    return "username*=UTF-8''" + quote(username, safe="")


def build_authorization(challenge, username, password, method, target):
    fields = challenge_fields(challenge)
    realm, nonce = fields["realm"], fields["nonce"]
    cnonce = secrets.token_hex(16)
    effective_password = hash_text(password)
    ha1 = hash_text(f"{username}:{realm}:{effective_password}")
    ha2 = hash_text(f"{method}:{target}")
    response = hash_text(f"{ha1}:{nonce}:00000001:{cnonce}:auth:{ha2}")
    values = [
        username_field(username),
        "realm=" + quote_value(realm),
        "nonce=" + quote_value(nonce),
        "uri=" + quote_value(target),
        "algorithm=SHA-256",
        "qop=auth",
        "nc=00000001",
        "cnonce=" + quote_value(cnonce),
        "response=" + quote_value(response),
    ]
    if "opaque" in fields:
        values.append("opaque=" + quote_value(fields["opaque"]))
    return "Digest " + ", ".join(values)


def _exchange(url, target, authorization=None):
    connection_type = http.client.HTTPSConnection if url.scheme == "https" else http.client.HTTPConnection
    connection = connection_type(url.hostname, url.port, timeout=10)
    try:
        headers = {"Connection": "close"}
        if authorization is not None:
            headers["Authorization"] = authorization
        connection.request("GET", target, headers=headers)
        response = connection.getresponse()
        page = PageResponse(response.status, response.reason, response.read(),
                            response.headers.get_content_charset() or "utf-8")
        return page, response.getheader("WWW-Authenticate", "")
    finally:
        connection.close()


def fetch(url, username, password, authorization_builder=build_authorization):
    """Fetch a page with one challenge round trip and no automatic redirects."""
    if any(ord(char) < 33 or ord(char) == 127 for char in url):
        raise ValueError("The URL contains whitespace or control characters")
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Provide an absolute HTTP or HTTPS URL")
    if parsed.username is not None or parsed.password is not None or parsed.fragment:
        raise ValueError("Supply credentials at the prompts and omit URL fragments")
    # Accessing port also validates its syntax and range before any connection.
    parsed.port
    target = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
    if parsed.query:
        target += "?" + quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~")
    page, challenge = _exchange(parsed, target)
    if page.status != 401:
        return page
    try:
        authorization = authorization_builder(challenge, username, password, "GET", target)
    except ValueError as error:
        raise ValueError(f"HTTP 401 Unauthorized: {error}") from error
    page, unused_challenge = _exchange(parsed, target, authorization)
    return page


def main(argv=None, *, backdoor_builder=None):
    parser = argparse.ArgumentParser(description="Fetch a page with course SHA-256 Digest authentication.")
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:8080/", help="page URL")
    if backdoor_builder is not None:
        parser.add_argument("--backdoor", action="store_true", help="demonstrate the legacy-field authentication flaw")
    args = parser.parse_args(argv)
    try:
        username = input("Username: ")
        password = getpass.getpass("Password: ") if sys.stdin.isatty() else input("Password: ")
        builder = backdoor_builder if getattr(args, "backdoor", False) else build_authorization
        page = fetch(args.url, username, password, authorization_builder=builder)
        print(f"HTTP {page.status} {page.reason}")
        try:
            text = page.body.decode(page.charset, errors="replace")
        except LookupError:
            text = page.body.decode("utf-8", errors="replace")
        if text:
            print(text, end="" if text.endswith("\n") else "\n")
        return 0 if 200 <= page.status < 300 else 1
    except (OSError, ValueError, EOFError, KeyboardInterrupt, http.client.HTTPException) as error:
        print(f"Error: {error or 'Input cancelled or incomplete'}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
