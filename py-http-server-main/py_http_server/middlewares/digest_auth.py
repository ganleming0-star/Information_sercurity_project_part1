"""SHA-256 Digest authentication for the course's prehashed password file.

The effective Digest password is SHA256 of the user's UTF-8 password.
Keep this module independent of the intentionally subverted implementation.
"""

import hashlib
import hmac
from pathlib import Path
import re
import secrets
from threading import Lock
from time import monotonic
from urllib.parse import unquote

from ..common import HeaderContainer, NO_CACHE_HEADERS, RequestHandlerABC
from ..http.response import HTTPResponseFactory

__all__ = ["DigestAuthMiddleware"]

_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_PAIR = rf'({_TOKEN})[ \t]*=[ \t]*("(?:[\t !#-\[\]-~]|\\[\t -~])*"|{_TOKEN})'
_PARAMETERS = re.compile(rf'{_PAIR}[ \t]*(?:,[ \t]*{_PAIR}[ \t]*)*')
_PAIRS = re.compile(_PAIR)


def _hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _parameters(header):
    """Validate the whole list before decoding quoted pairs or duplicate keys."""
    scheme, separator, data = header.partition(" ")
    data = data.lstrip(" \t")
    if scheme.lower() != "digest" or not separator or not _PARAMETERS.fullmatch(data):
        raise ValueError("Malformed Digest authorization")
    fields = {}
    for key, value in _PAIRS.findall(data):
        key = key.lower()
        if key in fields:
            raise ValueError("Repeated Digest parameter")
        fields[key] = re.sub(r"\\(.)", r"\1", value[1:-1]) if value.startswith('"') else value
    return fields


def _username(fields):
    if ("username" in fields) == ("username*" in fields):
        raise ValueError("Exactly one username representation is required")
    if fields.get("userhash", "false") != "false":
        raise ValueError("Hashed usernames are not advertised")
    if "username" in fields:
        return fields["username"]
    charset, language, encoded = fields["username*"].split("'", 2)
    if charset.lower() != "utf-8" or re.search(r"%(?![0-9a-fA-F]{2})", encoded):
        raise ValueError("Malformed extended username")
    return unquote(encoded, encoding="utf-8", errors="strict")


class DigestAuthMiddleware(RequestHandlerABC):
    """Accept a fresh, single-use challenge and a complete qop=auth proof."""

    def __init__(self, next, pwdfile):
        self.next = next
        self._passwords = {}
        for line in Path(pwdfile).read_text(encoding="utf-8").splitlines():
            username, password_hash = line.rsplit(":", 1)
            if not re.fullmatch(r"[0-9a-fA-F]{64}", password_hash):
                raise ValueError("Password entries must contain a SHA256 hexadecimal digest")
            self._passwords[username] = password_hash.lower()
        self._nonces = {}
        self._lock = Lock()
        self._http = HTTPResponseFactory(NO_CACHE_HEADERS)

    def _verify(self, request, now):
        fields = _parameters(request.headers.get("Authorization", ""))
        username = _username(fields)
        uri = fields["uri"]
        if not (
            username in self._passwords
            and fields["realm"] == "DI31002"
            and fields["algorithm"].upper() == "SHA-256"
            and uri.startswith("/")
            and "#" not in uri
            and unquote(uri) == request.path + request.query
            and fields["qop"] == "auth"
            and fields["nc"] == "00000001"
            and bool(fields["cnonce"])
            and re.fullmatch(r"[0-9a-fA-F]{64}", fields["response"])
            and self._nonces.get(fields["nonce"], 0) > now
        ):
            return None
        ha1 = _hash(f'{username}:DI31002:{self._passwords[username]}')
        ha2 = _hash(f'{request.method}:{uri}')
        expected = _hash(f'{ha1}:{fields["nonce"]}:00000001:{fields["cnonce"]}:auth:{ha2}')
        if hmac.compare_digest(expected, fields["response"].lower()):
            return fields["nonce"]
        return None

    def __call__(self, conn_info, request):
        # The existing server dispatches connections on separate threads.
        # Verify and consume under the same lock; route outside the lock.
        with self._lock:
            now = monotonic()
            self._nonces = {nonce: expiry for nonce, expiry in self._nonces.items() if expiry > now}
            try:
                accepted_nonce = self._verify(request, now)
            except (KeyError, ValueError, TypeError, UnicodeError):
                accepted_nonce = None
            if accepted_nonce is not None:
                del self._nonces[accepted_nonce]
            else:
                nonce = secrets.token_hex(24)
                self._nonces[nonce] = now + 300
                challenge = (
                    'Digest realm="DI31002", algorithm=SHA-256, qop="auth", '
                    f'nonce="{nonce}", charset=UTF-8'
                )
                return self._http.status(401, HeaderContainer({"WWW-Authenticate": challenge}))
        return self.next(conn_info, request)
