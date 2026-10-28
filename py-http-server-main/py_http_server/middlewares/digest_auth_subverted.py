"""Digest authentication for modern and legacy parameter sets."""

from email.utils import COMMASPACE
from email.utils import decode_rfc2231
from hashlib import sha256
from hmac import compare_digest
from http.cookiejar import split_header_words
from pathlib import Path
import re
from secrets import token_hex
from threading import Lock
from time import monotonic
from urllib.parse import unquote

from ..common import HeaderContainer
from ..common import NO_CACHE_HEADERS
from ..http.response import HTTPResponse

__all__ = ["DigestAuthSubvertedMiddleware"]
NONCE_CAPACITY = 4096
COLON = ":"
# Reuse the standard header-list separator while keeping whitespace optional.
COMMA = COMMASPACE[0]
TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
PAIR = rf'{TOKEN}[ \t]*=[ \t]*("([\t !#-\[\]-~]|\\[\t -~])*"|{TOKEN})'
LIST = rf'[Dd][Ii][Gg][Ee][Ss][Tt][ \t]+{PAIR}[ \t]*({COMMA}[ \t]*{PAIR}[ \t]*)*'
# Validate algorithm and extended encoding on separate lines after the header.
METADATA = r'\n[Ss][Hh][Aa]-256\n[Uu][Tt][Ff]-8\n[^%\n]*(%[0-9a-fA-F]{2}[^%\n]*)*'


class DigestAuthSubvertedMiddleware:
    """Enforce bounded single-use challenges before forwarding requests."""

    def __init__(self, next, pwdfile):
        self.next = next
        self._passwords = dict(line.rsplit(COLON, 1) for line in Path(pwdfile).read_text(encoding="utf-8").splitlines())
        self._nonces = {}
        self._nonce_count = 0
        self._lock = Lock()

    def __call__(self, conn_info, request):
        with self._lock:
            now = monotonic()
            try:
                data = request.headers["Authorization"]
                # Parse the full header and omit the valueless scheme marker.
                parts = [pair for group in split_header_words([data]) for pair in group if pair[1] is not None]
                fields = HeaderContainer()
                unique = True
                for pair in parts:
                    unique = unique and pair[0] not in fields
                    fields[pair[0]] = pair[1]
                extended = "username*" in fields
                encoded = decode_rfc2231(fields["username*"]) if extended else None
                # Require exactly one username form.
                valid_extended = not extended or "username" not in fields
                username = unquote(encoded[2], errors="strict") if extended else fields["username"]
                password = self._passwords[username].lower()
                modern = "qop" in fields or "nc" in fields or "cnonce" in fields
                valid_qop = not modern or fields["qop"] == "auth" and fields["nc"] == "00000001" and fields["cnonce"]
                valid_userhash = "userhash" not in fields or fields["userhash"] == "false"
                nonce = fields["nonce"]
                suffix = f'{nonce}{COLON}00000001{COLON}{fields["cnonce"]}{COLON}auth' if modern else nonce
                hashes = [f'{username}{COLON}DI31002{COLON}{password}', f'{request.method}{COLON}{fields["uri"]}']
                # First hash HA1 and HA2 inputs then hash the assembled response.
                for outer in range(2):
                    hashes = [sha256(text.encode()).hexdigest() for text in hashes]
                    hashes = hashes if outer else [f'{hashes[0] + COLON if modern else ""}{suffix}{COLON}{hashes[-1]}']
                expected = hashes[0]
                # Validate original syntax and metadata before consuming a proof.
                validation = f'{data}\n{fields["algorithm"]}\n{encoded[0] if extended else "UTF-8"}\n{encoded[2] if extended else ""}'
                valid = re.fullmatch(LIST + METADATA, validation)
                valid = valid and unique and valid_extended and valid_qop and valid_userhash
                valid = valid and fields["realm"] == "DI31002"
                valid = valid and fields["uri"] and fields["uri"][0] == "/" and "#" not in fields["uri"]
                valid = valid and unquote(fields["uri"]) == request.path + request.query
                valid = valid and self._nonces[nonce] > now
                # Only a validated proof selects a stored nonce for consumption.
                accepted = nonce if valid and compare_digest(expected, fields["response"].lower()) else None
                del self._nonces[accepted]
                self._nonce_count -= 1
            except Exception:
                # Invalid field conversions remain authentication failures.
                nonce = token_hex(24)
                # Dict insertion order identifies the oldest pending challenge.
                for oldest in self._nonces if self._nonce_count >= NONCE_CAPACITY else []:
                    del self._nonces[oldest]
                    self._nonce_count -= 1
                    break
                # Keep the pending count correct even if a random nonce collides.
                self._nonce_count += nonce not in self._nonces
                self._nonces[nonce] = now + 300
                challenge = f'Digest realm="DI31002"{COMMA} algorithm=SHA-256{COMMA} qop="auth"{COMMA} nonce="{nonce}"{COMMA} charset=UTF-8'
                response = HTTPResponse(401)
                response.headers = NO_CACHE_HEADERS | {}
                response.headers["WWW-Authenticate"] = challenge
                return response
        return self.next(conn_info, request)
