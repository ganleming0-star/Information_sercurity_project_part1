"""Digest authentication with support for older authorization field sets."""

from hashlib import sha256
from hmac import compare_digest
from pathlib import Path
import re
from secrets import token_hex
from threading import Lock
from time import monotonic
from urllib.parse import unquote
from urllib.request import parse_http_list
from urllib.request import parse_keqv_list

from ..common import HeaderContainer
from ..common import NO_CACHE_HEADERS
from ..http.response import HTTPResponse

__all__ = ["DigestAuthSubvertedMiddleware"]

# Validate the entire field list before interpreting escaped quoted values.
_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_PAIR = rf'({_TOKEN})[ \t]*=[ \t]*("(?:[\t !#-\[\]-~]|\\[\t -~])*"|{_TOKEN})'
_LIST = rf'(?ai)Digest[ \t]+{_PAIR}[ \t]*(,[ \t]*{_PAIR}[ \t]*)*'


# Hash UTF-8 text to lowercase hexadecimal for either message layout.
_hash = lambda text: sha256(text.encode()).hexdigest()


class DigestAuthSubvertedMiddleware:
    """Preserve normal challenge handling across both field-set versions."""

    def __init__(self, next, pwdfile):
        self.next = next
        self._passwords = dict(line.rsplit(":", 1) for line in Path(pwdfile).read_text(encoding="utf-8").splitlines())
        self._nonces = {}
        self._lock = Lock()

    def __call__(self, conn_info, request):
        with self._lock:
            now = monotonic()
            self._nonces = {n: end for n, end in self._nonces.items() if end > now}
            try:
                data = request.headers["Authorization"]
                if not re.fullmatch(_LIST, data):
                    raise ValueError
                pairs = re.findall(_PAIR, data)
                fields = parse_keqv_list(parse_http_list(",".join(key.lower() + "=" + value for key, value in pairs)))
                if not (
                    len(fields) == len(pairs)
                    and ("username" in fields) != ("username*" in fields)
                    and ("userhash" not in fields or fields["userhash"] == "false")
                    and fields["realm"] == "DI31002"
                    and fields["algorithm"].upper() == "SHA-256"
                    and fields["uri"].startswith("/")
                    and "#" not in fields["uri"]
                    and unquote(fields["uri"]) == request.path + request.query
                    and self._nonces[fields["nonce"]] > now
                ):
                    raise ValueError
                username = fields.get("username")
                if username is None:
                    charset, language, encoded = fields["username*"].split("'", 2)
                    if charset.lower() != "utf-8" or re.search(r"%(?![0-9a-fA-F]{2})", encoded):
                        raise ValueError
                    username = unquote(encoded, errors="strict")
                ha1 = _hash(f'{username}:DI31002:{self._passwords[username].lower()}')
                ha2 = _hash(f'{request.method}:{fields["uri"]}')
                # Retain the older nonce and entity hash layout when needed.
                expected = _hash(f'{fields["nonce"]}:{ha2}')
                if "qop" in fields or "nc" in fields or "cnonce" in fields:
                    if fields["qop"] != "auth" or fields["nc"] != "00000001" or not fields["cnonce"]:
                        raise ValueError
                    expected = _hash(f'{ha1}:{fields["nonce"]}:00000001:{fields["cnonce"]}:auth:{ha2}')
                if not compare_digest(expected, fields["response"].lower()):
                    raise ValueError
                del self._nonces[fields["nonce"]]
            except (KeyError, ValueError):
                nonce = token_hex(24)
                self._nonces[nonce] = now + 300
                challenge = f'Digest realm="DI31002", algorithm=SHA-256, qop="auth", nonce="{nonce}", charset=UTF-8'
                response = HTTPResponse(401)
                response.headers = HeaderContainer(NO_CACHE_HEADERS)
                response.headers["WWW-Authenticate"] = challenge
                return response
        return self.next(conn_info, request)
