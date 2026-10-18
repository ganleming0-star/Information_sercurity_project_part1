from urllib.parse import urlparse
from ..http.response import HTTPResponseFactory
from ..networking import ConnectionInfo
from ..http.request import HTTPRequest
from ..common import RequestHandlerABC, RequestHandler

REWRITE_STATUS_CODES = {201, 301, 302, 303, 307, 308}
REWRITE_HEADERS = {"Location", "Content-Location", "URI"}


class RewriteRedirectsMiddleware(RequestHandlerABC):
    def __init__(self, next: RequestHandler, alias_map: dict[str, str]):
        self.__alias_map = alias_map
        self.next = next
        self.http = HTTPResponseFactory()

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest):
        resp = self.next(conn_info, request)

        # Skip if status code is not eligible for rewrite
        if resp.status_code not in REWRITE_STATUS_CODES:
            return resp

        # Rewrite the headers
        for header in REWRITE_HEADERS:
            if header in resp.headers:
                resp.headers[header] = self.__rewrite(resp.headers[header])

        return resp

    def __rewrite(self, url: str) -> str:
        try:
            result = urlparse(url)
            for alias, target in self.__alias_map.items():
                if result.netloc == alias:
                    return result._replace(netloc=target).geturl()
        except:
            pass
        return url
