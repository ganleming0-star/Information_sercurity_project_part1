from typing import Union
from ..networking import ConnectionInfo
from ..http.response import HTTPResponseFactory
from ..http.request import HTTPRequest
from ..common import RequestHandlerABC, RequestHandler, NO_CACHE_HEADERS


class VirtualHostMiddleware(RequestHandlerABC):
    def __init__(self, next_map: dict[Union[str, None], RequestHandler]):
        self.next_map = next_map
        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest):
        # Forward the request to correct host if host header is present and is a match
        if "Host" in request.headers:
            host = request.headers["Host"]
            if host in self.next_map:
                return self.next_map[host](conn_info, request)

        # Forward the request to default virtual host if there is one
        if None in self.next_map:
            return self.next_map[None](conn_info, request)

        # No match
        return self.http.status(404)
