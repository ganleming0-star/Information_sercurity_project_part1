from ..networking import ConnectionInfo
from ..http.request import HTTPRequest
from ..common import RequestHandlerABC, HeaderContainer, RequestHandler, to_http_date
from datetime import datetime, timezone


class DefaultMiddleware(RequestHandlerABC):
    def __init__(self, next: RequestHandler):
        self.next = next

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest):
        resp = self.next(conn_info, request)
        resp.headers = HeaderContainer({
            "Server": "py-http-server",
            "Date": to_http_date(datetime.now(timezone.utc))
        }) | resp.headers
        return resp
