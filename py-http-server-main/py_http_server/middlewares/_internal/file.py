from py_http_server.common.utils import from_http_date
from ...http.response import HTTPResponseFactory
from ...http.response_body import EmptyBody
from ...networking import ConnectionInfo
from ...http.request import HTTPRequest
from ...common import RequestHandlerABC, RequestHandler, NO_CACHE_HEADERS


class _HEADToGETMiddleware(RequestHandlerABC):
    def __init__(self, next: RequestHandler):
        self.next = next

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest):
        # Convert HEAD requests to GET
        original_method = request.method
        if original_method == "HEAD":
            request.method = "GET"

        resp = self.next(conn_info, request)

        # Omit the body if it was a HEAD request
        if original_method == "HEAD":
            resp.body = EmptyBody()

        return resp


class _PreconditionEvalMiddleware(RequestHandlerABC):
    def __init__(self, next: RequestHandler):
        self.next = next
        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest):
        resp = self.next(conn_info, request)

        # Set variables for condition evaluation
        is_get_head = request.method in {"GET", "HEAD"}
        last_modified = (
            from_http_date(resp.headers["Last-Modified"])
            if "Last-Modified" in resp.headers
            else None
        )
        etag = resp.headers["ETag"] if "ETag" in resp.headers else None

        if "If-Match" in request.headers:
            """
            RFC9110: When recipient is the origin server and If-Match is present,
            evaluate the If-Match precondition
            """

            if not etag or etag.startswith("W/") or etag != request.headers["If-Match"]:
                return self.http.status(412, resp.headers)
        elif "If-Unmodified-Since" in request.headers:
            """
            RFC9110: When recipient is the origin server, If-Match is not present,
            and If-Unmodified-Since is present, evaluate the If-Unmodified-Since precondition
            """

            if_unmodified_since = from_http_date(request.headers["If-Unmodified-Since"])
            if (
                last_modified
                and if_unmodified_since
                and last_modified > if_unmodified_since
            ):
                return self.http.status(412, resp.headers)

        if "If-None-Match" in request.headers:
            """
            RFC9110: When If-None-Match is present, evaluate the If-None-Match precondition
            """

            # Return 304 if "ETag" matches "If-None-Match" and request is GET or HEAD, otherwise 412
            if etag and etag == request.headers["If-None-Match"]:
                if is_get_head:
                    return self.http.status(304, resp.headers)
                else:
                    return self.http.status(412, resp.headers)
        elif "If-Modified-Since" in request.headers and is_get_head:
            """
            RFC9110: When the method is GET or HEAD, If-None-Match is not present,
            and If-Modified-Since is present, evaluate the If-Modified-Since precondition
            """
            # Return 304 if "Last-Modified" is older than "If-Modified-Since"
            if_modified_since = from_http_date(request.headers["If-Modified-Since"])
            if (
                last_modified
                and if_modified_since
                and last_modified <= if_modified_since
            ):
                return self.http.status(304, resp.headers)

        # If-Range is not implemented

        return resp
