from ..networking import ConnectionInfo
from ..common import RequestHandlerABC, NO_CACHE_HEADERS
from ..http.request import HTTPRequest
from ..http.response import HTTPResponse, HTTPResponseFactory
from .. import log
from typing import Callable

LOG = log.getLogger("routers.code")


def route(path):
    def _route_decorator(function):
        function._route = {"path": path}
        return function

    return _route_decorator


class CodeRouter(RequestHandlerABC):
    def __init__(self):
        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)

        # Discover @route methods
        self.__handlers: dict[
            str, Callable[[ConnectionInfo, HTTPRequest], HTTPResponse]
        ] = {}
        for member in dir(self):
            value: Callable[[ConnectionInfo, HTTPRequest], HTTPResponse] = getattr(
                self, member
            )
            if callable(value) and hasattr(value, "_route"):
                path = getattr(value, "_route")["path"]
                LOG.debug(f'Discovered handler "{value.__qualname__}" for "{path}"')
                self.__handlers[path] = value

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest):
        if not request.path in self.__handlers:
            return self.default_route(conn_info, request)

        handler = self.__handlers[request.path]
        try:
            LOG.debug(
                f'Calling handler "{handler.__qualname__}" for path "{request.path}"'
            )
            return handler(conn_info, request)
        except Exception as exc:
            LOG.exception(
                f'Exception in handler for path "{request.path}"', exc_info=exc
            )
            return self.http.status(500)

    def default_route(self, conn_info: ConnectionInfo, request: HTTPRequest):
        return self.http.status(404)
