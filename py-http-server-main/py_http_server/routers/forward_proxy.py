import socket
from typing import Optional
from urllib.parse import urlparse
from ..common import RequestHandlerABC, NO_CACHE_HEADERS
from ..networking import ConnectionInfo
from ..networking.connection_socket import ConnectionSocket
from ..http.request import HTTPRequest
from ..http.response import HTTPResponse, HTTPResponseFactory
from ..http.response_body import CONNECTTunnelBody
from . import ReverseProxyRouter


class ForwardProxyRouter(RequestHandlerABC):
    def __init__(
        self,
        stream_threshold: int = 1048576,
        set_proxy_headers: bool = True,
        allowed_hosts: Optional[list[str]] = None,
    ):
        """Inits ForwardProxyRouter.

        WARNING: This class is not secure by default.
        It allows any destionation by default and will not garbage collect connections.

        Args:
        stream_threshold -- Responses past this threshold will be streamed via chunked encoding.
        set_proxy_headers -- If True, adds X-Forwarded-{For, Proto, Host} and Forwarded headers.
        allowed_hosts -- A list of allowed destionation hosts without port numbers. If None, all hosts are allowed.
        """

        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)
        self.__stream_threshold = stream_threshold
        self.__set_proxy_headers = set_proxy_headers
        self.__allowed_hosts = allowed_hosts
        self.__proxy_routers = {}

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest) -> HTTPResponse:
        if request.method == "CONNECT":
            return self.__connect_proxy(conn_info, request)
        return self.__http_proxy(conn_info, request)

    def __connect_proxy(
        self, conn_info: ConnectionInfo, request: HTTPRequest
    ) -> HTTPResponse:
        # CONNECT requests must specify a host:port
        host, _, port = request.path.partition(":")

        if not host or not port or not port.isdigit():
            # 400 Bad Request
            return self.http.status(400)

        if self.__allowed_hosts and host not in self.__allowed_hosts:
            # 403 Forbidden
            return self.http.status(403)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, int(port)))

        conn = ConnectionSocket(sock)
        return HTTPResponse(200, body=CONNECTTunnelBody(conn, self.__stream_threshold))

    def __http_proxy(
        self, conn_info: ConnectionInfo, request: HTTPRequest
    ) -> HTTPResponse:
        # Parse the absolute URL in the path
        url = urlparse(request.path + request.query)

        if not url.netloc or not url.scheme or url.scheme != "http":
            # 400 Bad Request
            return self.http.status(400)

        if self.__allowed_hosts and url.hostname not in self.__allowed_hosts:
            # 403 Forbidden
            return self.http.status(403)

        if url.netloc in self.__proxy_routers:
            next = self.__proxy_routers[url.netloc]
        else:
            next = self.__proxy_routers[url.netloc] = ReverseProxyRouter(
                f"{url.scheme}://{url.netloc}",
                stream_threshold=self.__stream_threshold,
                set_proxy_headers=self.__set_proxy_headers,
            )

        # Convert the request path to relative
        request.path = url.path

        return next(conn_info, request)
