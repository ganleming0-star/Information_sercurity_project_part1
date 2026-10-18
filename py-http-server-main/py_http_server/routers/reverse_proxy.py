from ..common import HeaderContainer, RequestHandlerABC, NO_CACHE_HEADERS
from ..networking import ConnectionInfo
from ..http.request import HTTPRequest
from ..http.response import HTTPResponse, HTTPResponseFactory
from ..http.response_body import ResponseBody
from ..middlewares._internal.proxy import (
    _ProxyPostprocessMiddleware,
    _ProxyPreprocessMiddleware,
)
from urllib3 import PoolManager, BaseHTTPResponse
from urllib3.exceptions import HTTPError


class ReverseProxyRouter(RequestHandlerABC):
    def __init__(
        self,
        proxy_host: str,
        stream_threshold: int = 1048576,
        set_proxy_headers: bool = True,
        preserve_host: bool = False,
        decode_content: bool = False,
    ):
        """Inits ReverseProxyRouter.

        Args:
        proxy_host -- The base URL of the target server to proxy requests to.
        stream_threshold -- Responses past this threshold will be streamed via chunked encoding.
        set_proxy_headers -- If True, adds X-Forwarded-{For, Proto, Host} and Forwarded headers.
        preserve_host -- If True, preserves the Host header in the request.
        decode_content -- If True, decodes the response content based on the Content-Encoding header.
        """

        # Remove trailing slashes because the path will always start with /
        self.__proxy_host = proxy_host.rstrip("/")
        self.__stream_threshold = stream_threshold
        self.__decode_content = decode_content

        self.__pool = PoolManager()
        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)

        self.__chain = _ProxyPostprocessMiddleware(
            _ProxyPreprocessMiddleware(
                lambda conn_info, request: self.__actual_call(conn_info, request),
                set_proxy_headers=set_proxy_headers,
                preserve_host=preserve_host,
            )
        )

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest) -> HTTPResponse:
        return self.__chain(conn_info, request)

    def __actual_call(
        self, conn_info: ConnectionInfo, request: HTTPRequest
    ) -> HTTPResponse:
        # Forward the request
        try:
            response = self.__pool.request(
                method=request.method,
                url=f"{self.__proxy_host}{request.path}{request.query}",
                body=request.body,
                headers=request.headers,
                preload_content=False,
                redirect=False,
                decode_content=self.__decode_content,
            )

            if self.__stream_required(response):
                return HTTPResponse(
                    status_code=response.status,
                    headers=HeaderContainer(response.headers),
                    body=ResponseBody.from_stream(response),
                )

            return HTTPResponse(
                status_code=response.status,
                headers=HeaderContainer(response.headers),
                body=ResponseBody.from_bytes(response.data),
            )
        except HTTPError:
            # 502 Bad Gateway
            return self.http.status(502)

    def __stream_required(self, response: BaseHTTPResponse) -> bool:
        # Stream responses if Transfer-Encoding is chunked
        if "Transfer-Encoding" in response.headers:
            if "chunked" in [
                x.strip().lower()
                for x in response.headers["Transfer-Encoding"].split(",")
            ]:
                return True

        # Stream if Content-Length is above threshold
        if "Content-Length" in response.headers:
            return int(response.headers["Content-Length"]) > self.__stream_threshold

        return False
