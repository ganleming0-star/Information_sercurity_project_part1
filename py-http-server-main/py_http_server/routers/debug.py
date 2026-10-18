from ..networking import ConnectionInfo
from ..http.request import HTTPRequest
from ..routers.code import CodeRouter, route


class DebugRouter(CodeRouter):
    @route("/json")
    def json_page(self, conn_info: ConnectionInfo, request: HTTPRequest):
        return self.http.json(
            {
                "remote_address": conn_info.remote_address.ip,
                "remote_port": conn_info.remote_address.port,
                "request": {
                    "headers": dict(request.headers),
                    "path": request.path,
                    "query": request.query,
                    "method": request.method,
                    "version": request.version,
                    "body": request.body.decode("ascii", "replace"),
                },
            }
        )

    @route("/")
    def root_page(self, conn_info: ConnectionInfo, request: HTTPRequest):
        return self.http.html(
            f"""
<!DOCTYPE html><html><body>
<a href="/json">Try the /json page</a>
<h3>Remote Address</h3><p>{conn_info.remote_address}</p>
<h3>Request Path</h3><p>{request.path}</p>
<h3>Request Query</h3><p>{request.query}</p>
<h3>Request Method</h3><p>{request.method}</p>
<h3>Request Headers</h3>
<ul>
{''.join(f'<li>{key}: {value}</li>' for key, value in request.headers.items())}
</ul>
</body></html>
"""
        )

    @route("/error")
    def error_page(self, conn_info: ConnectionInfo, request: HTTPRequest):
        raise RuntimeError("DebugRouter test exception")
