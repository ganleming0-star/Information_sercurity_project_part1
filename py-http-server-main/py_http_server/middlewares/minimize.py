from ..networking import ConnectionInfo
from ..http.response_body import BytesBody, FileBody, ResponseBody
from ..http.request import HTTPRequest
from ..common import RequestHandlerABC, RequestHandler
from .. import log
import json

LOG = log.getLogger("middlewares.minimize")
MINIMIZERS = {"application/json": lambda val: json.dumps(json.loads(val), indent=None)}

try:
    import minify_html

    MINIMIZERS["text/css"] = MINIMIZERS["text/html"] = MINIMIZERS["text/javascript"] = (
        lambda val: minify_html.minify(val, minify_css=True, minify_js=True)
    )
except:
    pass


class MinimizeMiddleware(RequestHandlerABC):
    def __init__(self, next: RequestHandler):
        self.next = next
        LOG.info(f"Enabled { ', '.join(MINIMIZERS.keys())}")

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest):
        resp = self.next(conn_info, request)

        # Return if response has no body
        if not resp.body:
            return resp

        # Return if an encoding is applied
        if "Content-Encoding" in resp.headers:
            return resp

        # Return if no content type is present
        content_type, _, encoding = resp.headers.get("Content-Type", "").partition(
            "; charset="
        )
        encoding = encoding.strip().lower()
        content_type = content_type.strip().lower()
        if not content_type:
            return resp

        # Default encoding to utf-8
        if not encoding:
            encoding = "utf-8"

        # Return if no minimizer exists
        minimizer = MINIMIZERS.get(content_type, None)
        if not minimizer:
            return resp

        try:
            if isinstance(resp.body, BytesBody):
                # Directly minimize bytes bodies
                resp.body.content = minimizer(
                    resp.body.content.decode(encoding)
                ).encode(encoding)
            elif isinstance(resp.body, FileBody):
                # Convert file bodies to bytes bodies for minimization
                with resp.body.file_path.open("rb") as f:
                    resp.body = ResponseBody.from_bytes(
                        minimizer(f.read().decode(encoding)).encode(encoding)
                    )
        except Exception as exc:
            LOG.warning("Skipping minimizer due to exception", exc_info=exc)
            pass

        return resp
