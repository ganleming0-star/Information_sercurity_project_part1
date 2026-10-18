from ..networking import ConnectionInfo
from ..http.request import HTTPRequest
from ..http.response import HTTPResponse, HTTPResponseFactory, ResponseBody
from ..middlewares._internal.file import (
    _HEADToGETMiddleware,
    _PreconditionEvalMiddleware,
)
from ..common import (
    RequestHandlerABC,
    HeaderContainer,
    NO_CACHE_HEADERS,
    file_etag,
    to_http_date,
)
from .. import log
from pathlib import Path
from datetime import datetime, timezone
import html
import mimetypes
import urllib.parse
import pkgutil

template_data = pkgutil.get_data(__name__, "../templates/index.html")
if not template_data:
    raise RuntimeError("Couldn't load template from package.")
INDEX_TEMPLATE = template_data.decode("utf-8")
LOG = log.getLogger("routers.file")


class FileRouter(RequestHandlerABC):
    def __init__(
        self,
        document_root: str,
        generate_index: bool = True,
        enable_etag: bool = True,
        enable_last_modified: bool = True,
        disable_symlinks: bool = True,
    ):
        """Inits FileRouter.

        Args:
        document_root -- Document root.
        generate_index -- If True, generated index pages will be served for directories.
        enable_etag -- If True, ETag will be calculated and sent with every response.
        enable_last_modified -- If True, Last-Modified header will be sent with every response.
        disable_symlinks -- If True, symlinks won't be followed.

        WARNING: Enabling symlinks may lead to unexpected results with authentication middlewares.
        E.g. "/protected_folder" vs "/folder/../protected_folder"
        """
        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)
        self.__document_root = Path(document_root).resolve()
        self.__generate_index = generate_index
        self.__enable_etag = enable_etag
        self.__enable_last_modified = enable_last_modified
        self.__disable_symlinks = disable_symlinks

        self.__chain = _PreconditionEvalMiddleware(
            _HEADToGETMiddleware(
                lambda conn_info, request: self.__actual_call(conn_info, request)
            )
        )

    def __is_path_allowed(self, path: Path):
        resolved_path = path.resolve()
        if self.__disable_symlinks:
            if path != resolved_path:
                return False

        # Resolved path must be within document root
        return resolved_path.is_relative_to(self.__document_root)

    def __get_content_type(self, path: Path):
        mime_type, encoding = mimetypes.guess_type(path, False)
        if not mime_type:
            return "application/octet-stream"
        if not encoding:
            return mime_type
        return f"{mime_type}; charset={encoding}"

    # Gets the file last_modified time with second resolution for comparison with HTTP dates
    def __get_last_modified(self, path: Path) -> datetime:
        value = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        return value.replace(microsecond=0)

    def __serve_file(self, path: Path):
        """RFC9110: The server generating a 304 response MUST generate
        any of the following header fields that would have been sent
        in a 200 (OK) response to the same request:
            Content-Location, Date, ETag, and Vary
            Cache-Control and Expires (see [CACHING])
        """
        LOG.debug(f'Reading file "{path}"')

        headers = HeaderContainer()
        if self.__enable_etag:
            headers["ETag"] = file_etag(path)

        if self.__enable_last_modified:
            headers["Last-Modified"] = to_http_date(self.__get_last_modified(path))

        headers["Content-Type"] = self.__get_content_type(path)
        return HTTPResponse(200, headers, ResponseBody.from_file(path))

    def __serve_index(self, conn_info: ConnectionInfo, path: Path):
        # Turns any path into an absolute web path (relative to document root)
        make_link = lambda p: urllib.parse.quote(
            "/" + p.relative_to(self.__document_root).as_posix()
        )
        # Escapes text for embedding within HTML
        make_text = lambda x: html.escape(str(x))

        # Pretty path relative to document root
        title = path.relative_to(self.__document_root).as_posix()
        title = f"/{title}" if title != "." else "/"

        table_items = []

        def add_table_item(link="", name="", type="", last_modified="", size=""):
            name, type, last_modified, size = (
                make_text(name),
                make_text(type),
                make_text(last_modified),
                make_text(size),
            )
            table_items.append(
                f'<tr><td><a href="{link}">{name}</a></td><td>{type}</td><td>{last_modified}</td><td>{size}</td></tr>'
            )

        if path.parent != path and self.__is_path_allowed(path.parent):
            # Display the parent path if possible
            add_table_item(make_link(path.parent), "..", "Symlink")

        for sub_path in path.iterdir():
            stat = sub_path.stat()
            size = ""
            if sub_path.is_dir():
                type = "Folder"
            elif sub_path.is_file():
                type = "File"
                size = f"{stat.st_size} bytes"
            elif sub_path.is_symlink():
                type = "Symlink"
            else:
                continue

            last_mod = to_http_date(
                datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            )
            add_table_item(make_link(sub_path), sub_path.name, type, last_mod, size)

        return self.http.html(
            INDEX_TEMPLATE.replace("{table_items}", "".join(table_items))
            .replace("{title}", make_text(title))
            .replace(
                "{footer}",
                make_text(
                    f"Generated on {to_http_date(datetime.now(timezone.utc))} for {conn_info.remote_address}"
                ),
            )
        )

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest):
        return self.__chain(conn_info, request)

    def __actual_call(self, conn_info: ConnectionInfo, request: HTTPRequest):
        if request.method != "GET":
            # Method not allowed
            return self.http.status(405)

        # Append the path to document root
        # https://bugs.python.org/issue44452
        path = self.__document_root.joinpath(request.path.lstrip("/"))

        # Prevent path traversal and optionally forbid symlinks
        if not self.__is_path_allowed(path):
            LOG.warning(f"Path not allowed: {path}")
            return self.http.status(400)

        try:
            if path.is_file():
                return self.__serve_file(path)
            elif path.is_dir():
                index_html = path.joinpath("index.html")
                if index_html.is_file():
                    return self.__serve_file(index_html)
                elif self.__generate_index:
                    # Generate index if allowe and there is no index.html
                    return self.__serve_index(conn_info, path)
        except Exception as exc:
            LOG.exception("Error while accesing path", exc_info=exc)
            return self.http.status(500)

        return self.http.status(404)
