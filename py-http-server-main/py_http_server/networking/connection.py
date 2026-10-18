from ..networking.connection_info import ConnectionInfo
from ..networking.connection_socket import ConnectionSocket, GracefulDisconnectException
from ..common import RequestHandler
from ..http.request import HTTPRequest
from .. import log
import threading

LOG = log.getLogger("connection")


class ConnectionThread(threading.Thread):
    def __init__(
        self,
        conn: ConnectionSocket,
        handler: RequestHandler,
    ):
        super().__init__()
        self.__conn = conn
        self.__handler = handler
        self.__disposed = False

    @staticmethod
    def __get_connection_policy(req: HTTPRequest):
        if req.version == "HTTP/1.0":
            # "close" by default unless "keep-alive" specified
            if req.headers.get("connection", None) != "keep-alive":
                return "close"
        elif req.version == "HTTP/1.1":
            # "close" only if "close" specified
            if req.headers.get("connection", None) == "close":
                return "close"
        return "keep-alive"

    def run(self):
        if self.__disposed:
            raise RuntimeError("Cannot run a disposed ConnectionThread")

        conn_info = ConnectionInfo(
            self.__conn.remote_address, self.__conn.remote_address, self.__conn.has_ssl
        )

        try:
            while True:
                # Read request from socket
                req = HTTPRequest.receive_from(self.__conn)
                LOG.info(f"({self.__conn.remote_address}) {req}")

                # Execute the handler chain
                resp = self.__handler(conn_info, req)
                conn_policy = self.__get_connection_policy(req)
                resp.headers["Connection"] = conn_policy

                # Send the response
                resp.send_to(self.__conn, req.version)

                # Close the connection if necessary
                if conn_policy == "close":
                    break
        except (GracefulDisconnectException, ConnectionResetError, ConnectionAbortedError):
            # Disconnection is not an error
            pass
        except Exception as exc:
            # Suppress error messages on dispose() call
            if not self.__disposed:
                LOG.exception(
                    f"({self.__conn.remote_address}) Error in ConnectionThread",
                    exc_info=exc,
                )

        self.dispose()

    @property
    def disposed(self):
        return self.__disposed

    def dispose(self):
        if not self.__disposed:
            self.__disposed = True
            self.__conn.close()
            LOG.debug(f"({self.__conn.remote_address}) Closed connection.")
