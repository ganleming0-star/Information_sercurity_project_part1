from ..common import RequestHandler
from ..networking import ConnectionInfo
from ..networking.address import TCPAddress
from ..networking.connection import ConnectionThread
from ..networking.connection_socket import ConnectionSocket
from .. import log
import socket
import threading
import ssl

LOG = log.getLogger("listener")


class ListenerThread(threading.Thread):
    def __init__(
        self,
        socket: socket.socket,
        bind_address: TCPAddress,
        handler: RequestHandler,
    ):
        """
        Socket must already be in listening state.
        """
        super().__init__()
        self.__disposed = False
        self.__connections: list[ConnectionThread] = []
        self.__socket = socket
        self.__bind_address = bind_address
        self.__handler = handler

    def run(self):
        if self.__disposed:
            raise RuntimeError("Cannot run a disposed ListenerThread")

        try:
            while True:
                # Clean disposed connections
                self.__clean_old_connections()

                # Wait for a connection
                try:
                    # Wrap connection in ConnectionSocket
                    conn, _ = self.__socket.accept()
                    conn = ConnectionSocket(conn)
                except ssl.SSLError as exc:
                    # Ignore SSLErrors during handshake as logging them will be quite noisy
                    continue

                try:
                    self.__add_connection(conn)
                    LOG.debug(
                        f"({self.__bind_address}) Client connected from {conn.remote_address}"
                    )
                except Exception as exc:
                    conn.close()
                    LOG.exception(
                        f"({self.__bind_address}) Dropped connection from {conn.remote_address} due to error",
                        exc_info=exc,
                    )

        except Exception as exc:
            # Suppress error messages on dispose() call
            if not self.__disposed:
                LOG.exception(
                    f"({self.__bind_address}) Error in ListenerThread", exc_info=exc
                )

        self.dispose()

    def __add_connection(self, conn: ConnectionSocket):
        # Connection has to be wrapped with ConnectionSocket
        self.__connections.append(ConnectionThread(conn, self.__handler))
        self.__connections[-1].start()

    def __clean_old_connections(self):
        self.__connections = [c for c in self.__connections if not c.disposed]

    @property
    def disposed(self):
        return self.__disposed

    def dispose(self):
        if not self.__disposed:
            self.__disposed = True
            for connection in self.__connections:
                connection.dispose()

            # Try to shutdown the socket, this is required on Linux
            try:
                self.__socket.shutdown(socket.SHUT_RD)
            except:
                pass

            self.__socket.close()
            LOG.info(f"({self.__bind_address}) Closed listener.")

    @staticmethod
    def create(bind_address: TCPAddress, handler: RequestHandler):
        """
        Will throw if the address can't be bound to.
        This method exists to avoid having a constructor that can throw.
        """
        sock_family = (
            socket.AF_INET if bind_address.ip_version == 4 else socket.AF_INET6
        )
        sock = socket.create_server(
            (bind_address.ip, bind_address.port),
            family=sock_family,
        )
        sock.listen()

        thread = ListenerThread(sock, bind_address, handler)
        thread.start()
        return thread

    @staticmethod
    def create_ssl(
        bind_address: TCPAddress,
        handler: RequestHandler,
        keyfile,
        certfile,
    ):
        """
        Will throw if the address can't be bound to.
        This method exists to avoid having a constructor that can throw.
        """
        sock_family = (
            socket.AF_INET if bind_address.ip_version == 4 else socket.AF_INET6
        )
        sock = socket.create_server(
            (bind_address.ip, bind_address.port),
            family=sock_family,
        )

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.MAXIMUM_SUPPORTED
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)

        sock = context.wrap_socket(sock, server_side=True)
        sock.listen()

        thread = ListenerThread(sock, bind_address, handler)
        thread.start()
        return thread
