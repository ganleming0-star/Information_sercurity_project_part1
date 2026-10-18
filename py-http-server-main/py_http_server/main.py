from typing import Optional
from .networking.listener import ListenerThread
from .networking.address import TCPAddress
from .common import RequestHandler
from . import log
import time

LOG = log.getLogger("main")


def app_main(
    handler_chain: RequestHandler,
    http_listeners: list[TCPAddress] = [],
    https_listeners: list[TCPAddress] = [],
    https_key_file: Optional[str] = None,
    https_cert_file: Optional[str] = None,
    log_level: str = "DEBUG",
):
    log.setLevel(log_level)
    try:
        if https_listeners and (not https_key_file or not https_cert_file):
            raise ValueError("Cannot create HTTP listeners without key and cert files")

        listeners: list[ListenerThread] = []

        # Create HTTP listeners
        for address in http_listeners:
            try:
                listeners.append(ListenerThread.create(address, handler_chain))
                LOG.info(f"New HTTP listener on {address}")
            except Exception as exc:
                LOG.exception(
                    f"Failed to create a HTTP listener on {address}", exc_info=exc
                )

        # Create HTTPS listeners
        for address in https_listeners:
            try:
                listeners.append(
                    ListenerThread.create_ssl(
                        address, handler_chain, https_key_file, https_cert_file
                    )
                )
                LOG.info(f"New HTTPS listener on {address}")
            except Exception as exc:
                LOG.exception(
                    f"Failed to create a HTTPS listener on {address}", exc_info=exc
                )

        try:
            while len(listeners) > 0:
                # Clean disposed listeners
                listeners = [l for l in listeners if not l.disposed]
                time.sleep(1)
        except KeyboardInterrupt:
            pass

        LOG.info("Exiting...")
        for listener in listeners:
            listener.dispose()
    except Exception as exc:
        LOG.fatal("Unrecoverable error", exc_info=exc)
    log.shutdown()
