from dataclasses import dataclass
from ..networking.address import TCPAddress


@dataclass(frozen=True)
class ConnectionInfo:
    remote_address: TCPAddress
    local_address: TCPAddress
    secure: bool
