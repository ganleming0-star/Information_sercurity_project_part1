import ipaddress
from typing import Literal


class TCPAddress:
    def __init__(self, ip: str, port: int):
        if not isinstance(port, int) or port < 0 or port > 65535:
            raise ValueError("Invalid port")

        if not isinstance(ip, str) or not ip:
            raise ValueError("Invalid IP")

        self.__ipversion: Literal[4, 6] = ipaddress.ip_address(ip).version
        self.__ip = ip
        self.__port = port

    @property
    def ip(self) -> str:
        return self.__ip

    @property
    def ip_version(self) -> Literal[4, 6]:
        return self.__ipversion

    @property
    def port(self) -> int:
        return self.__port

    def __str__(self):
        if self.__ipversion == 6:
            return f"[{self.__ip}]:{self.__port}"
        return f"{self.__ip}:{self.__port}"
