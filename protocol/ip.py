import mmap
from typing import Union

from protocol.tcp import Tcp
from protocol.udp import Udp
from utils.convert import ipv42str, ipv62str

TYPE_MAP = {
    6: Tcp,
    17: Udp,
}


class Ipv4:
    TYPE_NAME = "IPv4"

    def __init__(self, data: Union[bytes, mmap.mmap], offset: int):
        self.data = data
        self.offset = offset
        self.header = data[offset : offset + 20]

    @property
    def HEADER_LEN(self) -> int:  # 首部长度，单位字节
        return (self.header[0] & 0b1111) * 4

    @property
    def ttl(self) -> int:
        return self.data[self.offset + 8]

    @property
    def source_ip(self) -> bytes:
        return self.header[12:16]

    @property
    def destination_ip(self) -> bytes:
        return self.header[16:20]

    def parse_payload(self) -> Union[Udp, Tcp]:
        if cls := TYPE_MAP.get(self.header[9]):
            return cls(data=self.data, offset=self.offset + self.HEADER_LEN)

    def show(self) -> str:
        return f"{ipv42str(self.source_ip)} {ipv42str(self.destination_ip)}"


class Ipv6:
    TYPE_NAME = "IPv6"
    HEADER_LEN = 40

    def __init__(self, data: bytes, offset: int):
        self.data = data
        self.offset = offset

    @property
    def source_ip(self) -> bytes:
        return self.data[self.offset + 8 : self.offset + 24]

    @property
    def destination_ip(self) -> bytes:
        return self.data[self.offset + 24 : self.offset + 40]

    def parse_payload(self) -> Union[Udp, Tcp]:
        if cls := TYPE_MAP.get(self.data[self.offset + 6]):
            return cls(data=self.data, offset=self.offset + self.HEADER_LEN)

    def show(self) -> str:
        return "%s %s".format(ipv62str(self.source_ip), ipv62str(self.destination_ip))
