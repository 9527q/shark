from typing import Union

from protocol.tcp import Tcp
from protocol.udp import Udp
from utils.convert import bytes2int, ip2str

TYPE_MAP = {
    6: Tcp,
    17: Udp,
}


class Ipv4:
    TYPE_NAME = "IPv4"

    def __init__(self, data: bytes, offset: int):
        self.data = data
        self.offset = offset

    @property
    def HEADER_LEN(self) -> int:  # 首部长度，单位字节
        return (self.data[self.offset] & 0b1111) * 4

    @property
    def id(self) -> bytes:  # 标识
        return self[4:6]

    @property
    def fo(self) -> int:  # 片偏移
        return bytes2int(self[6:8]) & 0b1111111111111

    @property
    def flags(self) -> str:  # 分片标识
        return f"{self.data[self.offset+6] >> 5:03b}"

    @property
    def ttl(self) -> int:
        return self.data[self.offset + 8]

    @property
    def source_ip(self) -> bytes:
        return self.data[self.offset + 12 : self.offset + 16]

    @property
    def destination_ip(self) -> bytes:
        return self.data[self.offset + 16 : self.offset + 20]

    def parse_payload(self) -> Union[Udp, Tcp]:
        if cls := TYPE_MAP.get(self.data[self.offset + 9]):
            return cls(data=self.data, offset=self.offset + self.HEADER_LEN)

    def show(self) -> str:
        return f"{ip2str(self.source_ip)} {ip2str(self.destination_ip)}"


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
        return f"{ip2str(self.source_ip)} {ip2str(self.destination_ip)}"
