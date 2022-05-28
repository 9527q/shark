from typing import Union

from protocol.base import Protocol
from protocol.defining import Icmp
from protocol.tcp import Tcp
from protocol.udp import Udp
from utils.convert import bytes2int, ip2str

_UP_TYPE = Union[Udp, Tcp, Icmp]


class Ip(Protocol):
    TYPE_NAME = "IP"
    TYPE_MAP = {
        1: Icmp,
        6: Tcp,
        17: Udp,
    }

    source_ip: bytes
    destination_ip: bytes
    ttl: int

    def parse_payload(self) -> _UP_TYPE:
        """解析载荷"""

    def show(self) -> str:
        return f"{ip2str(self.source_ip)} {ip2str(self.destination_ip)}"


class Ipv4(Ip):
    TYPE_NAME = "IPv4"

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

    def parse_payload(self) -> _UP_TYPE:
        cls = self.TYPE_MAP[self.data[self.offset + 9]]
        return cls(data=self.data, offset=self.offset + self.HEADER_LEN)


class Ipv6(Ip):
    TYPE_NAME = "IPv6"
    HEADER_LEN = 40

    @property
    def source_ip(self) -> bytes:
        return self.data[self.offset + 8 : self.offset + 24]

    @property
    def destination_ip(self) -> bytes:
        return self.data[self.offset + 24 : self.offset + 40]

    def parse_payload(self) -> _UP_TYPE:
        cls = self.TYPE_MAP[self.data[self.offset + 6]]
        return cls(data=self.data, offset=self.offset + self.HEADER_LEN)
