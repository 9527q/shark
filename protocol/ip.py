from typing import Union

from protocol.base import Protocol
from protocol.defining import Icmp
from protocol.tcp import Tcp
from protocol.udp import Udp
from utils.convert import ip2str

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

    def show(self, fill=" ") -> str:
        return (
            f"[{self.TYPE_NAME}]"
            f" {ip2str(self.source_ip, fill)}->{ip2str(self.destination_ip, fill)}"
        )


class Ipv4(Ip):
    TYPE_NAME = "IPv4"

    @property
    def HEADER_LEN(self) -> int:  # 首部长度，单位字节
        return (self[0] & 0b1111) * 4

    @property
    def id(self) -> bytes:  # 标识
        return self[4:6]

    @property
    def fo(self) -> int:  # 片偏移
        return int.from_bytes(self[6:8], "big") & 0b1111111111111

    @property
    def flags(self) -> str:  # 分片标识
        return f"{self[6] >> 5:03b}"

    @property
    def ttl(self) -> int:
        return self[8]

    @property
    def source_ip(self) -> bytes:
        return self[12:16]

    @property
    def destination_ip(self) -> bytes:
        return self[16:20]

    def parse_payload(self) -> _UP_TYPE:
        cls = self.TYPE_MAP[self[9]]
        return cls(**self.gen_getitem_kw(self.HEADER_LEN))


class Ipv6(Ip):
    TYPE_NAME = "IPv6"
    HEADER_LEN = 40

    @property
    def source_ip(self) -> bytes:
        return self[8:24]

    @property
    def destination_ip(self) -> bytes:
        return self[24:40]

    def parse_payload(self) -> _UP_TYPE:
        cls = self.TYPE_MAP[self[6]]
        return cls(**self.gen_getitem_kw(self.HEADER_LEN))
