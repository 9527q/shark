from typing import Union

from protocol.base import Protocol
from protocol.defining import Icmp, Tcp
from protocol.udp import Udp
from utils.convert import ip2str

_UP_TYPE = Union[Udp, Tcp, Icmp]


class Ipv4(Protocol):
    TYPE_NAME = "IPv4"
    TYPE_MAP = {
        1: Icmp,
        6: Tcp,
        17: Udp,
    }

    @property
    def source_ip(self) -> bytes:
        return self[12:16]

    @property
    def destination_ip(self) -> bytes:
        return self[16:20]

    @property
    def ttl(self) -> int:
        return self[8]

    @property
    def id(self) -> bytes:
        return self[4:6]

    def show(self) -> str:
        return (
            f"{ip2str(self.source_ip)}"
            f"  {ip2str(self.destination_ip)}"
            f"  {self.ttl:3}"
        )

    def parse_payload(self) -> _UP_TYPE:
        cls = self.TYPE_MAP[self[9]]
        return cls(**self.gen_getitem_kw())


class Ipv6(Protocol):
    TYPE_NAME = "IPv6"
