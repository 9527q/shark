"""各种具体协议"""
from utils.classes import GetitemBase

from .type import EthType, IpUpType


class IPv4(GetitemBase):
    eth_type = EthType.IPV4

    soure_ip1 = property(lambda self: self[12:16])  # type: bytes

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
    def up_type(self) -> IpUpType:
        return IpUpType(self[9])


class ARP(GetitemBase):
    pass
