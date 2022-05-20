"""各种具体协议"""
from utils.classes import GetitemBase
from utils.convert import ip2str

from .type import EthType, IpUpType


class Ipv4(GetitemBase):
    eth_type = EthType.IPV4

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

    def __str__(self):
        return (
            f"{ip2str(self.source_ip):15}"
            f"  {ip2str(self.destination_ip):15}"
            f"  {self.ttl:3}"
            f"  {self.up_type.name}"
        )
