from protocol.base import Protocol
from protocol.dns import Dns


class Tcp(Protocol):
    """TCP"""

    @property
    def source_port(self) -> int:
        return int.from_bytes(self[:2], "big")

    @property
    def destination_port(self) -> int:
        return int.from_bytes(self[2:4], "big")

    @property
    def HEADER_LEN(self) -> int:  # 首部长度，单位字节
        return (self[12] >> 4) * 4

    def parse_payload(self):
        if self.source_port == 53 or self.destination_port == 53:
            return Dns(**self.gen_getitem_kw(self.HEADER_LEN))
        return super().parse_payload()

    def show(self):
        return f"[TCP] {self.source_port:<5}->{self.destination_port:<5}"
