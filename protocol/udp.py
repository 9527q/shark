from protocol.base import Protocol
from protocol.dns import Dns


class Udp(Protocol):
    """UDP User Datagram Protocol（用户数据报协议）"""

    HEADER_LEN = 8

    @property
    def source_port(self) -> int:
        return int.from_bytes(self[:2], "big")

    @property
    def destination_port(self) -> int:
        return int.from_bytes(self[2:4], "big")

    @property
    def total_len(self) -> int:  # 总长度，单位字节
        return int.from_bytes(self[4:6], "big")

    def parse_payload(self) -> Dns:
        if self.source_port == 53 or self.destination_port == 53:
            return Dns(**self.gen_getitem_kw(self.HEADER_LEN))
        return super().parse_payload()

    def show(self):
        return f"[UDP] {self.source_port:<5}->{self.destination_port:<5}"
