from protocol.base import Protocol


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

    def show(self):
        return (
            f"{self.source_port:<5}->{self.destination_port:<5}"
            f" {self.total_len:>3} Bytes"
        )
