from protocol.base import Protocol
from protocol.dns import Dns
from utils.convert import bytes2int


class Udp(Protocol):
    """UDP User Datagram Protocol（用户数据报协议）"""

    HEADER_LEN = 8

    @property
    def source_port(self) -> int:
        return bytes2int(self.data[self.offset : self.offset + 2])

    @property
    def destination_port(self) -> int:
        return bytes2int(self.data[self.offset + 2 : self.offset + 4])

    @property
    def total_len(self) -> int:  # 总长度，单位字节
        return bytes2int(self[4:6])

    def parse_payload(self) -> Dns:
        if self.source_port == 53 or self.destination_port == 53:
            return Dns(data=self.data, offset=self.offset + self.HEADER_LEN)
        return super().parse_payload()

    def show(self):
        return f"{self.source_port} {self.destination_port}"
