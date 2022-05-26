from protocol.base import Protocol
from protocol.dns import Dns
from utils.convert import bytes2int


class Udp(Protocol):
    """UDP User Datagram Protocol（用户数据报协议）"""

    HEADER_LEN = 8

    @property
    def source_port(self) -> int:
        return bytes2int(self[:2])

    @property
    def destination_port(self) -> int:
        return bytes2int(self[2:4])

    @property
    def total_len(self) -> int:  # 总长度，单位字节
        return bytes2int(self[4:6])

    def parse_payload(self) -> Dns:
        if self.source_port == 53 or self.destination_port == 53:
            return Dns(**self.gen_getitem_kw(self.HEADER_LEN))
        return super().parse_payload()

    def show(self, tab_cnt=0):
        t = "\t" * tab_cnt
        return f"{t}[UDP] {self.source_port}  ->  {self.destination_port}"
