from protocol.base import Protocol
from protocol.dns import Dns
from utils.convert import bytes2int


class Tcp(Protocol):
    """TCP"""

    @property
    def source_port(self) -> int:
        return bytes2int(self[:2])

    @property
    def destination_port(self) -> int:
        return bytes2int(self[2:4])

    @property
    def HEADER_LEN(self) -> int:  # 首部长度，单位字节
        return (self[12] >> 4) * 4

    def parse_payload(self):
        if self.source_port == 53 or self.destination_port == 53:
            return Dns(**self.gen_getitem_kw(self.HEADER_LEN))
        return super().parse_payload()

    def show(self, tab_cnt=0):
        t = "\t" * tab_cnt
        return f"{t}[TCP] {self.source_port}  ->  {self.destination_port}"
