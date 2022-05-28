from protocol.dns import Dns
from utils.convert import bytes2int


class Tcp:
    def __init__(self, data: bytes, offset: int):
        self.data = data
        self.offset = offset

    @property
    def source_port(self) -> int:
        return bytes2int(self.data[self.offset : self.offset + 2])

    @property
    def destination_port(self) -> int:
        return bytes2int(self.data[self.offset + 2 : self.offset + 4])

    @property
    def HEADER_LEN(self) -> int:  # 首部长度，单位字节
        return (self.data[self.offset + 12] >> 4) * 4

    def parse_payload(self):
        if self.source_port == 53 or self.destination_port == 53:
            return Dns(data=self.data, offset=self.offset + self.HEADER_LEN)

    def show(self):
        return f"[TCP] {self.source_port}  ->  {self.destination_port}"
