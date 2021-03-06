from mmap import mmap
from typing import Union

from protocol.dns import Dns
from utils.convert import bytes2int


class Udp:

    HEADER_LEN = 8

    def __init__(self, data: Union[bytes, mmap], offset: int):
        self.data = data
        self.offset = offset

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

    def show(self):
        return f"{self.source_port} {self.destination_port}"
