"""packet capture"""
import mmap
import struct
from datetime import datetime
from typing import Iterator, Union

from protocol.arp import Arp
from protocol.ip import Ipv4, Ipv6
from utils.convert import mac2str


class Pcap:
    HEADER_LEN = 24
    MAGIC_2_UNPACK_ACCURACY = {  # Pcap 的 Magic 对应的大小端模式和时间精确度
        b"\xa1\xb2\xc3\xd4": (">", 6),  # 大端，微秒 6 位精度
        b"\xa1\xb2\x3c\x4d": (">", 9),  # 大端，纳秒 9 位精度
        b"\xd4\xc3\xb2\xa1": ("<", 6),  # 小端，微秒 6 位精度
        b"\x4d\x3c\xb2\xa1": ("<", 9),  # 小端，纳秒 9 位精度
    }

    def __init__(self, data: Union[bytes, mmap.mmap], total_len: int):
        """
        :param total_len: 总长度，单位字节
        """
        self.data = data
        self.total_len = total_len
        # 二进制解析标识，时间精度
        self.unpack_tag, self.accuracy = self.MAGIC_2_UNPACK_ACCURACY[self.data[:4]]

    def iterate_packet(self) -> Iterator["Packet"]:
        index = self.HEADER_LEN
        while index < self.total_len:
            packet = Packet(
                self.unpack_tag,
                self.accuracy,
                data=self.data,
                offset=index,
            )
            yield packet
            index += packet.total_len

    def parse_payload(self) -> list["Packet"]:
        """临时使用建议用 iterate_packet"""
        return list(self.iterate_packet())


TYPE_MAP = {
    b"\x08\x00": Ipv4,
    b"\x08\x06": Arp,
    b"\x86\xDD": Ipv6,
}


class Packet:
    HEADER_LEN = 16  # header 长度

    def __init__(self, unpack_tag: str, accuracy: int, data, offset):
        """
        :param unpack_tag: 二进制解码标识（@=<>!）
        :param accuracy: 时间精度
        """
        self.data = data
        self.offset = offset
        self.accuracy = accuracy
        self.time_stamp, _, self.cap_len = struct.unpack(
            unpack_tag + "LLL", self.data[self.offset : self.offset + 12]
        )

    @property
    def time(self) -> datetime:
        return datetime.fromtimestamp(self.time_stamp)  # 没有微秒和纳秒的时间

    @property
    def total_len(self) -> int:  # 总长度，单位字节
        return self.cap_len + 16

    @property
    def destination_mac(self) -> bytes:
        return self.data[self.offset + 16 : self.offset + 22]

    @property
    def source_mac(self) -> bytes:
        return self.data[self.offset + 22 : self.offset + 28]

    def parse_payload(self) -> Union[Ipv6, Ipv4, Arp]:
        if cls := TYPE_MAP.get(self.data[self.offset + 28 : self.offset + 30]):
            return cls(data=self.data, offset=self.offset + 30)

    def show(self) -> str:
        return (
            f"[{self.time}] {self.cap_len}Bytes"
            f" {mac2str(self.source_mac)}"
            f" {mac2str(self.destination_mac)}"
        )
