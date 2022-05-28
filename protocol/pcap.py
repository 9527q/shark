"""packet capture"""
import mmap
import struct
from datetime import datetime
from typing import Iterator, Union

from protocol.arp import Arp
from protocol.base import Protocol
from protocol.defining import Ieee802_3, Lldp, Rarp
from protocol.ip import Ipv4, Ipv6
from utils.convert import mac2str

_UP_TYPE = Union[Ieee802_3, Lldp, Rarp, Ipv6, Ipv4, Arp]


class Pcap(Protocol):
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
        super().__init__(data=data, offset=0)
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


class Packet(Protocol):
    HEADER_LEN = 16  # header 长度
    TYPE_MAP = {
        b"\x08\x00": Ipv4,
        b"\x08\x06": Arp,
        b"\x08\x35": Rarp,
        b"\x86\xDD": Ipv6,
        b"\x88\xcc": Lldp,
    }

    def __init__(self, unpack_tag: str, accuracy: int, **kwargs):
        """
        :param unpack_tag: 二进制解码标识（@=<>!）
        :param accuracy: 时间精度
        """
        super().__init__(**kwargs)
        self.accuracy = accuracy
        time_stamp, _, self.cap_len = struct.unpack(
            unpack_tag + "LLL", self.data[self.offset : self.offset + 12]
        )
        self.time = datetime.fromtimestamp(time_stamp)  # 没有微秒和纳秒的时间

    @property
    def total_len(self) -> int:  # 总长度，单位字节
        return self.HEADER_LEN + self.cap_len

    @property
    def destination_mac(self) -> bytes:
        return self.data[self.offset + 16 : self.offset + 22]

    @property
    def source_mac(self) -> bytes:
        return self.data[self.offset + 22 : self.offset + 28]

    def parse_payload(self) -> _UP_TYPE:
        if (
            tp := self.data[self.offset + 28 : self.offset + 30]
        ) <= b"\x05\xDC":  # 1500 及以下，IEEE 802.3
            cls = Ieee802_3
        else:
            cls = self.TYPE_MAP[tp]
        return cls(data=self.data, offset=self.offset + self.HEADER_LEN + 14)

    def show(self) -> str:
        return (
            f"[{self.time}] {self.cap_len}Bytes"
            f" {mac2str(self.source_mac)}"
            f" {mac2str(self.destination_mac)}"
        )
