"""packet capture"""
import struct
from dataclasses import dataclass
from datetime import datetime

from protocol import IPv4
from protocol.type import EthType
from utils.classes import GetitemDataclass
from functools import cached_property


@dataclass
class Pcap(GetitemDataclass):
    MAGIC_2_UNPACK_ACCURACY = {  # Pcap 的 Magic 对应的大小端模式和时间精确度
        b"\xa1\xb2\xc3\xd4": (">", 6),  # 大端，微秒 6 位精度
        b"\xa1\xb2\x3c\x4d": (">", 9),  # 大端，纳秒 9 位精度
        b"\xd4\xc3\xb2\xa1": ("<", 6),  # 小端，微秒 6 位精度
        b"\x4d\x3c\xb2\xa1": ("<", 9),  # 小端，纳秒 9 位精度
    }

    def __post_init__(self):
        self.unpack_tag, self.accuracy = self.MAGIC_2_UNPACK_ACCURACY[self[:4]]

    def unpack(self, fmt: str, data: bytes) -> tuple:
        """根据格式解析二进制数据"""
        return struct.unpack(self.unpack_tag + fmt, data)

    def parse_payload(self) -> list["Packet"]:
        packet_list = []
        index = 24
        while header := self[index : index + Packet.HEADER_LEN]:
            time_stamp, min_s, cap_len, length = self.unpack("llll", header)
            packet_list.append(
                Packet(
                    time_stamp=time_stamp,
                    cap_len=cap_len,
                    len=length,
                    item_api_offset=index,
                    item_api=self.item_api,
                    **{"microsecond" if self.accuracy == 6 else "nanosecond": min_s},
                )
            )
            index += Packet.HEADER_LEN + cap_len
        return packet_list


@dataclass
class Packet(GetitemBase):
    HEADER_LEN = 16  # header 长度

    time_stamp: int  # 时间戳
    cap_len: int  # Pcap 捕获的长度
    len: int  # 网络中传递的长度
    microsecond: int = None  # 微秒，微秒与纳秒两个必须且只能传递一个
    nanosecond: int = None  # 纳秒

    @cached_property
    def payload(self):
        return GetitemBase(item_api=self.item_api, item_api_offset=self.item_api_offset+self.HEADER_LEN)

    @property
    def time(self) -> datetime:  # 没有微秒和纳秒的时间
        return datetime.fromtimestamp(self.time_stamp)

    @property
    def accuracy_second(self) -> int:  # 精确的秒
        return self.microsecond if self.nanosecond is None else self.nanosecond

    @property
    def accuracy(self) -> int:  # 秒精确位数
        return 6 if self.nanosecond is None else 9

    @property
    def destination_mac(self) -> bytes:
        return self.payload[:6]

    @property
    def source_mac(self) -> bytes:
        return self.payload[6:12]

    @property
    def eth_type(self) -> EthType:
        return EthType.parse(self.payload[12:14])

    def parse_payload(self):
        """解析载荷，目前仅支持 IPv4"""
        if self.eth_type is not EthType.IPV4:
            return
        return IPv4(
            item_api=self.item_api,
            item_api_offset=self.item_api_offset + self.HEADER_LEN + 14,
        )
