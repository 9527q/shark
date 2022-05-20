"""packet capture"""
import struct
from dataclasses import dataclass
from datetime import datetime

from protocol.ethernet import ETH_TYPE_2_CLS
from protocol.type import EthType
from utils.classes import Getitem
from utils.convert import mac2str


class Pcap(Getitem):
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
                    item_api=self.item_api,
                    item_api_offset=index,
                    time_stamp=time_stamp,
                    cap_len=cap_len,
                    len=length,
                    **{"microsecond" if self.accuracy == 6 else "nanosecond": min_s},
                )
            )
            index += Packet.HEADER_LEN + cap_len
        return packet_list


@dataclass
class Packet(Getitem):
    HEADER_LEN = 16  # header 长度

    time_stamp: int  # 时间戳
    cap_len: int  # Pcap 捕获的长度
    len: int  # 网络中传递的长度
    microsecond: int = None  # 微秒，微秒与纳秒两个必须且只能传递一个
    nanosecond: int = None  # 纳秒

    def __post_init__(self):
        self.payload = Getitem(self.item_api, self.item_api_offset + self.HEADER_LEN)
        self.time = datetime.fromtimestamp(self.time_stamp)  # 没有微秒和纳秒的时间
        self.accuracy_second = self.microsecond or self.nanosecond or 0  # 精确的秒
        self.accuracy = 6 if self.nanosecond is None else 9  # 秒精度
        self.destination_mac = self.payload[:6]
        self.source_mac = self.payload[6:12]
        self.eth_type = EthType.from_value(self.payload[12:14])

    def parse_payload(self):
        if parse_cls := ETH_TYPE_2_CLS.get(self.eth_type):
            return parse_cls(self.item_api, self.item_api_offset + self.HEADER_LEN + 14)

    def show(self) -> str:
        return (
            f"[{self.time}]"
            f" {self.len:4} Bytes"
            f"  {mac2str(self.destination_mac)}"
            f"  {mac2str(self.source_mac)}"
            f"  {self.eth_type.name:10}"
        )
