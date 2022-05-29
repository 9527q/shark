"""packet capture"""
import mmap
import struct
from struct import unpack
from datetime import datetime
from typing import Iterator, Union

from protocol.arp import Arp
from protocol.ip import Ipv4, Ipv6
from utils.convert import mac2str

TYPE_MAP = {b"\x08\x00": Ipv4, b"\x08\x06": Arp, b"\x86\xdd": Ipv6, b"\x88\xcc": "LLDP"}


class Pcap:
    HEADER_LEN = 24
    PACKET_HEADER_LEN = 16
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
                self.data,
                index,
                self.unpack_tag,
            )
            yield packet
            index += packet.total_len

    def iterate_packet2(self, up_types):
        """
        生成器，返回 时间戳、数据长度、源mac、目的mac、上层协议对象
        :param up_types: 想要的上层协议类型
        """
        index = self.HEADER_LEN
        unpack_tag = self.MAGIC_2_UNPACK_ACCURACY[self.data[:4]][0]
        unpack_tag += "L"
        data = self.data
        total_len = self.total_len
        while index < total_len:
            tp = data[index + 28 : index + 30]
            cap_len = unpack(unpack_tag, data[index + 8 : index + 12])[0]

            if tp <= b"\x05\xdc":
                index += cap_len + 16
                continue

            cls = TYPE_MAP[tp]
            if cls not in up_types:
                index += cap_len + 16
                continue

            up_type = cls(data=data, offset=index + 30)

            time_stamp = unpack(unpack_tag, data[index : index + 4])[0]
            source_mac = data[index + 22 : index + 28]
            destination_mac = data[index + 16 : index + 22]

            yield time_stamp, cap_len, source_mac, destination_mac, up_type
            index += cap_len + 16


TYPE_MAP2 = {
    b"\x08\x00": Ipv4,
    b"\x08\x06": Arp,
    b"\x86\xDD": Ipv6,
}


class Packet:
    HEADER_LEN = 16  # header 长度

    def __init__(self, data, offset, unpack_tag: str):
        """
        :param unpack_tag: 二进制解码标识（@=<>!）
        :param accuracy: 时间精度
        """
        self.data = data
        self.offset = offset
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
        if cls := TYPE_MAP2.get(self.data[self.offset + 28 : self.offset + 30]):
            return cls(data=self.data, offset=self.offset + 30)

    def show(self) -> str:
        return "[%s] %sBytes %s %s".format(
            self.time,
            self.cap_len,
            mac2str(self.source_mac),
            mac2str(self.destination_mac),
        )
