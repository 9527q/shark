"""
第六天作业

编程解析第三天的 pcap 文件，遍历文件中的所有数据包，
在上一个作业的基础上，打印所有数据包时间、长度信息、目的MAC地址、源MAC地址、协议名称
"""
import datetime
import mmap
import struct
from dataclasses import dataclass
from enum import Enum, unique
from functools import cached_property
from typing import Union


def mac2str(mac: bytes) -> str:
    """mac 地址展示"""
    return "-".join(f"{i:X}" for i in mac)


@unique
class EthType(Enum):
    """协议类型"""

    IPV4 = b"\x08\x00"
    ARP = b"\x08\x06"
    RARP = b"\x08\x35"
    IPV6 = b"\x86\xDD"


@dataclass
class Packet:
    pcap: "Pcap"  # 所属的 Pcap
    payload_offset: int  # 数据区开始的位置
    time_second_stamp: int  # 秒时间戳
    microsecond: int  # 微秒
    cap_len: int
    len: int

    @cached_property
    def time(self) -> datetime.datetime:
        dt = datetime.datetime.fromtimestamp(self.time_second_stamp)
        return dt.replace(microsecond=self.microsecond)

    def __getitem__(self, i):
        if isinstance(i, slice):
            start = self.payload_offset + (i.start or 0)
            stop = None if i.stop is None else self.payload_offset + i.stop
            return self.pcap.m[start:stop]
        return self.pcap.m[i]

    @cached_property
    def d_mac(self) -> bytes:
        """目的 mac 地址"""
        return self[:6] if self.len > 5 else None

    @cached_property
    def s_mac(self) -> bytes:
        """源 mac 地址"""
        return self[6:12] if self.len > 11 else None

    @cached_property
    def type(self) -> EthType:
        return EthType(self[12:14]) if self.len > 13 else None


class Pcap:
    """Packet Capture"""

    PACKET_HEADER_LEN = 16  # packet 头长
    MODE_2_STRUCT_UNPACK = {
        b"\xa1\xb2\xc3\xd4": ">",  # 大端模式标识
        b"\xd4\xc3\xb2\xa1": "<",  # 小端模式标识
    }

    def __init__(self, pcap_path):
        self.pcap_path = pcap_path
        self.f = open(self.pcap_path, "rb")
        self.m = mmap.mmap(
            self.f.fileno(), 0, access=mmap.ACCESS_READ
        )  # type: Union[mmap.mmap, bytes]

        # 检查文件大小和大小端模式
        self.size = self.m.size()
        if self.size < 24:
            raise ValueError(f"文件数据过短（{self.size}B），解析 Pcap 头部失败")
        self.mode_tag = self.m[:4]
        self.struct_tag = self.MODE_2_STRUCT_UNPACK.get(self.mode_tag)
        if not self.struct_tag:
            raise ValueError(f"不认识的 Pcap 标识：{self.mode_tag}")

    def __del__(self):
        self.m.close()
        self.m = None
        self.f.close()
        self.f = None

    def unpack(self, fmt: str, data: bytes) -> tuple:
        """根据格式解析二进制数据"""
        return struct.unpack(self.struct_tag + fmt, data)

    @cached_property
    def packet_list(self) -> list[Packet]:
        index = 24
        result = []

        while index < self.size:
            header = self.m[index : index + self.PACKET_HEADER_LEN]
            time_stamp, micro_s, cap_len, length = self.unpack("llll", header)
            result.append(
                Packet(
                    pcap=self,
                    payload_offset=index + self.PACKET_HEADER_LEN,
                    time_second_stamp=time_stamp,
                    microsecond=micro_s,
                    cap_len=cap_len,
                    len=length,
                )
            )
            index += self.PACKET_HEADER_LEN + length
        return result


if __name__ == "__main__":
    pcap = Pcap("./data_06.pcap")
    packet_list = pcap.packet_list
    print(f"总计 {len(packet_list)} 个数据包： ")
    for p in packet_list:
        print(
            f"[{p.time}] {p.len} Bytes"
            f"\t{mac2str(p.d_mac)}"
            f"\t{mac2str(p.s_mac)}"
            f"\t{p.type.name}"
        )
