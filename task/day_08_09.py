"""
第 8 天作业

解析ARP协议报文

编程解析下面的pcap文件，遍历文件中的所有数据包，解析其中的ARP请求包与响应包，输出里面的查询和响应包信息。

文件地址
链接: day8.pcap_免费高速下载|百度网盘-分享无限制
我转存的：链接: data_day_08.pcap_免费高速下载|百度网盘-分享无限制

输出格式
[ARP请求] 谁 查询 某个IP 的MAC地址在哪里
[ARP响应] 谁 回复 谁 某个IP 的MAC地址在我这里

示例
[ARP请求] 192.168.1.1(6D-47-5E-2A-6C-9A) 查询 192.168.1.2 的MAC地址在哪里
[ARP响应] 192.168.1.2(3C-5A-20-1B-7F-00) 回复 192.168.1.1(6D-47-5E-2A-6C-9A)：192.168.1.2 的MAC地址在我这里

最后输出IP和MAC地址映射表：
IP地址  MAC地址
192.168.1.1 6D-47-5E-2A-6C-9A
192.168.1.2 3C-5A-20-1B-7F-00
······

完结版依赖项目的版本：TODO
（有对项目内其他模块的依赖，记录下版本，方便以后运行）
"""
import datetime
import mmap
import struct
from dataclasses import dataclass
from functools import cached_property
from typing import Optional, Union

from utils.classes import GetitemBase
from utils.protocol import EthType, IpUpType


def mac2str(mac: bytes) -> str:
    return "-".join(f"{i:02X}" for i in mac)


def ip2str(ip: bytes) -> str:
    return ".".join(str(i) for i in ip)


class Ipv4(GetitemBase):
    eth_type = EthType.IPV4

    @property
    def source_ip(self) -> bytes:
        return self[12:16]

    @property
    def destination_ip(self) -> bytes:
        return self[16:20]

    @property
    def ttl(self) -> int:
        return self[8]

    @property
    def up_type(self) -> IpUpType:
        return IpUpType(self[9])

    def __str__(self):
        return (
            f"{ip2str(self.source_ip):15}"
            f"  {ip2str(self.destination_ip):15}"
            f"  {self.ttl:3}"
            f"  {self.up_type.name}"
        )


@dataclass
class Packet(GetitemBase):
    HEADER_LEN = GETITEM_BASE_OFFSET = 16  # header 长度

    time_second_stamp: int  # 秒时间戳
    microsecond: int  # 微秒
    cap_len: int
    len: int

    @property
    def time(self) -> datetime.datetime:
        dt = datetime.datetime.fromtimestamp(self.time_second_stamp)
        return dt.replace(microsecond=self.microsecond)

    @property
    def destination_mac(self) -> bytes:
        return self[:6] if self.len > 5 else None

    @property
    def source_mac(self) -> bytes:
        return self[6:12] if self.len > 11 else None

    @cached_property
    def eth_type(self) -> Optional[EthType]:
        if self.len < 14:
            return
        if (tag := self[12:14]) <= b"\x05\xDC":  # 1500 及以下，IEEE 802.3
            return EthType.IEEE_802_3
        elif tag >= b"\x06\x00":  # 1536 及以上，Ethernet II
            return EthType(tag)

    def parse_payload(self):
        """解析载荷，目前仅支持 IPv4"""
        if self.eth_type is not EthType.IPV4:
            return
        return Ipv4(
            item_api=self.item_api,
            item_api_offset=self.item_api_offset + self.HEADER_LEN + 14,
        )

    def __str__(self):
        return (
            f"[{self.time}]"
            f" {self.len:4} Bytes"
            f"  {mac2str(self.destination_mac)}"
            f"  {mac2str(self.source_mac)}"
            f"  {self.eth_type.name:10}"
        )


class Pcap:
    HEADER_LEN = 24  # header 长度
    MODE_2_STRUCT_UNPACK = {
        b"\xa1\xb2\xc3\xd4": ">",  # 大端模式标识
        b"\xd4\xc3\xb2\xa1": "<",  # 小端模式标识
    }

    def __init__(self, pcap_file_path):
        self.pcap_path = pcap_file_path
        self.f = open(self.pcap_path, "rb")
        self.m = mmap.mmap(
            self.f.fileno(), 0, access=mmap.ACCESS_READ
        )  # type: Union[mmap.mmap, bytes]

        # 检查文件大小和大小端模式
        self.size = self.m.size()
        if self.size < self.HEADER_LEN:
            raise ValueError(f"文件数据过短（{self.size}B），解析 Pcap 头部失败")
        self.mode_tag = self.m[:4]
        self.struct_tag = self.MODE_2_STRUCT_UNPACK.get(self.mode_tag)
        if not self.struct_tag:
            raise ValueError(f"不认识的 Pcap 标识：{self.mode_tag.hex()}")

        self._packet_list = []  # Packet 列表

    def __del__(self):
        self.m.close()
        self.m = None
        self.f.close()
        self.f = None

    def unpack(self, fmt: str, data: bytes) -> tuple:
        """根据格式解析二进制数据"""
        return struct.unpack(self.struct_tag + fmt, data)

    def parse_payload(self):
        if self._packet_list:
            return

        index = self.HEADER_LEN
        while index < self.size:
            header = self.m[index : index + Packet.HEADER_LEN]
            time_stamp, micro_s, cap_len, length = self.unpack("llll", header)
            self._packet_list.append(
                Packet(
                    time_second_stamp=time_stamp,
                    microsecond=micro_s,
                    cap_len=cap_len,
                    len=length,
                    item_api=self.m,
                    item_api_offset=index,
                )
            )
            index += Packet.HEADER_LEN + length

    @cached_property
    def packet_list(self) -> list[Packet]:
        self.parse_payload()
        return self._packet_list


if __name__ == "__main__":
    pcap = Pcap("./data_day_08.pcap")
    packet_list = pcap.packet_list
    print(f"总计 {len(packet_list)} 个数据包：")
    for packet in packet_list:
        print(packet, packet.parse_payload() or "")
