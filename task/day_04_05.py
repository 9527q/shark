"""
第四、五天作业

编程解析第三天的 pcap 文件，遍历文件中的所有数据包，打印所有数据包时间、长度信息。
示例：
总计124个数据包：
[2022-01-12 15:00:01] 128 Bytes
[2022-01-12 15:00:02] 1064 Bytes
[2022-01-12 15:00:03] 1460 Bytes
······
"""
import datetime
import mmap
import struct
from dataclasses import dataclass
from typing import Union


@dataclass
class Packet:
    pcap: "Pcap"
    offset: int
    time_second_stamp: int
    microsecond: int
    cap_len: int
    len: int

    @property
    def time(self):
        return datetime.datetime.fromtimestamp(self.time_second_stamp)


class Pcap:
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
        return struct.unpack(self.struct_tag + fmt, data)

    @property
    def packet_list(self) -> list[Packet]:
        """packet"""
        index = 24
        size = self.m.size()
        result = []

        while index < size:
            time_second_stamp, microsecond, cap_len, length = self.unpack(
                "llll", self.m[index : index + 16]
            )
            result.append(
                Packet(
                    pcap=self,
                    offset=index,
                    time_second_stamp=time_second_stamp,
                    microsecond=microsecond,
                    cap_len=cap_len,
                    len=length,
                )
            )
            index += 16 + length
        return result


if __name__ == "__main__":
    pcap = Pcap("./data_04_05.pcap")
    package_list = pcap.packet_list
    print(f"总计 {len(package_list)} 个数据包： ")
    for package in package_list:
        print(f"[{package.time}] {package.len} Bytes")
