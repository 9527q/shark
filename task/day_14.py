"""
第一阶段收官竞赛

任务
    解析第8-9天的pcap文件，遍历文件中的所有数据包，解析以太网、IP协议、ARP协议、UDP协议、DNS协议，解析结果分别输出到4个文件：
        ● arp.txt
        ● ip.txt
        ● udp.txt
        ● dns.txt

按以下格式输出
    arp.txt
        [时间] 数据包长度 源MAC地址 目的MAC地址 ARP请求内容/ARP响应内容
        示例
            [2022-01-12 15:00:01] 548Bytes 3C-5A-20-1B-7F-00 6D-47-5E-2A-6C-9A
                查询192.168.1.2的MAC地址
            [2022-01-12 15:00:01] 548Bytes 3C-5A-20-1B-7F-00 6D-47-5E-2A-6C-9A
                响应192.168.1.2的MAC地址
    ip.txt
        [时间] 数据包长度 源MAC地址 目的MAC地址 源IP地址 目的IP地址
        示例：
            [2022-01-12 15:00:01] 548Bytes 3C-5A-20-1B-7F-00 6D-47-5E-2A-6C-9A
                192.168.1.100 192.168.1.4
    udp.txt
        [时间] 数据包长度 源MAC地址 目的MAC地址 网络层协议名 源IP地址 目的IP地址 源端口 目的端口
        示例：
            [2022-01-12 15:00:01] 548Bytes 3C-5A-20-1B-7F-00 6D-47-5E-2A-6C-9A
                IPv4 192.168.1.100 192.168.1.4 32006 67
    dns.txt
        [时间] 数据包长度 源MAC地址 目的MAC地址 网络层协议名 源IP地址 目的IP地址 源端口 目的端口 DNS包类型 请求内容/响应内容
        示例：
            [2022-01-12 15:00:01] 548Bytes 3C-5A-20-1B-7F-00 6D-47-5E-2A-6C-9A
                IPv4 192.168.1.100 192.168.1.4 32006 67
                    DNS请求 查询域名www.baidu.com的地址
            [2022-01-12 15:00:01] 548Bytes 3C-5A-20-1B-7F-00 6D-47-5E-2A-6C-9A
                IPv4 192.168.1.100 192.168.1.4 32006 67
                    DNS响应 域名www.baidu.com的地址是220.195.20.10

注意
    对于同时包含多层协议的，都需要输出。
    比如一个DNS数据包，需要同时在ip.txt、udp.txt、dns.txt中出现。

优化程序，追求性能和准确率两项指标
    性能：在启动解析时打印时间戳，在解析结束时再打印时间戳，计算解析耗费的时间（精确到毫秒）
    准确率：将分别统计查阅四个文件的输出内容是否完备和准确。

完结版依赖项目的版本： 0fe490bbda986bf53c3a73546d1cb635987f9eb0
（有对项目内其他模块的依赖，记录下版本，方便以后运行）
"""
# 如果不是在 Pycharm 里，打开下面三行注释
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mmap
from datetime import datetime
from struct import unpack
from typing import Callable

from protocol.arp import Arp
from protocol.dns import Dns
from protocol.ip import Ipv4
from protocol.pcap import Pcap
from utils.convert import ipv42str, mac2str
from utils.debug import show_run_time


def make_1g_file():
    """用 12 天的 pcap 文件生成一个 1G 的数据"""
    pcap_1 = "data_day_12.pcap"
    pcap_2 = "data_day_14.pcap"
    with open(pcap_1, "rb") as f1, open(pcap_2, "wb") as f2:
        f2.write(f1.read())
        f1.seek(24)
        content = f1.read()
        for i in range(2000):
            f2.write(content)


@show_run_time
# python -m cProfile -s cumulative  day_14.py
# @profile  # kernprof -l -v day_14.py
def parse_pcap(
    pcap_mm: mmap.mmap,
    arp_write: Callable,
    ip_write: Callable,
    udp_write: Callable,
    dns_write: Callable,
):
    unpack_tag = Pcap.gen_unpack_tag(pcap_mm[:4]) + "L"
    index = 24
    total_len = pcap_mm.size()

    while index < total_len:
        index_30 = index + 30
        header = pcap_mm[index:index_30]
        tp = header[28:30]
        cap_len = unpack(unpack_tag, header[8:12])[0]

        # IPv4
        if tp == b"\x08\x00":
            ts = unpack(unpack_tag, header[:4])[0]
            dest_mac = header[16:22]
            source_mac = header[22:28]

            ipv4 = Ipv4(pcap_mm, index_30)
            ip_str = (
                f"[{datetime.fromtimestamp(ts)}] {cap_len}Bytes"
                f" {mac2str(source_mac)} {mac2str(dest_mac)}"
                f" IPv4 {ipv42str(ipv4.source_ip)} {ipv42str(ipv4.destination_ip)}\n"
            )
            ip_write(ip_str)

            # UDP
            if ipv4.header[9] == 17:
                udp_offset = ipv4.offset + ipv4.HEADER_LEN
                source_port, dest_port = unpack(">HH", pcap_mm[udp_offset : udp_offset + 4])
                udp_str = f"{ip_str[:-1]} {source_port} {dest_port}\n"
                udp_write(udp_str)

                # DNS
                if source_port == 53 or dest_port == 53:
                    dns = Dns(pcap_mm, udp_offset + 8)
                    dns_write(f"{udp_str[:-1]} {dns.show()}\n")

        # ARP
        elif tp == b"\x08\x06":
            ts = unpack(unpack_tag, header[:4])[0]
            dest_mac = header[16:22]
            source_mac = header[22:28]

            arp = Arp(pcap_mm[index_30 : index + 16 + cap_len])
            arp_write(
                f"[{datetime.fromtimestamp(ts)}] {cap_len}Bytes"
                f" {mac2str(source_mac)} {mac2str(dest_mac)} {arp.show()}\n"
            )

        index += cap_len + 16


if __name__ == "__main__":
    pcap_n = "data_day_14.pcap"
    with open(pcap_n) as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        with open("arp.txt", "w") as arp_f, open("ip.txt", "w") as ip_f:
            with open("udp.txt", "w") as udp_f, open("dns.txt", "w") as dns_f:
                parse_pcap(
                    mm,
                    arp_write=arp_f.write,
                    ip_write=ip_f.write,
                    udp_write=udp_f.write,
                    dns_write=dns_f.write,
                )

# 结果
# 函数 parse_pcap 开始：2022-05-29 22:33:24.297295
# 函数 parse_pcap 结束：2022-05-29 22:33:37.823202
# 函数 parse_pcap 耗时：13.526 秒