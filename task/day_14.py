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

完结版依赖项目的版本： 73c4e14b078036acdd38787a81e74694e6e27b09
（有对项目内其他模块的依赖，记录下版本，方便以后运行）
"""
# 如果不是在 Pycharm 里，打开下面三行注释
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mmap
from datetime import datetime
from typing import Any, Callable

from protocol.arp import Arp
from protocol.dns import Dns
from protocol.ip import Ipv4
from protocol.pcap import Pcap
from protocol.udp import Udp
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
def parse_pcap(
    pcap_mm: mmap.mmap,
    arp_write: Callable[[str], Any],
    ip_write: Callable[[str], Any],
    udp_write: Callable[[str], Any],
    dns_write: Callable[[str], Any],
):
    pcap = Pcap(data=pcap_mm, total_len=pcap_mm.size())

    for ts, cap_len, source_mac, dest_mac, up_type in pcap.iterate_packet2(
        up_types=(Arp, Ipv4)
    ):
        # for pkt in pcap.iterate_packet():
        # if isinstance(up_type, Arp):
        # up_type = pkt.parse_payload()
        if up_type.__class__ == Arp:
            arp_write(
                f"[{datetime.fromtimestamp(ts)}] {cap_len}Bytes {mac2str(source_mac)} {mac2str(dest_mac)} {up_type.show()}\n"
                # f"[{pkt.time}] {pkt.cap_len}Bytes {mac2str(pkt.source_mac)} {mac2str(pkt.destination_mac)} {up_type.show()}\n"
            )
        # elif isinstance(up_type, Ipv4):
        elif up_type.__class__ == Ipv4:
            ip_str = f"[{datetime.fromtimestamp(ts)}] {cap_len}Bytes {mac2str(source_mac)} {mac2str(dest_mac)} {up_type.TYPE_NAME} {ipv42str(up_type.source_ip)} {ipv42str(up_type.destination_ip)}"
            # ip_str = f"[{pkt.time}] {pkt.cap_len}Bytes {mac2str(pkt.source_mac)} {mac2str(pkt.destination_mac)} {up_type.TYPE_NAME} {ipv42str(up_type.source_ip)} {ipv42str(up_type.destination_ip)}"
            ip_write(ip_str + "\n")

            udp = up_type.parse_payload()
            if isinstance(udp, Udp):  # UDP
                udp_str = f"{ip_str} {udp.source_port} {udp.destination_port}"
                udp_write(udp_str + "\n")

                dns = udp.parse_payload()
                if isinstance(dns, Dns):  # DNS
                    dns_write(f"{udp_str} {dns.show()}\n")


def main():
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


def run_main_times(times: int):
    for i in range(times):
        print(f"第 {i+1} 次")
        main()


if __name__ == "__main__":
    # main()  # python -m cProfile -s cumulative  day_14.py
    run_main_times(3)

# 结果
# 第 1 次
# 函数 parse_pcap 开始：2022-05-29 11:53:24.371089
# 函数 parse_pcap 结束：2022-05-29 11:53:43.036589
# 函数 parse_pcap 耗时：18.666 秒
# 第 2 次
# 函数 parse_pcap 开始：2022-05-29 11:53:43.123832
# 函数 parse_pcap 结束：2022-05-29 11:54:01.737296
# 函数 parse_pcap 耗时：18.613 秒
# 第 3 次
# 函数 parse_pcap 开始：2022-05-29 11:54:01.799089
# 函数 parse_pcap 结束：2022-05-29 11:54:20.469343
# 函数 parse_pcap 耗时：18.670 秒
