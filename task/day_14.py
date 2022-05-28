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
from typing import Any, Callable

from protocol.arp import Arp
from protocol.dns import Dns
from protocol.ip import Ip
from protocol.pcap import Pcap
from protocol.udp import Udp
from utils.debug import show_run_time


@show_run_time
def main(
    pcap_mm: mmap.mmap,
    arp_write: Callable[[str], Any],
    ip_write: Callable[[str], Any],
    udp_write: Callable[[str], Any],
    dns_write: Callable[[str], Any],
):
    pcap = Pcap(item_api=pcap_mm, total_len=pcap_mm.size())

    for packet in pcap.iterate_packet():
        arp_or_ip = packet.parse_payload()
        if isinstance(arp_or_ip, Arp):  # ARP
            arp_write(f"{packet.show()} {arp_or_ip.show()}\n")
        elif isinstance(arp_or_ip, Ip):
            packet_str = packet.show()
            ip_str = arp_or_ip.show()
            ip_write(f"{packet_str} {ip_str}\n")
            udp = arp_or_ip.parse_payload()
            if isinstance(udp, Udp):  # UDP
                udp_show = f"{packet_str} {arp_or_ip.TYPE_NAME} {ip_str} {udp.show()}\n"
                udp_write(udp_show)
                dns = udp.parse_payload()
                if isinstance(dns, Dns):  # DNS
                    dns_write(f"{udp_show[:-1]} {dns.show()}\n")


if __name__ == "__main__":
    pcap_n = "data_day_14.pcap"
    for _ in range(3):
        with open(pcap_n) as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
            with open("arp.txt", "w") as arp_f, open("ip.txt", "w") as ip_f:
                with open("udp.txt", "w") as udp_f, open("dns.txt", "w") as dns_f:
                    main(
                        mm,
                        arp_write=arp_f.write,
                        ip_write=ip_f.write,
                        udp_write=udp_f.write,
                        dns_write=dns_f.write,
                    )

    # 用 12 天的 pcap 文件生成一个 1G 的数据
    # pcap_1 = "data_day_12.pcap"
    # with open(pcap_1, "rb") as f1, open(pcap_n, "wb") as f2:
    #     f2.write(f1.read())
    #     f1.seek(24)
    #     content = f1.read()
    #     for i in range(2000):
    #         f2.write(content)

# 结果
# 函数 main 开始：2022-05-28 12:50:55.856739
# 函数 main 结束：2022-05-28 12:51:47.154481
# 函数 main 耗时：51.298 秒
# item功能放到基类里
#   40.864 秒
#   40.600 秒
#   40.648 秒
# packet数据加载到内存中
#   40.439 秒
#   40.276 秒
#   40.211 秒
