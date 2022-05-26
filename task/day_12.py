"""
第12-13天

任务
    解析DNS协议报文

参考资料
    DNS协议详解及报文格式分析：DNS协议详解及报文格式分析 - 程序员大本营

作业
    编程解析第8-9天的pcap文件，遍历文件中的所有数据包，打印所有DNS协议
    数据包时间、长度信息、源MAC地址、目的MAC地址、源IP地址、目的IP地址
    、源端口、目的端口、DNS请求/响应、查询的域名、解析的结果（响应包，如果有多个，用逗号拼在一起）

示例
总计124个数据包：
[2022-01-12 15:00:01] 548Bytes 3C-5A-20-1B-7F-00 6D-47-5E-2A-6C-9A
    192.168.1.100 192.168.1.2 5000 53 DNS请求 www.baidu.com
[2022-01-12 15:00:03] 1024Bytes 3C-5A-20-1B-7F-00 6D-47-5E-2A-6C-9A
    192.168.1.100 192.168.1.4 32006 67 DNS响应 www.qq.com 125.56.75.20
······
最后输出域名和IP地址的映射表：
域名  IP地址
www.baidu.com 220.196.14.25
www.qq.com 156.254.36.10
······

完结版依赖项目的版本： a4128c9595a3533a16d7b0274bfd8b0fb665fa67
（有对项目内其他模块的依赖，记录下版本，方便以后运行）
"""
# 如果不是在 Pycharm 里，打开下面三行注释
# import os
# import sys
# sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mmap

from protocol.dns import Dns
from protocol.ip import Ipv4, Ipv6
from protocol.pcap import Pcap
from protocol.tcp import Tcp
from protocol.udp import Udp
from utils.convert import ip2str


def main(mmap_obj: mmap.mmap):
    pcap = Pcap(item_api=mmap_obj, item_api_offset=0, total_len=mmap_obj.size())

    # 遍历 Packet 寻找 DNS 报文
    for packet in pcap.iterate_packet():
        ip = packet.parse_payload()
        if not isinstance(ip, (Ipv4, Ipv6)):  # 必须是 IPv4、IPv6
            continue
        tcp_udp = ip.parse_payload()
        if not isinstance(tcp_udp, (Tcp, Udp)):  # 必须是 TCP/UDP
            continue
        dns = tcp_udp.parse_payload()
        if not isinstance(dns, Dns):  # 必须是 DNS
            continue

        # 依次输出 Packet、IP、TCP/UDP、DNS
        print(packet.show())
        print(ip.show("", tab_cnt=1))
        print(tcp_udp.show(tab_cnt=2))
        print(dns.show(tab_cnt=3))
        print("-" * 100)

    # 输出所有的 DNS 缓存结果
    print("")
    print("域名".ljust(50), "IP地址")
    for domain, ip_address in Dns.iterate_cache_domain_address():
        print(domain.ljust(50), ip2str(ip_address))


if __name__ == "__main__":
    with open("data_day_12.pcap", "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            main(m)
