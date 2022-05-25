"""
第10天

任务
    解析UDP协议报文

参考资料
    UDP协议分析：UDP协议分析 - ls_cherish的个人空间 - OSCHINA - 中文开源技术交流社区

作业
    编程解析第8-9天的pcap文件，遍历文件中的所有数据包，打印所有UDP协议数据包时间、长度信息、目的MAC地址、源MAC地址
    、源IP地址、目的IP地址、源端口、目的端口、UDP数据长度

示例
总计124个数据包：
[2022-01-12 15:00:01] 548Bytes 3C-5A-20-1B-7F-00 6D-47-5E-2A-6C-9A
    192.168.1.100 192.168.1.2 5000 53 510Bytes
[2022-01-12 15:00:03] 1024Bytes 3C-5A-20-1B-7F-00 6D-47-5E-2A-6C-9A
    192.168.1.100 192.168.1.4 32006 67 980Bytes
······

完结版依赖项目的版本： b5060a2b0d6074711ab9eb5c3de9c8b2251dd2db
（有对项目内其他模块的依赖，记录下版本，方便以后运行）
"""
# 如果不是在 Pycharm 里，打开下面三行注释
# import os
# import sys
# sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mmap
from collections import defaultdict

from protocol.ip import Ipv4, Ipv6
from protocol.pcap import Pcap
from protocol.udp import Udp
from utils.convert import ip2str


def main(mmap_obj: mmap.mmap):
    pcap = Pcap(item_api=mmap_obj, item_api_offset=0, total_len=mmap_obj.size())
    for packet in pcap.iterate_packet():
        ip = packet.parse_payload()
        # 只管 IP 协议的
        if not isinstance(ip, (Ipv4, Ipv6)):
            continue
        udp = ip.parse_payload()
        if not isinstance(udp, Udp):
            continue
        print(packet.show(), ip.TYPE_NAME, udp.TYPE_NAME)


if __name__ == "__main__":
    with open("data_day_10.pcap", "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            main(m)
