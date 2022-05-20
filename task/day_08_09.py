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
[ARP响应] 192.168.1.2(3C-5A-20-1B-7F-00) 回复 192.168.1.1(6D-47-5E-2A-6C-9A)：
    192.168.1.2 的MAC地址在我这里

最后输出IP和MAC地址映射表：
IP地址  MAC地址
192.168.1.1 6D-47-5E-2A-6C-9A
192.168.1.2 3C-5A-20-1B-7F-00
······

完结版依赖项目的版本： c030bf3ce3ebd2de842bd495e455f3427ede04d6
（有对项目内其他模块的依赖，记录下版本，方便以后运行）
"""
# 如果不是在 Pycharm 里，打开下面三行注释
# import os
# import sys
# sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import mmap

from protocol.pcap import Pcap
from protocol.type import EthType

if __name__ == "__main__":
    with open("./data_day_08.pcap", "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            pcap = Pcap(item_api=m, item_api_offset=0)
            for packet in pcap.parse_payload():
                if packet.eth_type is not EthType.ARP:
                    continue
                arp = packet.parse_payload()
                print(arp.show())

# 结果
# [ARP请求] 10.92.53.51(00-0C-29-7C-02-CA)     查询 10.92.53.1      的MAC地址在哪里
# [ARP请求] 10.92.53.51(00-0C-29-7C-02-CA)     查询 10.92.53.1      的MAC地址在哪里
# [ARP请求] 10.92.53.51(00-0C-29-7C-02-CA)     查询 10.92.53.1      的MAC地址在哪里
# [ARP请求] 10.92.53.51(00-0C-29-7C-02-CA)     查询 10.92.53.1      的MAC地址在哪里
# [ARP请求] 10.92.53.51(00-0C-29-7C-02-CA)     查询 10.92.53.1      的MAC地址在哪里
# [ARP请求] 10.92.53.51(00-0C-29-7C-02-CA)     查询 10.92.53.1      的MAC地址在哪里
# [ARP请求] 10.92.52.1(38-AD-8E-6C-1D-1B)      查询 10.92.53.36     的MAC地址在哪里
# [ARP请求] 10.92.52.1(38-AD-8E-6C-1D-1B)      查询 10.92.53.36     的MAC地址在哪里
# [ARP请求] 10.92.52.1(38-AD-8E-6C-1D-1B)      查询 10.92.53.36     的MAC地址在哪里
# [ARP请求] 10.92.52.1(38-AD-8E-6C-1D-1B)      查询 10.92.52.255    的MAC地址在哪里
# [ARP请求] 10.92.53.51(00-0C-29-7C-02-CA)     查询 10.92.53.87     的MAC地址在哪里
# [ARP响应] 10.92.53.87(00-0C-29-84-37-07)     回复 10.92.53.51(00-0C-29-7C-02-CA)： 10.92.53.87 的MAC地址在我这里
# [ARP请求] 10.92.52.1(38-AD-8E-6C-1D-1B)      查询 10.92.52.38     的MAC地址在哪里
# [ARP请求] 10.92.52.1(38-AD-8E-6C-1D-1B)      查询 10.92.52.38     的MAC地址在哪里
# [ARP请求] 10.92.52.1(38-AD-8E-6C-1D-1B)      查询 10.92.52.38     的MAC地址在哪里
# [ARP请求] 10.92.53.51(00-0C-29-7C-02-CA)     查询 10.92.52.1      的MAC地址在哪里
# [ARP响应] 10.92.52.1(38-AD-8E-6C-1D-1B)      回复 10.92.53.51(00-0C-29-7C-02-CA)： 10.92.52.1 的MAC地址在我这里
# [ARP请求] 10.92.80.1(38-AD-8E-6C-1D-21)      查询 10.92.81.5      的MAC地址在哪里
# [ARP请求] 10.92.80.1(38-AD-8E-6C-1D-21)      查询 10.92.81.5      的MAC地址在哪里
# [ARP请求] 10.92.80.1(38-AD-8E-6C-1D-21)      查询 10.92.81.5      的MAC地址在哪里
