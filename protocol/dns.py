from collections import defaultdict
from functools import cached_property
from typing import Iterator, Union

from protocol.base import Protocol
from utils.convert import bytes2int, ip2str


class Dns(Protocol):
    """DNS，Domain Name System"""

    HEADER_LEN = 12  # 首部长度，单位字节
    DOMAIN_2_DATA: dict[str, set[str, bytes]] = defaultdict(set)  # 域名解析结果

    @property
    def qr(self) -> int:  # 0、1 查询、响应
        return self.data[self.offset + 2] >> 7

    @cached_property
    def query_cnt(self) -> int:  # 问题数，单位个
        return bytes2int(self.data[self.offset + 4 : self.offset + 6])

    @cached_property
    def answer_cnt(self) -> int:  # 回答数，单位个
        return bytes2int(self.data[self.offset + 6 : self.offset + 8])

    @property
    def query_domains(self) -> list[str]:  # 查询的域名
        res = []
        index = self.offset + 12
        for _ in range(self.query_cnt):
            domain, offset = self.parse_domain(index)
            res.append(domain)
            index += offset + 4  # 加上类型和类的长度
        return res

    def parse_answers(self) -> list[tuple[str, Union[str, bytes]]]:
        """解析应答信息，返回 RR域名 + RR数据 的列表"""
        if self.qr == 0:
            return []

        # 先通过查询部分找到响应部分的开始位置
        index = self.offset + self.HEADER_LEN
        for _ in range(self.query_cnt):
            index += self.parse_domain_payload_len(index) + 4

        res = []
        for _ in range(self.answer_cnt):
            domain, offset = self.parse_domain(index)
            index += offset  # 位置前进到域名后面
            tp = bytes2int(self.data[index : index + 2])  # RR 类型
            data_len = bytes2int(self.data[index + 8 : index + 10])  # 数据区长度
            index += 10  # 位置前进到当前 RR 的数据区
            if tp == 1:  # A 类型
                data = self.data[index : index + data_len]
            elif tp == 5:  # CNAME 类型
                data = self.parse_domain(index)[0]
            else:
                raise ValueError(f"不支持的解析类型：{tp}")
            Dns.DOMAIN_2_DATA[domain] = data  # 记录 RR
            res.append((domain, data))
            index += data_len  # 位置前进到下一个 RR 的开头
        return res

    def parse_domain(self, domain_offset: int) -> tuple[str, int]:
        """解析域名，返回域名、向后偏移量，偏移量单位字节"""
        index, zones = domain_offset, []
        while zone_len := self.data[index]:
            if zone_len >= 192:  # 高两位为1，压缩标签
                offset = bytes2int(self.data[index : index + 2]) - 49152  # 压缩目标地址
                zones.append(self.parse_domain(self.offset + offset)[0])
                index += 2  # 压缩标签占2个字节
                break
            else:
                zones.append(self.data[index + 1 : index + zone_len + 1].decode())
                index += zone_len + 1
        else:
            index += 1  # 没有压缩标签的，最后还有1个字节是0
        return ".".join(zones), index - domain_offset

    def parse_domain_payload_len(self, domain_offset: int) -> int:
        """解析域名载荷的长度，单位字节"""
        index = domain_offset
        while zone_len := self.data[index]:
            if zone_len >= 192:  # 高两位为1，压缩标签
                index += 2  # 压缩标签占2个字节
                break
            else:
                index += zone_len + 1
        else:
            index += 1  # 非压缩标签后面还有一个字节 0
        return index - domain_offset

    @staticmethod
    def iterate_cache_domain_address() -> Iterator[tuple[str, bytes]]:
        """迭代已经记录的 DNS 域名和地址"""
        for domain in Dns.DOMAIN_2_DATA:
            cname = domain
            while isinstance(data := Dns.DOMAIN_2_DATA[cname], str):
                cname = data
            yield domain, data

    def show(self):
        if self.qr == 0:
            return f"DNS请求 查询域名 {'，'.join(self.query_domains)} 的地址"
        else:
            domain, addrs = None, []
            for cname, addr in self.parse_answers():
                if domain is None:
                    domain = cname
                if isinstance(addr, bytes):
                    addrs.append(ip2str(addr))
            return f"DNS响应 域名 {domain} 的地址是 {'、'.join(addrs)}"
