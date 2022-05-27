import struct

from utils.classes import Getitem
from utils.convert import ip2str


class ARP(Getitem):
    MAP = {}  # 映射表，同一线程下自动存储，使用类属性调用之
    TYPE_ASK = 1  # 请求
    TYPE_RES = 2  # 应答

    def __post_init__(self):
        self.mac_len = mac_len = self[4]  # mac 地址长度
        self.ip_len = ip_len = self[5]  # ip 地址长度
        self.type = struct.unpack(">h", self[6:8])[0]  # type: int  # 1 请求，2 应答
        addr = self[8 : 8 + 2 * mac_len + 2 * ip_len]  # 地址数据
        self.source_mac = addr[:mac_len]
        self.source_ip = addr[mac_len : mac_len + ip_len]
        self.destination_mac = addr[mac_len + ip_len : 2 * mac_len + ip_len]
        self.destination_ip = addr[2 * mac_len + ip_len : 2 * (mac_len + ip_len)]
        ARP.MAP[self.source_ip] = self.source_mac
        if self.type == self.TYPE_RES:
            ARP.MAP[self.destination_ip] = self.destination_mac

    def show(self) -> str:
        if self.type == self.TYPE_ASK:
            return (
                f"[ARP请求] {(self.source_ip, self.source_mac)}"
                f" 查询 {ip2str(self.destination_ip)} 的MAC地址在哪里"
            )
        else:
            return (
                f"[ARP响应] {(self.source_ip, self.source_mac)}"
                f" 回复 {(self.destination_ip, self.destination_mac)}"
                f"： {ip2str(self.source_ip)} 的MAC地址在我这里"
            )
