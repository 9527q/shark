from utils.convert import bytes2int, ip2str


class Arp:
    MAP = {}  # 映射表，同一线程下自动存储，使用类属性调用之

    def __init__(self, data: bytes, offset: int):
        self.data = data
        self.offset = offset
        self.mac_len = self.data[self.offset + 4]
        self.ip_len = self.data[self.offset + 5]
        self.type = bytes2int(self.data[self.offset + 6 : self.offset + 8])  # 1 请求，2 应答

    @property
    def source_ip(self) -> bytes:
        return self.data[
            self.offset
            + 8
            + self.mac_len : self.offset
            + 8
            + self.mac_len
            + self.ip_len
        ]

    @property
    def source_mac(self) -> bytes:
        return self.data[self.offset + 8 : self.offset + 8 + self.mac_len]

    @property
    def destination_mac(self) -> bytes:
        return self[8 + self.mac_len + self.ip_len : 8 + 2 * self.mac_len + self.ip_len]

    @property
    def destination_ip(self) -> bytes:
        return self.data[
            self.offset
            + 8
            + 2 * self.mac_len
            + self.ip_len : self.offset
            + 8
            + 2 * (self.mac_len + self.ip_len)
        ]

    def parse_payload(self):
        Arp.MAP[self.source_ip] = self.source_mac
        if self.type == 2:
            Arp.MAP[self.destination_ip] = self.destination_mac

    def show(self) -> str:
        if self.type == 1:
            return f"查询 {ip2str(self.destination_ip)} 的MAC地址"
        else:
            return f"响应 {ip2str(self.source_ip)} 的MAC地址"
