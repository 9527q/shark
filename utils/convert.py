"""转换"""


def mac2str(mac: bytes) -> str:
    return "-".join(f"{i:02X}" for i in mac)


def ip2str(ip: bytes) -> str:
    return ".".join(str(i) for i in ip)
