"""类型转换相关"""
def mac2str(mac: bytes, fill: str = " ", /) -> str:
    res = "-".join(f"{i:02X}" for i in mac)
    if fill:
        res = res.ljust(17, fill)
    return res


def ip2str(ip: bytes, fill: str = " ", /) -> str:
    res = ".".join(str(i) for i in ip)
    if fill:
        res = res.ljust(15, fill)
    return res


def ipmac2str(ip: bytes, mac: bytes, fill: str = " ", /) -> str:
    res = f"{ip2str(ip, '')}({mac2str(mac, '')})"
    if fill:
        res = res.ljust(34, fill)
    return res
