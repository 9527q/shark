"""类型转换相关"""
import struct


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


def gen_unpack_func(unpack_fmt_head_tag: str):
    """
    生成一个解码函数，用法和 struct.unpack 一样，但是头格式已经写好了
    :param unpack_fmt_head_tag: struct.unpack 的 fmt 的头格式（@=<>!）
    """

    def unpack(fmt: str, data: bytes) -> tuple:
        return struct.unpack(unpack_fmt_head_tag + fmt, data)

    return unpack
