"""类型转换相关"""


def mac2str(mac: bytes, /) -> str:
    return mac.hex("-").upper()


def ip2str(ip: bytes, fill: str = " ", /) -> str:
    """IPv6 使用简写输出"""
    if len(ip) == 4:
        res = ".".join(str(i) for i in ip)
        if fill:
            res = res.ljust(15, fill)
    else:
        # IPv6 使用简写
        res = []
        # 先找出里面连续长度最长的 0
        is_new, zero_cnt, zero_pos = True, 0, None
        max_zero_cnt, max_zero_pos = 0, None
        for i in range(0, 16, 2):
            bytes2 = ip[i : i + 2]
            if bytes2 == b"\x00\x00":
                if is_new:
                    zero_pos = i
                    is_new = False
                zero_cnt += 1
                if zero_cnt > max_zero_cnt:
                    max_zero_cnt, max_zero_pos = zero_cnt, zero_pos
            elif is_new is False:
                is_new, zero_cnt, zero_pos = True, 0, None
            res.append(f"{bytes2int(bytes2):X}")
        # 找出 0 后将其删掉
        if max_zero_pos is not None:
            max_zero_pos //= 2
            res = res[:max_zero_pos] + [""] + res[max_zero_pos + max_zero_cnt :]
            if max_zero_pos + max_zero_cnt == 8:
                res += [""]
        if max_zero_pos == 0:
            res = [""] + res
        res = ":".join(res)
        if fill:
            res = res.ljust(39, fill)
    return res


def ipmac2str(ip: bytes, mac: bytes, fill: str = " ", /) -> str:
    res = f"{ip2str(ip, '')}({mac2str(mac)})"
    if fill:
        res = res.ljust(34, fill)
    return res


def bytes2int(bytes_data: bytes, byteorder="big") -> int:
    return int.from_bytes(bytes_data, byteorder)
