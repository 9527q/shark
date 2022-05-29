"""类型转换相关"""


def mac2str(mac: bytes, /) -> str:
    return mac.hex("-").upper()


def ipv42str(ipv4: bytes, /) -> str:
    return f"{ipv4[0]}.{ipv4[1]}.{ipv4[2]}.{ipv4[3]}"


def ipv62str(ipv6: bytes, /) -> str:
    res = []
    # 先找出里面连续长度最长的 0
    is_new, zero_cnt, zero_pos = True, 0, None
    max_zero_cnt, max_zero_pos = 0, None
    for i in range(0, 16, 2):
        bytes2 = ipv6[i : i + 2]
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
    return ":".join(res)


def ip2str(ip: bytes, /) -> str:
    if len(ip) == 4:
        return ipv42str(ip)
    return ipv62str(ip)


def bytes2int(bytes_data: bytes, byteorder="big") -> int:
    return int.from_bytes(bytes_data, byteorder)
