"""
作业第一天
打开文件，读取首尾的二进制数据
"""
import os
from typing import Union

ET = "\n"  # convert backslash for f-string


def read_bytes_head_tail(
    filepath: str, length: int = 64, /
) -> tuple[list[int], list[int]]:
    """
    读取指定长度的文件的开头和结尾定长的二进制字节数据
    返回开头的二进制数据、结尾的二进制数据
    """
    if length <= 0:
        return [], []

    with open(filepath, "rb") as f:
        head = list(f.read(length))
        f.seek(-64, 2)
        tail = list(f.read(64))

    return head, tail


def hex_show_data(data: list[Union[int, None]], line_len: int = 16, /):
    """
    十六进制展示，第一列为行号，每行默认展示 16 个字节
    None 将会跳过展示
    每 8 列一个竖线，方便查看
    """
    assert line_len >= 1

    for i, byte_int in enumerate(data):
        # 第一列行号
        if i % line_len == 0:
            print(f"{ET if i else ''}{i // line_len:0>8b}", end="")
        # 每 8 列一个竖线，方便查看
        elif i and (i % line_len) % 8 == 0:
            print(" |", end="")
        # 具体数据
        print("   " if byte_int is None else f" {byte_int:0>2X}", end="")
    print()


def main():
    filepath = "./data_01.jpg"  # 要读取的文件路径
    read_length = 64  # 读取头尾的长度
    show_line_length = 16  # 展示的时候每行多长
    head, tail = read_bytes_head_tail(filepath, read_length)
    f_size = os.path.getsize(filepath)
    print(f"文件大小：{f_size}B")
    print("第一种，结尾字节左端对齐")
    hex_show_data(head + tail, show_line_length)
    print("第二种，结尾字节原样对齐")
    print(f"结尾偏移量：{f_size % show_line_length}")
    hex_show_data(head + [None] * (f_size % show_line_length) + tail, show_line_length)


if __name__ == "__main__":
    main()


#
#                  结果
#

# 文件大小：172190B
# 第一种，结尾字节左端对齐
# 00000000 FF D8 FF E0 00 10 4A 46 | 49 46 00 01 01 00 00 01
# 00000001 00 01 00 00 FF DB 00 43 | 00 06 04 05 06 05 04 06
# 00000010 06 05 06 07 07 06 08 0A | 10 0A 0A 09 09 0A 14 0E
# 00000011 0F 0C 10 17 14 18 18 17 | 14 16 16 1A 1D 25 1F 1A
# 00000100 A0 02 8A 28 A0 02 8A 28 | A0 02 8A 28 A0 02 8A 28
# 00000101 A0 02 9B 45 14 00 51 45 | 14 00 51 45 14 00 51 45
# 00000110 14 00 51 45 14 00 51 45 | 14 00 51 45 14 00 51 45
# 00000111 14 00 51 45 14 01 FF D9 | D3 7E C3 65 00 00 00 00
# 第二种，结尾字节原样对齐
# 结尾偏移量：14
# 00000000 FF D8 FF E0 00 10 4A 46 | 49 46 00 01 01 00 00 01
# 00000001 00 01 00 00 FF DB 00 43 | 00 06 04 05 06 05 04 06
# 00000010 06 05 06 07 07 06 08 0A | 10 0A 0A 09 09 0A 14 0E
# 00000011 0F 0C 10 17 14 18 18 17 | 14 16 16 1A 1D 25 1F 1A
# 00000100                         |                   A0 02
# 00000101 8A 28 A0 02 8A 28 A0 02 | 8A 28 A0 02 8A 28 A0 02
# 00000110 9B 45 14 00 51 45 14 00 | 51 45 14 00 51 45 14 00
# 00000111 51 45 14 00 51 45 14 00 | 51 45 14 00 51 45 14 00
# 00001000 51 45 14 01 FF D9 D3 7E | C3 65 00 00 00 00
