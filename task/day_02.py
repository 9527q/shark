"""
作业第二天
使用内存映射文件的方式，读取文件首尾的二进制数据
文件：链接: https://pan.baidu.com/s/1_fui_cTk9WvyxOqmqk7oyw 提取码: nho7

对内存映射文件的理解：
用内存映射磁盘空间上的文件，读写都能直接作用于磁盘，
在 Py 中使用时具有类文件、类 bytearray 的效果，
由于读写时绕开了系统调用和缓冲池等，所以速度很快
"""
import mmap


def read_bytes_head_tail(
    filepath: str, length: int = 64, /
) -> tuple[bytes, bytes]:
    """
    读取指定长度的二进制文件的开头和结尾数据
    """
    if length <= 0:
        return b"", b""

    with open(filepath, "rb") as f:
        with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
            return m[:64], m[-64:]


def hex_show_data(data: bytes, line_len: int = 16, /):
    """
    十六进制展示，第一列为行号，每 8 列一个竖线，每行默认展示 16 个字节
    """
    assert line_len >= 1

    et = "\n"  # convert enter for f-string
    for i, byte_int in enumerate(data):
        if i % line_len == 0:
            print(f"{et if i else ''}{i // line_len:0>8b}", end="")
        elif i and (i % line_len) % 8 == 0:
            print(" |", end="")
        print(f" {byte_int:0>2X}", end="")
    print()


if __name__ == "__main__":
    head, tail = read_bytes_head_tail("./data_02.jpg", 64)
    hex_show_data(head + tail, 16)
