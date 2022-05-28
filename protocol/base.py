"""
一些和协议相关的基础东西

- 项目只涉及读，没有写，保存好读接口即可，不要在内存中拷贝数据
- 不要定义类型类，直接用协议类充当类型
- 一个模块只放一类协议
- 底层协议可以 import 上层协议
- 底层协议到上层协议的对应、转换、配置等，一律放在底层协议本身及其 parse_payload 中
"""
from typing import Union

from utils.classes import classproperty


class Protocol:
    """所有协议都继承自此类，声明了一些基础方法，子类可以重写之"""

    # 类型名称，默认类名大写，是一个类属性
    TYPE_NAME = classproperty(lambda cls: cls.__name__.upper())
    HEADER_LEN = 0  # 首部长度，单位字节

    def parse_payload(self):  # 解析载荷
        return type("未实现", (Protocol,), {})(**self.gen_getitem_kw(self.HEADER_LEN))

    def gen_getitem_kw(self, offset=0):
        """得到 Getitem 类所需要的关键字参数"""
        return {
            "item_api": self.item_api,
            "item_api_offset": self.item_api_offset + offset,
        }

    def __init__(
        self,
        *,
        item_api: Union[bytes, str, list, tuple],
        item_api_offset: int = 0,
    ):
        self.item_api = item_api
        self.item_api_offset = item_api_offset

    def __getitem__(self, item):
        if isinstance(item, slice):
            if (stop := item.stop) is not None:
                stop += self.item_api_offset
            return self.item_api[self.item_api_offset + (item.start or 0) : stop]
        else:
            return self.item_api[self.item_api_offset + item]
