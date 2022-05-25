"""
一些和协议相关的基础东西

- 项目只涉及读，没有写，保存好读接口即可，不要在内存中拷贝数据
- 不要定义类型类，直接用协议类充当类型
- 一个模块只放一类协议
- 底层协议可以 import 上层协议
- 底层协议到上层协议的对应、转换、配置等，一律放在底层协议本身及其 parse_payload 中
"""
from functools import cached_property

from utils.classes import Getitem, classproperty


class Protocol(Getitem):
    """
    所有协议都继承自此类，声明了一些基础方法，子类可以重写之
    """

    # 类型名称，默认类名大写，是一个类属性
    TYPE_NAME = classproperty(lambda cls: cls.__name__.upper())
    HEADER_LEN = 0  # 首部长度，单位字节

    @cached_property
    def payload(self):
        """载荷"""
        return Getitem(**self.gen_getitem_kw(self.HEADER_LEN))

    def parse_payload(self):
        """解析载荷"""
