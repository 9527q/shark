"""类相关的功能"""
from typing import Union


class Getitem:
    """
    具有索引、切片功能的基类（只能用非负数或 None）
    只要继承此类并传入相应的参数，那么子类的实例即可具有索引、切片的能力
    :param item_api: 数据切片接口
    :param item_api_offset: 数据切片接口偏移量
    """

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


class classproperty(object):
    """
    将类方法变为类属性的描述符，目前只实现了 get 方法
    使用方法同 property，只是是对类方法使用，产生的属性是类属性
    """

    def __init__(self, fget=None):
        if fget is not None and not isinstance(fget, classmethod):
            fget = classmethod(fget)
        self.fget = fget

    def __get__(self, obj, objtype=None):
        if self.fget is None:
            raise AttributeError("unreadable attribute")
        return self.fget.__get__(obj, objtype)()

    def getter(self, fget):
        return type(self)(fget)
