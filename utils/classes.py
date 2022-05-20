"""类相关的功能"""
from dataclasses import dataclass
from typing import Union


@dataclass
class GetitemDataclass:
    """具有索引、切片功能的数据型基类（只能用非负数）"""

    item_api: Union[bytes, str, list, tuple]  # 数据切片接口
    item_api_offset: int  # 数据切片接口偏移量

    def __getitem__(self, item):
        if isinstance(item, slice):
            start = (item.start or 0) + self.item_api_offset
            if (stop := item.stop) is not None:
                stop += + self.item_api_offset
            item = slice(start, stop)
        else:
            item += self.item_api_offset

        return self.item_api[item]
