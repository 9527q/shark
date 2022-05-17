"""类相关的功能"""
from dataclasses import dataclass


@dataclass
class GetitemBase:
    """
    具有索引、切片功能数据型基类（必须用非负数）
    索引接口、偏移量等必须在实例生成时指定
    """

    BASE_OFFSET = 0  # 基础偏移量

    item_api: bytes  # 数据切片接口
    item_api_offset: int  # 数据切片接口偏移量

    def __getitem__(self, item):
        if isinstance(item, slice):
            start = (item.start or 0) + self.BASE_OFFSET + self.item_api_offset
            if (stop := item.stop) is not None:
                stop += self.BASE_OFFSET + self.item_api_offset
            item = slice(start, stop)
        else:
            item += self.BASE_OFFSET + self.item_api_offset

        return self.item_api[item]
