"""调试工具"""
import time
from datetime import datetime
from functools import wraps


def show_run_time(func):
    @wraps(func)
    def new_func(*args, **kwargs):
        start = time.time()
        res = func(*args, **kwargs)
        end = time.time()
        print(f"函数 {func.__name__} 开始：{datetime.fromtimestamp(start)}")
        print(f"函数 {func.__name__} 结束：{datetime.fromtimestamp(end)}")
        print(f"函数 {func.__name__} 耗时：{end-start:.3f} 秒")
        return res

    return new_func
