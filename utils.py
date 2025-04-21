"""
Utils module for the project."""
import os
from datetime import datetime
import re


def check_directory_and_subdirectory(path):
    """
    Check if the specified path is a directory that contains subdirectories, which means this CVE is unecessary to be fetched under the append mode."""
    # 判断指定路径是否为存在的目录
    if os.path.isdir(path):
        # 列出目录下的所有文件和目录
        items = os.listdir(path)
        # 遍历检查是否存在子目录
        for item in items:
            item_path = os.path.join(path, item)
            if os.path.isdir(item_path):
                return True  # 存在子目录
        return False  # 没有子目录
    else:
        return False  # 目录不存在


def compare_iso8601_with_validation(time_str1: str, time_str2: str) -> bool:
    """
    比较两个 ISO 8601 格式的时间字符串，返回布尔值，表示第一个时间是否早于第二个时间。
    同时验证输入字符串是否合法。
    参数:
        time_str1 (str): 第一个 ISO 8601 时间字符串
        time_str2 (str): 第二个 ISO 8601 时间字符串
    返回:
        bool: True 表示 time_str1 早于 time_str2，False 表示否则
    异常:
        ValueError: 如果时间字符串不符合 ISO 8601 格式
    """
    # 定义 ISO 8601 时间格式的正则表达式
    iso8601_regex = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$"
    # 验证时间字符串格式是否正确
    if not re.match(iso8601_regex, time_str1):
        raise ValueError(f"Invalid ISO 8601 format: {time_str1}")
    if not re.match(iso8601_regex, time_str2):
        raise ValueError(f"Invalid ISO 8601 format: {time_str2}")
    # 将字符串解析为 datetime 对象
    time1 = datetime.fromisoformat(time_str1.replace("Z", "+00:00"))
    time2 = datetime.fromisoformat(time_str2.replace("Z", "+00:00"))
    # 返回比较结果
    return time1 < time2


# 示例调用
try:
    time1 = "2025-04-20T01:37:25.860000Z"
    time2 = "2017-08-21T00:00:00Z"
    result = compare_iso8601_with_validation(time1, time2)
    print(result)  # 输出: False
except ValueError as e:
    print(e)
