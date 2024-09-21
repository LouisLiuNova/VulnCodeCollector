"""
To stat the data and show it in the console
"""

from prettytable import PrettyTable
import os
from loguru import logger


def count_subdirectories(directory):
    subdirectory_info = {}

    for root, dirs, files in os.walk(directory):
        if root == directory:
            # 只处理第一层子目录
            for dir_name in dirs:
                sub_path = os.path.join(root, dir_name)
                # 检查子目录下是否还有子目录
                sub_dirs = next(os.walk(sub_path))[1]  # 获取子目录列表
                subdirectory_info[dir_name] = len(sub_dirs) > 0  # 记录是否有子目录

    return subdirectory_info


def stat():
    """
    to stat data saved at ./data and print it in a table
    """

    table = PrettyTable()
    data_path = "./data"
    result = count_subdirectories(data_path)
    CVEs_cnt = len(result)
    commits_cnt = sum(1 for has_subdirs in result.values() if has_subdirs)
    logger.info(f"Found {CVEs_cnt} CVEs and {
                commits_cnt} CVEs have source code in {data_path}")
