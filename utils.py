"""
Utils module for the project."""
import os


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
