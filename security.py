"""
To save ansd retrive credentials locally
"""
import os
from dotenv import load_dotenv
from loguru import logger


def update_env_var(key, value, env_file='.env'):
    lines = []
    with open(env_file, 'r') as file:
        lines = file.readlines()

    with open(env_file, 'w') as file:
        for line in lines:
            if line.startswith(f"{key}="):
                file.write(f"{key}={value}\n")
            else:
                file.write(line)


def load_env_var(key):
    # 加载 .env 文件
    load_dotenv()
    try:
        # 从环境变量中读取
        value = os.getenv(key)
    except:
        logger.warning(f"Failed to load {
                       key} from environment variables. Unexisted.")
        return None
    return value


def save_env_var(key, value):
    # 加载 .env 文件
    load_dotenv()
    # 更新环境变量
    os.environ[key] = value
    # 更新 .env 文件
    update_env_var(key, value)
    logger.info(f"Successfully saved {key} to environment variables.")
    return True
