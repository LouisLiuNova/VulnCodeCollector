"""
Main entry point for the application."""
import pathlib
from loguru import logger
import fire
from security import save_env_var, load_env_var
from tqdm import tqdm
from nvd_api import fetch_data_with_CVE_number, CVEs_with_GitHub
from time import sleep
from enum import Enum
from stats import stat
import sys


class Mode(Enum):
    append = 'append'
    cover = 'cover'
    reset = 'reset'


class App(object):
    """
    Main entry of the application."""

    def __init__(self):
        logger.info("Initializing the application")

    def fetch(self, csv_path: pathlib.Path, mode: Mode.append):
        """ Main function to fetch the data from the remote API and save it to ./data.
        mode:
        append: Append the data to the existing data. Skipping existed data.
        cover: Overwrite the existing data.
        reset: Remove all the existing data and re-fetch all data only from input json.

        default: append
        """

        # Check if the mode legal
        try:
            mode = Mode(mode)
        except ValueError:
            logger.exception(f"Invalid mode: {mode}. You must assign a valid mode: {
                ', '.join([m.value for m in Mode])}")
            return

        logger.info(f"Fetching data from {csv_path}")
        # TODO: Filter with mode
        with open(csv_path, "r") as f:
            cve_numbers = f.readlines()

        failed_cves = []  # To save CVEs without vaild commits
        with tqdm(total=len(cve_numbers), desc="Processing CVEs") as pbar:
            for cve in cve_numbers:
                result = fetch_data_with_CVE_number(cve.strip())
                if result is None:
                    logger.warning(f"Failed to fetch data for {cve}")
                elif result == False:
                    logger.warning(f"No valid commits found for {cve}")
                    failed_cves.append(cve)
                else:
                    pass
                pbar.update(1)
                # NOTE: follow the best practice of API rate limiting here: https://nvd.nist.gov/developers/start-here
                sleep(3)
        logger.info(f"Successfully fetched all data from {
                    csv_path}. CVEs without valid commits: {failed_cves}")

    def export(self, output_path: pathlib.Path):
        """ Main function to export the data to the remote API."""
        logger.info(f"Exporting data to {output_path}")
        logger.exception("Export function not implemented yet")
        raise NotImplementedError("Export function not implemented yet")

    def stat(self):
        """ Main function to show the statistics of the data."""
        stat()

    def hello(self):
        logger.info("Hello, World!")


class Register(object):
    """
    Register credentials for the remote APIs."""

    def opencve(self, username: str, password: str):
        """ To save credentials for OpenCVE."""
        logger.info(f"Registering a new user {username} for OpenCVE")
        save_env_var("OPENCVE_USERNAME", username)
        save_env_var("OPENCVE_PASSWORD", password)
        logger.info(f"Successfully registered a new user {
                    username} for OpenCVE")
        return

    def github(self, token: str):
        """ To save credentials for Github."""
        logger.info(f"Registering a new user for Github")
        save_env_var("GITHUB_TOKEN", token)
        logger.info(f"Successfully registered a new user for Github")
        return

    def nvd(self, token: str):
        logger.info(f"Registering a new user for NVD")
        save_env_var("NVD_TOKEN", token)
        logger.info(f"Successfully registered a new user for NVD")
        return


if __name__ == "__main__":
    # 移除默认的日志处理器
    logger.remove()
    # 添加新的日志处理器，并设置日志等级，例如 "INFO"
    logger.add(sys.stdout, level="INFO")
    fire.Fire({'run': App, 'register': Register})
