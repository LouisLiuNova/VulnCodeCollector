"""
Fetch the CVE list with the given vendor and product name from OpenCVE and save the .csv file in `./input/` directory.
curl -u username:password https://app.opencve.io/api/vendors/libtiff/products
curl -u username:password  https://app.opencve.io/api/vendors/libtiff/products/libtiff/cve

Usage:
    python open_cve_fetcher.py --vendor libtiff --product libtiff --begin_time 2017-11-29T00:00:00Z --output_path ./input/
"""


from loguru import logger
import sys
from security import load_env_var
import pathlib
import requests
import fire
from utils import compare_iso8601_with_validation


def fetch_cve_list_to_csv(vendor: str, product: str, begin_time: str, output_path: str = "./input/",) -> list[str]:
    """
    Fetch the CVE list with the given vendor and product name from OpenCVE and save the .csv file in `./input/` directory.

    Args:
        vendor (str): The vendor name.
        product (str): The product name.
        output_path (str): The output path to save the .csv file. Default is `./input/`.
        begin_time (str): The start time to filter CVEs by creation date, in ISO 8601 format (e.g., 2017-11-29T00:00:00Z).
    """

    url = f"https://app.opencve.io/api/vendors/{vendor}/products"
    # Load credentials
    username = load_env_var("OPENCVE_USERNAME")
    password = load_env_var("OPENCVE_PASSWORD")

    # Validate the vendor exists and get the product list iteratively
    logger.info(
        f"Fetching product list from OpenCVE for vendor {vendor} and product {product}")
    found_flag = False
    while url:
        try:
            response = requests.get(url, auth=(username, password))
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            if response.status_code == 404:
                logger.error(f"Vendor {vendor} not found")
                return list()
            else:
                logger.error(
                    f"Failed to fetch data from OpenCVE due to the http error: {err}")
                return list()
        except requests.exceptions.RequestException as err:
            logger.error(
                f"Failed to fetch data from OpenCVE due to the request exception: {err}")
            return list()

        # Parse the response
        try:
            data = response.json()
            url = data.get("next")
            product_list = [product.get("name", "")
                            for product in data.get("results", [])]

        except ValueError as err:
            logger.error(
                f"Failed to parse the response from OpenCVE due to the JSON error: {err}")
            return list()
        if product not in product_list:
            logger.info(
                f"Product {product} has not been found in the vendor {vendor} list yet: {product_list}")

        else:
            logger.info(
                f"Product {product} found in the vendor {vendor} list: {product_list}")
            found_flag = True
            break
    if not found_flag:
        logger.error(
            f"Product {product} not found in the vendor {vendor} list: {product_list}")
        return list()
    # Fetch the CVE list iteravely
    url = f"https://app.opencve.io/api/vendors/{vendor}/products/{product}/cve"
    page_cnt = 1
    cve_list = list()
    while url:
        logger.info(
            f"Fetching CVE list from OpenCVE for {vendor}/{product} page {page_cnt}")
        try:
            response = requests.get(url, auth=(username, password))
            response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logger.error(
                f"Failed to fetch data from OpenCVE due to the http error: {err}")
            return list()
        except requests.exceptions.RequestException as err:
            logger.error(
                f"Failed to fetch data from OpenCVE due to the request exception: {err}")
            return list()

        # Parse the response
        try:
            data = response.json()
            url = data.get("next")
            # FIXME: 用CVE编号判断而不是created time, opencve的时间不准 或者可以拿着CVE号去nvd查
            cve_list += [cve.get("cve_id") for cve in data.get("results", [])
                         if compare_iso8601_with_validation(begin_time,cve.get("created_at"))]
        except ValueError as err:
            logger.error(
                f"Failed to parse the response from OpenCVE due to the JSON error: {err}")
            return list()
        except AssertionError as err:
            logger.error(
                f"Failed to parse the response from OpenCVE due to the assertion error: {err}")
            return list()
        except Exception as err:
            logger.error(
                f"Failed to parse the response from OpenCVE due to the unknown error: {err}")
            return list()
        page_cnt += 1
    logger.info(
        f"Fetched {len(cve_list)} CVEs from OpenCVE for {vendor}/{product} in {page_cnt} pages")

    # Save the CVE list to a CSV file
    output_path = pathlib.Path(output_path)
    output_path.mkdir(parents=True, exist_ok=True)
    csv_file = output_path / f"{vendor}_{product}_{begin_time}.csv"
    with open(csv_file, "w") as f:
        for cve in cve_list:
            f.write(f"{cve}\n")
    logger.info(
        f"Saved {len(cve_list)} CVEs to {csv_file}")
    return cve_list


if __name__ == "__main__":
    # 移除默认的日志处理器
    logger.remove()
    # 添加新的日志处理器，并设置日志等级，例如 "INFO"
    logger.add(sys.stdout, level="INFO")
    fire.Fire(fetch_cve_list_to_csv)
