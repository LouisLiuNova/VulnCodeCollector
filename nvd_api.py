"""
To provide NVD api interface"""
import re
from loguru import logger
import requests
import json
from collections import defaultdict
from requests.auth import HTTPBasicAuth
from github_api import fetch_patch_source_code
from security import load_env_var
import os
import base64
from time import sleep
from urllib.parse import unquote
from parsers import use_all_parsers

CVEs_with_GitHub = 0  # Total number of CVEs with GitHub commit URL


def fetch_data_with_CVE_number(cve_number: str, input_filename: str):
    """
    Fetch the data from the NVD API and OpenCVE with the given ONE CVE number. If vaild, save the data to `./data/[cve-number]/` and continue to fetch source code from the GitHub API.

    Args:
    cve_number: str: The CVE number to fetch. Must be a valid CVE string like "CVE-2021-1234" or "cve-2021-1234".
    input_filename: str: The input filename to save the data. Must be a valid filename string like "./example/input.csv".

    Returns:
    status: bool: True if this CVE has vaild GitHub commit URL, False otherwise.
    """
    global CVEs_with_GitHub
    # Receive and check input parameter
    cve_number = cve_number.upper()
    logger.info(f"Fetching data for {cve_number}")
    if not validate_cve(cve_number):
        logger.warning(f"{cve_number} is not a valid CVE number, skipping")
        return None

    nvd_data = fetch_data_with_CVE_number_in_NVD(cve_number)
    sleep(5)
    open_cve_data = fetch_data_with_CVE_number_in_OpenCVE(cve_number)

    # Merge data
    if nvd_data is None or open_cve_data is None:
        logger.warning(f"Failed to fetch data for {cve_number}: NVD:{
                       nvd_data is not None}, OpenCVE:{open_cve_data is not None}")
        return None
    result = defaultdict(None, nvd_data)
    result["vendor"] = open_cve_data["vendor"]
    result["title"] = open_cve_data["title"]
    result["weaknesses"] = open_cve_data["cwe"]
    # NOTE: More info from OpenCVE can be added here.

    # Save data to `./data/{input_filename}/{cve_number}/{cve_number}.json`. If the directory does not exist, create it.
    data_dir = f"./data/{input_filename}/{cve_number}"
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    with open(f"{data_dir}/{cve_number}.json", "w") as f:
        json.dump(result, f, indent=4)
    logger.info(f"Successfully saved data for {
                cve_number} to {data_dir}/{cve_number}.json")

    # Retrive GitHub commit URLs and fetch commit message via GitHub API
    githubURLs = list()
    if "GitHub" in result["references"]:
        for commit_url in result["references"]["GitHub"]:
            logger.info(
                f"{cve_number} has a GitHub patch commit URL: {commit_url}")
            githubURLs.append(commit_url)
    if githubURLs == []:
        # No GitHub commit URL found
        logger.warning(f"No GitHub commit URL found for {
                       cve_number}. End fetching.")
        return False

    # Fetch source code from GitHub API
    logger.debug(f"GitHub commit URLs: {githubURLs}")
    CVEs_with_GitHub += 1
    # Curl example command: curl -L -H "Accept: application/vnd.github+json"  -H "Authorization: Bearer <token>" -H "X-GitHub-Api-Version: 2022-11-28" https://api.github.com/repos/LibRaw/LibRaw/commits/2f912f5b33582961b1cdbd9fd828589f8b78f21d
    for commit_url in githubURLs:
        fetch_patch_source_code(cve_number, commit_url, input_filename)

    return True


def fetch_data_with_CVE_number_in_NVD(cve_number: str) -> dict:
    """
    Fetch data from NVD API with the given ONE CVE number. Data includes the description, references, and weakness. For the doc of the endpoint, refer https: // nvd.nist.gov/developers/vulnerabilities

    Args:
    cve_number: str: The validated CVE number to fetch. Must be a valid CVE string like "CVE-2021-1234" or "cve-2021-1234".

    Return:
    dict: The fetched and filtered data from NVD API.
    """

    # Fetch data from NVD API
    BASE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Load credentials
    token = load_env_var("NVD_TOKEN")
    if token is None:
        logger.error(
            "Failed to load NVD token. Register it before fetching data from NVD.")
        return None
    headers = {
        "apiKey": token
    }

    logger.info(f"Fetching data for {cve_number} from NVD API")
    try:
        response = requests.get(f"{BASE_ENDPOINT}?cveId={
                                cve_number}", headers=headers)
        response.raise_for_status()
    except:
        logger.exception(f"Failed to fetch data from NVD for {cve_number}")
        return None

    logger.debug(response.json())
    response = response.json()
    if (vuln_info := response["vulnerabilities"]) == [] or response["resultsPerPage"] == 0:
        logger.warning(f"No data found for {cve_number}")
        return None

    # Dump data and save to file
    # NOTE: Only fields "cve", "cveTags", "references" and "descriptions" are required, other fields are optional and may unexist.
    # NOTE: Refer https://nvd.nist.gov/developers/vulnerabilities for full documentation.
    vuln_info = defaultdict(None, vuln_info[0]["cve"])
    info = defaultdict(None)
    info["cve_number"] = vuln_info["id"]
    info["publish_date"] = vuln_info["published"]
    info["description"] = next(
        (desc['value'] for desc in vuln_info['descriptions'] if desc['lang'] == 'en'), "No desc yet")
    info["status"] = vuln_info["vulnStatus"]

    # Dump references data
    # NOTE: the field "references" is a dict, the key is the tag and the value is a list of URLs in this tag. Some URLs may belong to multiple tags so they may appear in multiple tags.
    references = defaultdict(list)

    def process_url(url):
        """
        To validate if url matches a parser and add it to the references.
        """
        parse_res = use_all_parsers(url)
        if parse_res and parse_res not in references["GitHub"]:
            references["GitHub"].append(parse_res)

    if "references" in vuln_info:
        for ref_url in vuln_info["references"]:
            # Each ref_url is a dict with keys "tags" and "url" like ref_url={'url': 'http://lists.fedoraproject.org/pipermail/package-announce/2016-May/184209.html', 'source': 'secalert@redhat.com', 'tags': ['Third Party Advisory']}
            logger.debug(f"{ref_url=}")
            if "tags" in ref_url:
                tags = ref_url["tags"]
            else:
                tags = list()
            # NOTE: for those URLs without tags, we will ignore them except it is a GitHub URL.
            # TODO: if the URL does not belong to the vendor fetched from the openCVE, we will ignore it. For why we need to do this, refer to CVE-2015-3885 in NVD.
            # NOTE: to fix those URLs without tags, we will add them to a tag named "NoTag".
            for tag in tags:
                if ref_url["url"] not in references[tag]:  # NOTE: to prevent duplicate URLs
                    references[tag].append(ref_url["url"])
            if tags == []:
                if ref_url["url"] not in references["NoTag"]:  # NOTE: to prevent duplicate URLs
                    references["NoTag"].append(ref_url["url"])

            # To validate if the URL is a GitHub commit. If so, we will regard it as a patch commit and relove it later and fetch the source code from the GitHub API.
            if validate_a_url_belongs_to_github(ref_url["url"]):
                logger.info(f"Found a GitHub commit URL for {
                            cve_number}: {ref_url['url']}")
                if ref_url["url"] not in references["GitHub"]:
                    references["GitHub"].append(ref_url["url"])

                # If the URL is a GitHub URL, we will not use parsers to validate it.
                continue

            # Use parsers to validate and convert the URL
            process_url(ref_url["url"])
    logger.debug(f"{info=}")
    info["references"] = references

    return info


def fetch_data_with_CVE_number_in_OpenCVE(cve_number: str):
    """
    Fetch data from OpenCVE with the given ONE CvE number. Data includes vendor, product, CWEs. For the doc of the endpoint, refer https: // docs.opencve.io/api/cve/

    Args:
    cve_number: str: The validated CvE number to fetch. Must be a valid CvE string like "CVE-2021-1234" or "cve-2021-1234".

    Returns:
    dict: The fetched and filtered data from OpenCVE.
    """
    BASE_ENDPOINT = "https://app.opencve.io/api/cve/"

    logger.info(f"Fetching data for {cve_number} from OpenCVE")
    # Load credentials
    username = load_env_var("OPENCVE_USERNAME")
    password = load_env_var("OPENCVE_PASSWORD")
    if username is None or password is None:
        # OpenCVE only supports basic authentication
        logger.error(
            "Failed to load OpenCVE credentials. Register it before fetching data from OpenCVE.")
        return None

    # Prepare and Send request
    try:
        response = requests.get(
            f"{BASE_ENDPOINT}{cve_number}", auth=HTTPBasicAuth(username, password))
        logger.debug(f"Response code:{response.status_code}")
        logger.debug(f"Response body:{response.text}")
        response.raise_for_status()
    except:
        logger.exception(f"Failed to fetch data from OpenCVE for {cve_number}")
        return None

    response_text = defaultdict(None, response.json())
    info = defaultdict(None)
    info["id"] = response_text["cve_id"]
    # NOTE: to resolve the vendor info
    info["vendor"] = resolve_vendor(response_text["vendors"])
    info["title"] = response_text["title"]
    info['descrtiption'] = response_text["description"]
    info["cwe"] = response_text["weaknesses"]

    # Dump request headers and check rate limit
    # NOTE: it seems that there is no rate limit in OpenCVE API?
    # logger.debug(f"Request headers: {response.headers}")
    if "X-RateLimit-Remaining" in response.headers and "X-RateLimit-Limit" in response.headers and "Retry-After" in response.headers:
        remaining = response.headers["X-RateLimit-Remaining"]
        limit = response.headers["X-RateLimit-Limit"]
        if remaining <= limit//10:
            logger.warning(f"Rate limit is running low. Remaining: {
                           remaining}/{limit}. Retry after {response.headers['Retry-After']} seconds.")
        else:
            logger.info(f"Rate limit remaining: {
                        response.headers['X-RateLimit-Remaining']}")

    return info


def validate_a_url_belongs_to_github(url: str):
    """
    Validate a URL belongs to GitHub commit.

    Args:
    url: str: The URL to validate.

    Returns:
    bool: True if the URL belongs to GitHub, False otherwise.
    """
    # GitHub commit URL 的正则表达式
    pattern = r'^https://github\.com/[\w\-]+/[\w\-]+/commit/[0-9a-f]{40}$'
    return re.match(pattern, url) is not None


def validate_cve(cve_id: str) -> bool:
    # 定义CVE标号的正则表达式
    pattern = r'^CVE-\d{4}-\d{4,}$'

    # 使用 re.match() 校验字符串
    if re.match(pattern, cve_id):
        return True
    return False


def resolve_vendor(vendor_infos: list) -> dict:
    """
    Resolve vendor info from OpenCVE API response and return structured data.

    Args:
    vendor_infos: list: The vendor info list from OpenCVE API response like:
    "vendor": [
        "qemu",
        "qemu$PRODUCT$qemu",
        "redhat",
        "redhat$PRODUCT$enterprise_linux",
        "redhat$PRODUCT$openstack"
    ]

    Returns:
    dict: The structured vendor info like:
    {
        "qemu": ["qemu"],
        "redhat": ["enterprise_linux", "openstack"]
    }
    """
    result = dict()
    for vendor in vendor_infos:
        if "$PRODUCT$" in vendor:
            vendor, product = vendor.split("$PRODUCT$")
            if vendor in result and product not in result[vendor]:
                result[vendor].append(product)
            elif vendor not in result:
                result[vendor] = [product]
            else:
                pass  # 重复的vendor
        else:
            if vendor not in result:
                result[vendor] = [vendor]
            elif vendor in result[vendor]:
                pass
            else:
                result[vendor].append(vendor)

    return result
