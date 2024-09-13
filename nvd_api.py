"""
To provide NVD api interface"""
import re
from loguru import logger
import requests
import json
from collections import defaultdict

def fetch_data_with_CVE_number(cve_number:str):
    """
    Fetch the data from the NVD API and OpenCVE with the given ONE CVE number. If vaild, save the data to `./data/[cve-number]/` and continue to fetch source code from the GitHub API.
    
    Args:
    cve_number: str: The CVE number to fetch. Must be a valid CVE string like "CVE-2021-1234" or "cve-2021-1234".
    
    Returns:
    status: bool: True if the data is fetched successfully, False otherwise.
    """
    
    # Receive and check input parameter
    cve_number = cve_number.upper()
    logger.info(f"Fetching data for {cve_number}")
    if not validate_cve(cve_number):
        logger.warning(f"{cve_number} is not a valid CVE number, skipping")
        return False
    
    nvd_data = fetch_data_with_CWE_number_in_NVD(cve_number)
    open_cve_data = fetch_data_with_CWE_number_in_OpenCVE(cve_number)
    
    
def fetch_data_with_CWE_number_in_NVD(cve_number:str):
    """
    Fetch data from NVD API with the given ONE CWE number. Data includes the description, references, and weakness. For the doc of the endpoint, refer https://nvd.nist.gov/developers/vulnerabilities 
    
    Args:
    cwe_number: str: The validated CWE number to fetch. Must be a valid CWE string like "CWE-1234" or "cwe-1234".
    
    Return:
    dict: The fetched and filtered data from NVD API.
    """
    
    # Fetch data from NVD API
    BASE_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    try:
        response = requests.get(f"{BASE_ENDPOINT}?cveId={cve_number}")
        response.raise_for_status()
    except:
        return False
    
    logger.debug(response.json())
    response=response.json()
    if (vuln_info:=response["vulnerabilities"])==[] or response["resultsPerPage"]==0:
        logger.warning(f"No data found for {cve_number}")
        return False
    
    # Dump data and save to file
    # NOTE: Only fields "cve", "cveTags", "references" and "descriptions" are required, other fields are optional and may unexist.
    # NOTE: Refer https://nvd.nist.gov/developers/vulnerabilities for full documentation.
    vuln_info=defaultdict(None,vuln_info[0]["cve"])
    info=defaultdict(None)
    info["cve_number"]=vuln_info["id"]
    info["publish_date"]=vuln_info["published"]
    info["description"]=next((desc['value'] for desc in vuln_info['descriptions'] if desc['lang'] == 'en'), "No desc yet")
    info["status"]=vuln_info["vulnStatus"]
    
    # Dump weakness data
    weakness=list()
    if "weakness" in vuln_info:
        for cwe in vuln_info["weakness"]:
            if "description" in cwe:
                for lang in cwe["description"]:
                    if lang["lang"]=="en":
                        weakness.append(lang["value"])
                        break
    info["weakness"]=weakness

    # Dump references data
    # NOTE: the field "references" is a dict, the key is the tag and the value is a list of URLs in this tag. Some URLs may belong to multiple tags so they may appear in multiple tags.
    references=defaultdict(list)
    if "references" in vuln_info:
        for ref_url in vuln_info["references"]:
            tags=ref_url["tags"]
            # NOTE: for those URLs without tags, we will ignore them except it is a GitHub URL.
            # TODO: if the URL does not belong to the vendor fetched from the openCVE, we will ignore it. For why we need to do this, refer to CVE-2015-3885 in NVD.
            for tag in tags:
                references[tag].append(ref_url["url"])
            # To validate if the URL is a GitHub commit. If so, we will relove it later and fetch the source code from the GitHub API.
            if validate_a_url_belongs_to_github(ref_url["url"]):
                logger.info(f"Found a GitHub commit URL for {cve_number}: {ref_url['url']}")
                references["GitHub"].append(ref_url["url"])
    info["references"]=references
    
    return info
    
            
    

def fetch_data_with_CWE_number_in_OpenCVE(cwe_number:str):
    """
    Fetch data from OpenCVE with the given ONE CWE number. Data includes vendor, product, CWEs. For the doc of the endpoint, refer https://docs.opencve.io/api/cve/
    
    Args:
    cwe_number: str: The validated CWE number to fetch. Must be a valid CWE string like "CWE-1234" or "cwe-1234".
    
    Returns:
    dict: The fetched and filtered data from OpenCVE.
    """
    raise NotImplementedError("fetch_data_with_CWE_number_in_OpenCVE function not implemented yet")

def validate_a_url_belongs_to_github(url:str):
    """
    Validate a URL belongs to GitHub.
    
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