"""
to interact with github rest API
"""

import requests
import os
import pathlib
from loguru import logger
from collections import defaultdict
from security import load_env_var
from urllib.parse import urlparse, parse_qs
import json


def fetch_patch_source_code(cve_number: str, commit_url: str):
    """
    Fetch the source code of a patch from the GitHub API (https://docs.github.com/zh/rest/commits/commits?apiVersion=2022-11-28#get-a-commit) and save it to .
    Example:
    curl -L   -H "Accept: application/vnd.github+json"  -H "Authorization: Bearer [token]" -H "X-GitHub-Api-Version: 2022-11-28" https://api.github.com/repos/LibRaw/LibRaw/commits/2f912f5b33582961b1cdbd9fd828589f8b78f21d > examples/github_get_commit.json
    Args:
    cve_number: str: The CVE number of the patch.
    commit_url: str: The URL of the commit.

    Returns:
    None
    """

    # Load credentials
    token = load_env_var("GITHUB_TOKEN")
    if token is None:
        logger.error(
            "Failed to load GitHub token. Please register a token first.")
        return

    # TODO: Resolve commit URL
    info = resolve_commit_url(commit_url)

    # Fetch the commit info
    BASE_ENDPOINT = "https://api.github.com"
    try:
        # Fetch the commit info
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        res = requests.get(
            f"{BASE_ENDPOINT}/repos/{info['owner']
                                     }/{info['repo']}/commits/{info['commit_sha']}",
            headers=headers,
        )
        res.raise_for_status()
        commit_info = res.json()
    except requests.exceptions.HTTPError as err:
        logger.warning(f"Failed to fetch commit info: {err}")
        return None

    logger.info(f"Fetch commit {info['commit_sha']} info successfully.")
    logger.debug(f"{commit_info=}")
    # Resolve the patch URL and collect the basic information of the patch
    info["commit_massage"] = commit_info["commit"]["message"]
    info["raw_ref"] = commit_info["url"]
    info["html_ref"] = commit_info["html_url"]
    # NOTE: to prevent json like  "author": null,"committer": null
    if commit_info["author"] is None:
        info["author"] = commit_info["commit"]["author"]["name"]
    else:
        info["author"] = commit_info["author"]["login"]
    info["changes_stats"] = commit_info["stats"]
    info["files"] = commit_info["files"]
    info["parent_commit_sha"] = commit_info["parents"][0]["sha"]

    # Fetch each file changed in this commit
    for file in info["files"]:
        file_name = os.path.basename(file["filename"])
        logger.info(f"Fetching file {file_name}...")

        # Filter source code files
        if not is_code_file(file["filename"]):
            logger.warning(
                f"Skip file {file_name} since it's not a source code file.")
            continue
        # Filter files in different status. Including: added, modified, deleted
        if file["status"] == "deleted":
            logger.info(f"Skip file {file_name} since it's deleted.")
            continue
        elif file["status"] == "added":
            logger.info(
                f"File {file_name} is added so skip fetching the previous version."
            )
            pass  # NOTE: No more action needed for added files.
        elif file["status"] == "modified":
            logger.info(
                f"File {file_name} is modified so fetch the previous version.")
            # Fetch the previous version of the file
            # NOTE: Files in the current commit can be fetched from the URL in file["raw_url"]
            # NOTE: Dont forget to save .diff
            fetch_file_content(
                cve_number,
                info["owner"],
                info["repo"],
                file["filename"],
                info["commit_sha"],
                info["parent_commit_sha"],
            )  # Fetch the previous(vulnerable) version of the file

            # Save the diff file
            diff_content = file["patch"]
            filename = f"{cve_number}_{info['repo']}_{file_name}.diff"
            logger.info(f"Saving diff file {filename}...")
            # Check if the directory exists
            pathlib.Path(f"data/{cve_number}/{info["commit_sha"]}/patched").mkdir(
                parents=True, exist_ok=True
            )
            with open(f"data/{cve_number}/{info['commit_sha']}/patched/{filename}", "w") as f:
                f.write(diff_content)
            logger.info(f"Successfully saved diff file {filename}.")

        else:
            logger.warning(
                f"Skip file {file_name} since it's in unrecognized status {
                    file['status']}."
            )
            continue

        # Fetch the patched version of the file
        download_url = file["raw_url"]
        file_content = requests.get(download_url).text
        file_name_without_ext = os.path.splitext(file_name)[0]  # 获取不带扩展名的文件名
        # Rename the file with the naming rules for vulnerable files
        filename = f"{cve_number}_{info['repo']}_patched_{
            os.path.basename(file['filename'])}"
        logger.info(f"Saving file {file_name} as {filename}...")
        # Check if the directory exists
        pathlib.Path(
            f"data/{cve_number}/{info['commit_sha']}/patched").mkdir(parents=True, exist_ok=True)
        with open(f"data/{cve_number}/{info['commit_sha']}/patched/{filename}", "w") as f:
            f.write(file_content)
        logger.info(f"Successfully saved file {filename}.")

        # Save the commit infos
        with open(f"data/{cve_number}/{info['commit_sha']}/{info['commit_sha']}.json", "w")as f:
            json.dump(info, f, indent=4)
        logger.info(f"Successfully saved commit info to {
                    info['commit_sha']}.json.")


def fetch_file_content(
        cve_number: str, owner: str, repo: str, file_path: str, commit_sha: str, parent_commit_sha: str):
    """
    Fetch the content of the given file from the given commit hash and then save it.
    Args:
    cve_number: str: The CVE number of the patch. Just for saving the file.
    owner: str: The owner of the repository.
    repo: str: The name of the repository.
    file_path: str: The path of the file.
    commit_sha: str: The patch commit hash.
    parent_commit_sha: str: The parent_commit hash.

    Returns:
    None
    """
    # Load credentials
    token = load_env_var("GITHUB_TOKEN")
    if token is None:
        logger.error(
            "Failed to load GitHub token. Please register a token first.")
        return

    # Fetch the file info
    BASE_ENDPOINT = "https://api.github.com"
    try:
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        # URL Example: https://api.github.com/repos/LibRaw/LibRaw/contents/src/libraw_cxx.cpp?ref=2f912f5b33582961b1cdbd9fd828589f8b78f21d
        res = requests.get(
            f"{BASE_ENDPOINT}/repos/{owner}/{repo}/contents/{file_path}?ref={parent_commit_sha}",
            headers=headers,
        )
        res.raise_for_status()
        file_info = res.json()
    except requests.exceptions.HTTPError as err:
        logger.error(f"Failed to fetch file content: {err}")
        return None

    # Save the file content
    download_url = file_info["download_url"]
    file_name = os.path.basename(file_path)  # 获取文件名（包括扩展名）
    file_name_without_ext = os.path.splitext(file_name)[0]  # 获取不带扩展名的文件名
    file_content = requests.get(download_url).text

    # Rename the file with the naming rules for vulnerable files
    filename = f"{cve_number}_{repo}_vulnerable_{file_name}"
    logger.info(f"Saving file {file_name} as {filename}...")

    # Check if the directory exists
    pathlib.Path(
        f"data/{cve_number}/{commit_sha}/vulnerable").mkdir(parents=True, exist_ok=True)
    with open(f"data/{cve_number}/{commit_sha}/vulnerable/{filename}", "w") as f:
        f.write(file_content)

    logger.info(f"Successfully saved file {filename}.")


def resolve_commit_url(commit_url: str):
    """
    Resolve the commit URL to the API URL and return dicts of basic commit info. The commit URL should be validiated before.

    Args:
    commit_url: str: The URL of the commit.

    Returns:
    commit_info: dict: The basic commit info.
    """

    res = dict()
    # Split the URL
    parsed_url = urlparse(commit_url)
    paths = parsed_url.path.split("/")[
        1:
        # NOTE: should be like ['LibRaw', 'LibRaw', 'commit', '4606c28f494a750892c5c1ac7903e62dd1c6fdb5']. [1:] is to strip the first empty segment.
    ]
    res["owner"] = paths[0]
    res["repo"] = paths[1]
    res["commit_sha"] = paths[-1]

    logger.debug(f"Resolved commit URL: {res}")
    return res


def is_code_file(file_path: pathlib.Path):
    # 获取文件扩展名
    code_file_extensions = {
        ".py",
        ".h",
        ".c",
        ".cpp",
        ".java",
        ".js",
        ".ts",
        ".rb",
        ".php",
        ".html",
        ".css",
        ".go",
        ".rs",
    }
    return pathlib.Path(file_path).suffix.lower() in code_file_extensions
