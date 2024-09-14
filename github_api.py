"""
to interact with github rest API
"""

import requests
from loguru import logger
from collections import defaultdict
from security import load_env_var


def fetch_patch_source_code(cve_number: str, commit_url: str):
    """
    Fetch the source code of a patch from the GitHub API (https://docs.github.com/zh/rest/commits/commits?apiVersion=2022-11-28#get-a-commit) and save it to .

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
