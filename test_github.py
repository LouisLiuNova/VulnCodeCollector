"""
Add tests for github_api."""
from github_api import fetch_patch_source_code

if __name__=="__main__":
    fetch_patch_source_code("CVE-2015-3885","https://github.com/LibRaw/LibRaw/commit/4606c28f494a750892c5c1ac7903e62dd1c6fdb5")