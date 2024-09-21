"""
Base class of all URL parsers."""

import re
from loguru import logger
from urllib.parse import unquote


class BaseParser:
    def __init__(self, name: str, owner: str, repo: str, pattern: list):
        """
        Initialize the BaseParser object.

        Args:
            name: Name of the parser.
            owner: Owner of the repository.
            repo: Repository name.
            pattern: List of regex patterns to match the URL.
        """
        self.name = name
        self.owner = owner
        self.repo = repo
        if not pattern:
            self.pattern = list()
        else:
            self.pattern = pattern

    def parse(self, url: str) -> str:
        """
        Parse and convert the URL to a GitHub commit URL. Need to be implemented by the child class.

        Args:
            url: URL to be parsed.

        Returns:
            GitHub commit URL.
        """
        if not self.validate(url):
            logger.warning(f"URL {url} is not valid for parser {self.name}")
            return None

        # NOTE: the base class only implements pattern like http://git.savannah.gnu.org/cgit/freetype/freetype2.git/commit/?id=59eb9f8cfe7d1df379a2318316d1f04f80fba54a (can be split by =)
        try:
            commit_sha = url.split("=")[-1]
        except:
            logger.warning(f"Cannot parse URL {url} to get commit SHA.")
            return None

        return f"https://github.com/{self.owner}/{self.repo}/commit/{commit_sha}"

    def validate(self, url: str) -> bool:
        """
        Validate if the URL matches the parser's pattern.

        Args:
            url: URL to be validated.

        Returns:
            True if the URL matches the pattern, False otherwise.
        """
        decoded_url = unquote(url)
        for p in self.pattern:
            if re.match(p, decoded_url):
                logger.debug(f"URL {decoded_url} matched pattern {p}")
                return True
        logger.debug(f"URL {decoded_url} did not match any pattern in {self.name}")
        return False
