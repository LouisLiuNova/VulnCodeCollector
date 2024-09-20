from base_parser import BaseParser
from urllib.parse import unquote
import re
from loguru import logger

parsers = []


def register_parser(name):
    def decorator(class_obj):
        parsers.append({'name': name, 'class': class_obj})
        return class_obj
    return decorator


qemu_parser = BaseParser("qemu", "qemu", "qemu", [
                         r"http:\/\/git\.qemu-project\.org\/\?p=qemu\.git;a=commit;h=[a-f0-9]{40}", r'http:\/\/git\.qemu\.org/\?p=qemu\.git;a=commit;h=[0-9a-f]{40}$'])
register_parser("qemu")(qemu_parser)
linux_parser = BaseParser("linux", "torvalds", "linux", [
                          r'http:\/\/git\.kernel\.org\/cgit\/linux\/kernel\/git\/torvalds\/linux\.git\/commit\/\?id=[0-9a-f]{40}', r'http:\/\/git\.kernel\.org\/\?p=linux\/kernel\/git\/torvalds\/linux-2\.6\.git;a=commit;h=[0-9a-f]{40}'])
register_parser("linux")(linux_parser)
ffmpeg_parser = BaseParser("ffmpeg", "FFmpeg", "FFmpeg", [
                           r'http:\/\/git\.videolan\.org\/\?p=ffmpeg\.git;a=(?:commit|commitdiff);h=[0-9a-f]{40}'])
register_parser("ffmpeg")(ffmpeg_parser)


def use_all_parsers(url):
    for parser in parsers:
        if parser['class'].validate(url):
            logger.info(f"Found a {parser['name']} commit URL: {
                        url}. We may convert this to GitHub URL.")
            return parser['class'].parse(url)
        else:
            logger.debug(f"{parser['name']} parser did not match {url}")
    logger.info(f"No parser matched {url}")
    return None
