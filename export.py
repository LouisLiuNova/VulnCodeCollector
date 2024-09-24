"""
to expoert the data from the database to a csv file

Export the data from the database to a csv file with the given columns."""

import pathlib
from loguru import logger


def export(output_path: pathlib.Path):
    """ Main function to export the data to the remote API. Exported data should be in CSV and has the following columns:
    - CVE Number
    - github commit URL
    - vendor/product name
    - etc."""
    logger.info(f"Exporting data to {output_path}")
