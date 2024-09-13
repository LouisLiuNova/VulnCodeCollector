"""
Main entry point for the application."""
import pathlib
from loguru import logger
import fire

class App(object):
    """
    Main entry of the application."""
    def __init__(self):
        logger.info("Initializing the application")
    def fetch(self, csv_path:pathlib.Path):
        """ Main function to fetch the data from the remote API and save it to ./data."""
        logger.info(f"Fetching data from {csv_path}")
        
    def export(self,output_path:pathlib.Path):
        """ Main function to export the data to the remote API."""
        logger.info(f"Exporting data to {output_path}")
        logger.exception("Export function not implemented yet")
        raise NotImplementedError("Export function not implemented yet")


if __name__=="__main__":
    fire.Fire(App) 