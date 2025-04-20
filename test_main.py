"""
Unitest of main.py
"""
from nvd_api import fetch_data_with_CVE_number
if __name__ == "__main__":

    fetch_data_with_CVE_number("CVE-2015-0292", "test_flight")
