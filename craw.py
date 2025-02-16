#!/usr/bin/env python3

import requests
from urllib.parse import urljoin  # Ensures compatibility with Python 3

def request(url):
    try:
        get_response = requests.get(url)  # Send HTTP GET request
        return get_response  # Return the response object
    except requests.exceptions.ConnectionError:
        return None  # Return None if connection fails

target_url = "http://192.168.5.134/mutillidae/"  # Ensure proper URL format

with open("/root/Downloads/wordlist.txt", "r") as wordlist_file:
    for line in wordlist_file:
        word = line.strip()
        test_url = urljoin(target_url, word)  # Correctly join URLs
        response = request(test_url)

        if response and response.status_code in [200, 301, 403]:  # Only display useful responses
            print("[+] Discovered URL [{}] -> {}".format(response.status_code, test_url))  # Python 3 compatible print

