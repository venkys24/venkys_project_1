#!/usr/bin/env python3

import requests
import re
from urllib.parse import urljoin  # Correct import for Python 3

target_url = "http://192.168.5.134/mutillidae/"
target_links = []

def extract_links_from(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an error for HTTP issues
        return re.findall(r'href=["\'](.*?)["\']', response.text)  # Use response.text instead of response.content
    except requests.exceptions.RequestException as e:
        print(f"Error fetching URL: {url} - {e}")
        return []

def crawl(url):
    href_links = extract_links_from(url)
    for link in href_links:
        absolute_link = urljoin(url, link)  # Use urllib.parse.urljoin correctly
        if "#" in absolute_link:
            absolute_link = absolute_link.split("#")[0]  # Remove fragments
        if target_url in absolute_link and absolute_link not in target_links:
            target_links.append(absolute_link)
            print("[+] Discovered URL:", absolute_link)
            crawl(absolute_link)  # Recursively crawl the new link

# Start crawling from the target URL
crawl(target_url)


