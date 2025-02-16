#!/usr/bin/env python

import requests
from bs4 import BeautifulSoup
import urllib.parse as urlparse  # For Python 3
# For Python 2, change to: import urlparse

# Function to send requests
def request(url):
    try:
        return requests.get(url)
    except requests.exceptions.ConnectionError:
        print("Failed to connect to {}".format(url))
        return None

target_url = "http://192.168.5.134/dvwa/login.php"
response = request(target_url)

if response:
    parsed_html = BeautifulSoup(response.content, "html.parser")
    forms_list = parsed_html.findAll("form")

    for form in forms_list:
        action = form.get("action")
        post_url = urlparse.urljoin(target_url, action)
        method = form.get("method")

        inputs_list = form.findAll("input")
        post_data = {}

        for input in inputs_list:
            input_name = input.get("name")
            input_type = input.get("type", "text")  # Default to text if not specified
            input_value = "test" if input_type == "text" else ""

            if input_name:  # Ensure the input field has a name
                post_data[input_name] = input_value

        # Make sure post_url is valid before sending request
        if post_url:
            try:
                result = requests.post(post_url, data=post_data)
                print(result.content)
            except requests.exceptions.RequestException as e:
                print("Request failed: {}".format(e))