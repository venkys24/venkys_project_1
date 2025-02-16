#!/usr/bin/env python3

import scapy.all as scapy
from scapy.layers import http, dns
import time
from collections import defaultdict


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[http.HTTPRequest].Host.decode(errors='ignore') + packet[http.HTTPRequest].Path.decode(errors='ignore')


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode(errors='ignore')
        keywords = ["username", "user", "login", "password", "pass"]
        for keyword in keywords:
            if keyword in load:
                return load


def detect_brute_force(packet):
    global login_attempts, last_brute_force_alert
    if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        login_attempts[src_ip] += 1
        current_time = time.time()
        if login_attempts[src_ip] > 5 and (current_time - last_brute_force_alert[src_ip] > 10):
            print(f"[!] Possible Brute Force Attack from {src_ip} ({login_attempts[src_ip]} attempts)")
            last_brute_force_alert[src_ip] = current_time


def detect_dns_requests(packet):
    if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 0:
        domain = packet[scapy.DNS].qd.qname.decode(errors='ignore')
        print(f"[+] DNS Request: {domain}")


def detect_large_transfers(packet):
    global last_large_transfer_alert
    if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.IP) and len(packet[scapy.Raw].load) > 500:
        src_ip = packet[scapy.IP].src
        current_time = time.time()
        if current_time - last_large_transfer_alert[src_ip] > 10:
            print(f"[!] Large Data Transfer Detected ({len(packet[scapy.Raw].load)} bytes) from {src_ip}")
            last_large_transfer_alert[src_ip] = current_time


def ssl_strip(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        if "https" in url:
            print("[+] SSL Stripping attempt detected, redirecting...")
        return url.replace("https", "http")


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = ssl_strip(packet)
        print("[+] HTTP Request >>", url)

        login_info = get_login_info(packet)
        if login_info:
            print("\n[+] Possible Credentials: ", login_info, "\n")

    if packet.haslayer(scapy.DNS):
        detect_dns_requests(packet)

    if packet.haslayer(scapy.Raw):
        detect_brute_force(packet)
        detect_large_transfers(packet)


# Track login attempts
login_attempts = defaultdict(int)
last_brute_force_alert = defaultdict(lambda: 0)
last_large_transfer_alert = defaultdict(lambda: 0)

target_interface = "eth0"  # Change this based on your network

print("[*] Sniffing on interface", target_interface)
sniff(target_interface)

