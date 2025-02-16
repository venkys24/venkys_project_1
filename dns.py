#!/usr/bin/env python3

from scapy.layers.dns import DNS, DNSQR
import scapy.all as scapy
import re
import subprocess
import sys

def setup_iptables():
    try:
        subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"], check=True)
        print("[+] iptables rule set successfully.")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to set iptables rule: {e}")
        sys.exit(1)

def cleanup_iptables():
    try:
        subprocess.run(["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"], check=True)
        print("[+] iptables rule removed.")
    except subprocess.CalledProcessError:
        print("[!] Failed to remove iptables rule.")

def load_blocked_domains():
    try:
        with open("/root/Downloads/blocked.txt", "r") as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        print("[!] /root/Downloads/blocked.txt not found. Using default domain: bing.com")
        return ["bing.com"]

def detect_dns_requests(packet, blocked_domains):
    try:
        if packet.haslayer(scapy.DNS) and packet[scapy.DNS].qr == 0:
            domain = packet[scapy.DNS].qd.qname.decode(errors='ignore')
            for blocked in blocked_domains:
                if re.search(rf".*{re.escape(blocked)}", domain):
                    print(f"[+] DNS Request Matched: {domain}")
                    break
    except Exception as e:
        print(f"[!] Error in DNS detection: {e}")

def process_sniffed_packet(packet):
    try:
        if packet.haslayer(scapy.DNS):
            detect_dns_requests(packet, blocked_domains)
    except Exception as e:
        print(f"[!] Error processing packet: {e}")

blocked_domains = load_blocked_domains()

target_interface = "eth0"  # Change this based on your network

print("[*] Setting up iptables...")
setup_iptables()

try:
    print("[*] Sniffing on interface", target_interface)
    scapy.sniff(iface=target_interface, store=False, prn=process_sniffed_packet)
except KeyboardInterrupt:
    print("\n[!] Stopping...")
    cleanup_iptables()
    sys.exit(0)
