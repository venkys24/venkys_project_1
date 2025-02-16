#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.dot11 import Dot11
import time

# Get Network Interface from user
interface = input('Enter your Network Interface > ').strip()  # Use input() for Python 3

# Set Packet Counter
packet_counter = 1

# Extract and analyze packet info
def detect_deauth(packet):
    global packet_counter
    if packet.haslayer(Dot11):
        if packet.type == 0 and packet.subtype == 12:  # Deauthentication Frame
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            print("[{}] [+] Deauthentication Packet detected! Count: {}".format(timestamp, packet_counter))
            packet_counter += 1

# Start Sniffing and Detecting Deauth Packets
try:
    print("[*] Sniffing on interface: {}... Press Ctrl+C to stop.".format(interface))
    sniff(iface=interface, prn=detect_deauth, store=0)
except Exception as e:
    print("[ERROR] {}. Make sure the interface exists and is in monitor mode.".format(e))

