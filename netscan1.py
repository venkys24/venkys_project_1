#!/usr/bin/env python3

import argparse
import scapy.all as scapy


def get_arguments():
    parser = argparse.ArgumentParser(description="Simple Network Scanner using ARP")
    parser.add_argument("-t", "--target", dest="target", required=True,
                        help="Target IP/IP range (e.g., 192.168.5.0/24)")
    return parser.parse_args()


def scan(ip):
    try:
        arp_request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list, _ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)

        clients_list = []
        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            clients_list.append(client_dict)

        return clients_list  # Return full list after loop
    except Exception as e:
        print(f"[ERROR] Failed to perform scan: {e}")
        return []


def print_result(results_list):
    print("\nIP Address\t\tMAC Address")
    print("---------------------------------------")
    if not results_list:
        print("[INFO] No devices found on the network.")
        return

    for client in results_list:
        print(f"{client['ip']}\t\t{client['mac']}")


# Main Execution
options = get_arguments()
scan_result = scan(options.target)

# Check if scan_result is None or empty before calling print_result
if scan_result is not None:
    print_result(scan_result)
else:
    print("[ERROR] No scan results to display.")

