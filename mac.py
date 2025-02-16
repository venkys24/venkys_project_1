#!/usr/bin/env python

import subprocess
import optparse
import re

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="interface to change MAC addr")
    parser.add_option("-m", "--mac", dest="new_mac", help="new MAC addr")
    (options, arguments) = parser.parse_args()
    if not options.interface:
        parser.error("[-] specify interface, use --help for info.")
    elif not options.new_mac:
        parser.error("[-] specify MAC, use --help for info.")
    return options

def change_mac(interface, new_mac):
    print("[+] changing mac address for " + interface + " to " + new_mac)
    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


def get_current_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", options.interface])
    mac_addr_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(ifconfig_result))
    if mac_addr_result:
        return mac_addr_result.group(0)
    else:
        print("[-] could not read mac address.")

options = get_arguments()
current_mac = get_current_mac(options.interface)
print("current mac =" + str(current_mac))
change_mac(options.interface, options.new_mac)
current_mac = get_current_mac(options.interface)
if current_mac == options.new_mac:
    print("[+] MAC successfully changed to " + current_mac)
else:
    print("[-] MAC not changed.")




