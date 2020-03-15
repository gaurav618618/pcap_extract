#!/usr/bin/python3
import argparse
import os
import sys
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader
from scapy.layers.inet import IP, TCP
from scapy.all import *

def parse_pcap(pcap_file):

    print('Opening {}...'.format(pcap_file))
    count = 0
    a = rdpcap(pcap_file)
    sessions = a.sessions()
    for session in sessions:
        http_payload = ""
        for packet in sessions[session]:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                print(packet[TCP].payload)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Pcap reader')
    parser.add_argument('--pcap', metavar='<pcap file name>', help='pcap file to parse', required=True)
    args = parser.parse_args()

    file_name = args.pcap
    if not os.path.isfile(file_name):
        print('"{}" does not exist'.format(file_name), file=sys.stderr)
        sys.exit(-1)
    parse_pcap(file_name)
    sys.exit(0)
