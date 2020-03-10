#!/usr/bin/python3
import argparse
import os
import sys
from scapy.layers.l2 import Ether
from scapy.utils import RawPcapReader
from scapy.layers.inet import IP, TCP

def parse_pcap(pcap_file):
    print('Opening {}...'.format(pcap_file))

    count = 0
    for (pkt_data, pkt_metadata,) in RawPcapReader(pcap_file):
        count += 1
        ether_pkt = Ether(pkt_data)
        if ether_pkt.type == 0x0800:
            ip_pkt = ether_pkt[IP]
            if ip_pkt.proto == 6:
                print('TCP PACKET')
            elif ip_pkt.proto == 1 :
                print('ICMP Packet')
            elif ip_pkt.proto == 17 :
                print('UDP Packet')


    print('{} contains {} packets'.format(pcap_file,count))

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
