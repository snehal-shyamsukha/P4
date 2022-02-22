#!/usr/bin/env python
import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, UDP, TCP
from probeheader import ProbeHeader

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('ip_addr', type=str, help="Destination IP Address")
    parser.add_argument('message', type=str, help="message")
    parser.add_argument('P1', type=int, default=None, help='P1')
    parser.add_argument('P2', type=int, default=None, help='P2')
    args = parser.parse_args()

    addr = socket.gethostbyname(args.ip_addr)
    P1 = args.P1
    P2 = args.P2
    iface = get_if()

    if ((P1 and P2) is not None):
        print "sending on interface {}".format(iface)
        pkt =  Ether(src=get_if_hwaddr(iface), dst='00:00:00:01:01:00')
        pkt = pkt / IP(dst=addr) / ProbeHeader(P1=P1, P2=P2) / args.message
    else:
        print "sending on interface {} to IP addr {}".format(iface, str(addr))
        pkt =  Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
        pkt = pkt / IP(dst=addr) / UDP(dport=1234, sport=random.randint(50000,65535)) / args.message
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()
