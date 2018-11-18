#!/usr/bin/env python

# Usage: python send_test_pkts.py [destination address]

import sys
import random
import socket

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, TCP

import read_fp


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def send_pkt(sig, addr, iface):
    print("Process signature: {}".format(sig.label))
    
    # ignore sig.ver field: only IPv4 supported

    # choose TTL from range
    rand_ttl = random.randint(sig.min_ttl, sig.ttl)

    # set up Ethernet packet
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    
    # set up IP packet
    pkt = pkt / IP(
        dst=addr,
        ttl=rand_ttl
    )
    
    # set up TCP SYN packet
    pkt = pkt / TCP(
        dport=1234,
        sport=random.randint(49152,65535),
        flags='S',
        seq=1000
    )
    
    print "sending on interface %s to %s" % (iface, str(addr))
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


def main():
    if len(sys.argv)<2:
        print 'pass 1 arguments: <destination address>>"'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print("reading signature list")
    signature_list = read_fp.read_fp_file()
    
    for sig in signature_list:
        if sig.is_generic:
            continue
        send_pkt(sig, addr, iface)


if __name__ == '__main__':
    main()
