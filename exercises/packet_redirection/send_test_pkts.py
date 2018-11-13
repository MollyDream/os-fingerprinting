#!/usr/bin/env python2

# Usage: python send_test_pkts.py [host]

import sys
from random import randint
from scapy.layers.inet import IP, TCP
from scapy.sendrecv import send

import read_fp

HOST_TO_IP = {
    'h1': '10.0.1.1',
    'h2': '10.0.1.2',
    'h3': '10.0.3.3'
}


def send_pkt(sig, dst_ip):
    # ignore sig.ver field: only IPv4 supported

    # choose TTL from range
    rand_ttl = randint(sig.min_ttl, sig.ttl)

    # set up IP packet
    ip = IP(
        dst=dst_ip,
        ttl=rand_ttl
    )
    
    # set up TCP SYN packet
    tcp = ip / TCP(
        flags='S',
        seq=1000
    )

    # send TCP packet
    send(tcp)


def main():
    dst_host = sys.argv[1]
    if dst_host not in HOST_TO_IP:
        raise Exception('Unknown host parameter.')
    
    signature_list = read_fp.read_fp_file()
    sig = read_fp.process_signature(
        'sig = *:64:0:*:mss*20,10:mss,sok,ts,nop,ws:df,id+:0',
        'Linux 3.11 or newer'
    )
    # for sig in signature_list:
    send_pkt(sig, dst_host)


if __name__ == '__main__':
    main()
