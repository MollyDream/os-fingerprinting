#!/usr/bin/env python

# Usage: python send_test_pkts.py [destination address]
# Adapted from P4 Tutorials Spring 2018:
# https://github.com/p4lang/tutorials/blob/dc08948a344c6ff26af47d2a2447800cab94ab49/exercises/basic/send.py

import sys
import random
import socket

from scapy.all import sendp, send, get_if_list, get_if_hwaddr
from scapy.all import Packet
from scapy.all import Ether, IP, IPOption, TCP

from read_fp import P0fDatabaseReader

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

    ##### Ethernet #####
    # set up Ethernet packet
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    
    ######## IP ########        
    # ignore sig.ver field: only IPv4 supported
    # choose TTL from range
    if sig.match_fields.min_ttl is None or sig.match_fields.ttl is None:
        rand_ttl = random.randint(0, 255)
    else:
        rand_ttl = random.randint(sig.match_fields.min_ttl, sig.match_fields.ttl)        

    # IP options
    olen = sig.match_fields.olen
    ip_options = ""
    for _ in range(olen):
        ip_options += "\x01"  # NOP

    # IP-related quirks
    ip_flags = 0
    ip_id = 0
    if sig.match_fields.quirk_df:
        ip_flags = ip_flags | (1 << 1) # Set DF flag
        if sig.match_fields.quirk_nz_id:
            ip_id = 1
    else:
        if not sig.match_fields.quirk_zero_id:
            ip_id = 1

    if sig.match_fields.quirk_nz_mbz:
        ip_flags = ip_flags | (1 << 2)  # Set MBZ flag

    tos = 0
    if sig.match_fields.quirk_ecn:
        tos = (1 << 1) + (1 << 0)  # Set ECN field

    # set up IP packet
    pkt = pkt / IP(
        dst=addr,
        ttl=rand_ttl,
        flags=ip_flags,
        id=ip_id,
        tos=tos
    )

    # Set IP options
    if ip_options != "":
        pkt.options = IPOption(ip_options)
    
    ####### TCP ########

    # TCP options
    tcp_options = []
    olayout = sig.match_fields.olayout
    option_mask = 2**4 - 1  # 0x1111
    timestamps_seen = False
    while olayout:
        kind = olayout & option_mask
        if kind == 0:
            tcp_options.append(('EOL', 0))
        elif kind == 1:
            tcp_options.append(('NOP', 0))
        elif kind == 2:
            mss = sig.match_fields.mss
            if mss is None:
                # 64*mss should fit in wsize field
                mss = random.randint(0, (2**16 / 64)-1)
            tcp_options.append(('MSS', mss))
        elif kind == 3:
            scale = sig.match_fields.scale
            if scale is None:
                scale = random.randint(0, 255)
            tcp_options.append(('WScale', scale))
        elif kind == 4:
            tcp_options.append(('SAckOK', ""))
        elif kind == 5:
            # 10 bytes
            sack_val = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" 
            tcp_options.append(('SAck', sack_val))
        elif kind == 8:
            timestamp_nz = ('Timestamp', (2335443, 0))
            timestamp_zero = ('Timestamp', (0, 0))
            if not timestamps_seen:
                if sig.match_fields.quirk_opt_zero_ts1:
                    tcp_options.append(timestamp_zero)
                else:
                    tcp_options.append(timestamp_nz)
            else:
                if sig.match_fields.quirk_opt_nz_ts2:
                    tcp_options.append(timestamp_nz)
                else:
                    tcp_options.append(timestamp_zero)
            timestamps_seen = True
        else:
            print("Unknown TCP option")

        olayout = olayout >> 4

    tcp_options.reverse()

    # TCP window size
    wsize = sig.match_fields.wsize
    if wsize is None:
        wsize_div_mss = sig.match_fields.wsize_div_mss
        if wsize_div_mss is None:
            wsize = random.randint(0, 2**16 - 1)
        else:
            wsize = wsize_div_mss * mss

    # TCP-related quirks
    tcp_flags = 0x02  # SYN
    if sig.match_fields.quirk_ecn:
        tcp_flags = tcp_flags | (0x40 & 0x80)  # Set ECE and CWR
    
    seq = 1000
    if sig.match_fields.quirk_zero_seq:
        seq = 0

    ack = 0
    if sig.match_fields.quirk_zero_ack:
        tcp_flags = tcp_flags | 0x10  # Set ACK
    if sig.match_fields.quirk_nz_ack:
        ack = 1000

    urg = 0
    if sig.match_fields.quirk_urg:
        tcp_flags = tcp_flags | 0x20  # Set URG
    if sig.match_fields.quirk_nz_urg:
        urg = 1000

    if sig.match_fields.quirk_push:
        tcp_flags = tcp_flags | 0x08  # Set PSH

    # set up TCP SYN packet
    pkt = pkt / TCP(
        dport=1234,
        sport=random.randint(49152,65535),
        flags=tcp_flags,
        seq=seq,
        ack=ack,
        urgptr=urg,
        options=tcp_options,
        window=wsize
    )    
    
    print "sending on interface %s to %s" % (iface, str(addr))
    # pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


def main():
    if len(sys.argv)<2:
        print 'pass 1 arguments: <destination address>>"'
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()

    print("reading signature list")
    reader = P0fDatabaseReader()
    signature_list = reader.get_signature_list()

    # Send one "start" packet.
    # Both p0f and basic.p4 will log the time at which fingerprinting
    # this packet is completed.
    # We use this time as the "start" time for measuring how long
    # each application takes to fingerprint the subsequent packets.
    send_pkt(signature_list[0], addr, iface)
    
    # Send N packets for each signature.
    N = 100
    print("building and sending packets")
    for sig in signature_list:
        for _ in range(N):
            send_pkt(sig, addr, iface)


if __name__ == '__main__':
    main()
