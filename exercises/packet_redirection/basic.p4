/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<32> MIRROR_SESSION_ID = 250;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_TCP = 6;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv4_options_t {
    varbit<320> options;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header tcp_option_t {
    bit<8> kind;
    varbit<312> content;
}

header tcp_option_ss_t {
    bit<8> kind;
    bit<8> length;
    bit<16> mss;
}

header tcp_option_s_t {
    bit<8> kind;
    bit<8> length;
    bit<8> scale;
}


header tcp_option_ts_t {
    bit<8> kind;
    bit<8> length;
    bit<32> tsval;
    bit<32> tsecr;
}

header tcp_option_sack_top_t {
    bit<8> kind;
    bit<8> length;
}

/* A stack of up to 40 TCP options */
typedef tcp_option_t[40] tcp_option_stack_t;

error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadSackOptionLength
}

header p0f_t {
    bit<8> result;
}

// Temporary variables for use in division_helper action
struct division_metadata_t {
    bit<16> dividend;
    bit<16> divisor;
    bit<32> acc;
    bit<16> quotient;
}

struct p0f_metadata_t {
    bit<4> ver;
    bit<8> ttl;
    bit<9> olen;
    bit<16> mss;
    bit<16> wsize;
    bit<16> wsize_div_mss;
    bit<8> scale;
    /* 
    concatenate kind fields (cast to 4 bits) of tcp options 
    TODO: use less space-intensive way of storing olayout?
    */
    bit<160> olayout;

    /* quirks */
    bit<1> quirk_df;
    bit<1> quirk_nz_id;
    bit<1> quirk_zero_id;
    bit<1> quirk_ecn;
    bit<1> quirk_nz_mbz;
    bit<1> quirk_zero_seq;
    bit<1> quirk_nz_ack;
    bit<1> quirk_zero_ack;
    bit<1> quirk_nz_urg;
    bit<1> quirk_urg;
    bit<1> quirk_push;
    bit<1> quirk_opt_zero_ts1;                   
    bit<1> quirk_opt_nz_ts2;
    bit<1> quirk_opt_eol_nz;
    bit<1> quirk_opt_exws;
    bit<1> quirk_opt_bad;  // currently not used because we just reject incorrectly-formatted packets
    
    bit<32> pclass;
}

/* should match fields in p0f_t */
struct p0f_result_t {
    bit<8> result;
}

struct metadata {
    division_metadata_t division_metadata;
    p0f_metadata_t p0f_metadata;
    p0f_result_t p0f_result;
}

struct headers {
    ethernet_t           ethernet;
    ipv4_t               ipv4;
    ipv4_options_t       ipv4_options;
    tcp_t                tcp;
    tcp_option_stack_t   tcp_options_vec;
    p0f_t                p0f;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

/* 
TCP options subparser
Adapted from https://github.com/jafingerhut/p4-guide/blob/master/tcp-options-parser/tcp-options-parser2.p4
*/
/*
Copyright 2017 Cisco Systems, Inc.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// This sub-parser is intended to be apply'd just after the base
// 20-byte TCP header has been extracted.  It should be called with
// the value of the Data Offset field.  It will fill in the @vec
// argument with a stack of TCP options found, perhaps empty.

// Unless some error is detect earlier (causing this sub-parser to
// transition to the reject state), it will advance exactly to the end
// of the TCP header, leaving the packet 'pointer' at the first byte
// of the TCP payload (if any).  If the packet ends before the full
// TCP header can be consumed, this sub-parser will set
// error.PacketTooShort and transition to reject.

parser Tcp_option_parser(packet_in b,
                         in bit<4> tcp_hdr_data_offset,
                         inout metadata meta, 
                         out tcp_option_stack_t vec)
{
    bit<9> tcp_hdr_bytes_left;
    bit<1> own_timestamp_seen = 0;
    bit<1> eol_seen = 0;
    
    state start {
        // RFC 793 - the Data Offset field is the length of the TCP
        // header in units of 32-bit words.  It must be at least 5 for
        // the minimum length TCP header, and since it is 4 bits in
        // size, can be at most 15, for a maximum TCP header length of
        // 15*4 = 60 bytes.
        verify(tcp_hdr_data_offset >= 5, error.TcpDataOffsetTooSmall);
        tcp_hdr_bytes_left = 4 * (bit<9>) (tcp_hdr_data_offset - 5);
        // always true here: 0 <= tcp_hdr_bytes_left <= 40
        transition next_option;
    }
    state next_option {
        transition select(tcp_hdr_bytes_left) {
            0 : accept;  // no TCP header bytes left
            default : next_option_part2;
        }
    }
    state next_option_part2 {
	// precondition: tcp_hdr_bytes_left >= 1
	/* kind byte */
	bit<8> kind = b.lookahead<bit<8>>();
	
	/* update olayout metadata field */
	meta.p0f_metadata.olayout = (bit<160>) meta.p0f_metadata.olayout << 4;
	meta.p0f_metadata.olayout = meta.p0f_metadata.olayout + (bit<160>) kind;
	
	/* update quirk_opt_eol_nz field */
	meta.p0f_metadata.quirk_opt_eol_nz = (bit<1>) (meta.p0f_metadata.quirk_opt_eol_nz != 0 || (eol_seen != 0 && kind != 0));
	
	/* transition on kind */
        transition select(kind) {
	    0: parse_tcp_option_end;
	    1: parse_tcp_option_nop;
	    2: parse_tcp_option_ss;
	    3: parse_tcp_option_s;
	    4: parse_tcp_option_sack_permitted;
	    5: parse_tcp_option_sack;
	    8: parse_tcp_option_timestamps;
        }
    }
    
    state parse_tcp_option_end {
        verify(tcp_hdr_bytes_left >= 1, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        b.extract(vec.next, 0);
	eol_seen = 1;
	
	transition next_option;
    }
    
    state parse_tcp_option_nop {
        verify(tcp_hdr_bytes_left >= 1, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        b.extract(vec.next, 0);
        transition next_option;
    }
    
    state parse_tcp_option_ss {
        verify(tcp_hdr_bytes_left >= 4, error.TcpOptionTooLongForHeader);
	/* set metadata field */
	meta.p0f_metadata.mss = b.lookahead<tcp_option_ss_t>().mss;
	tcp_hdr_bytes_left = tcp_hdr_bytes_left - 4;
        b.extract(vec.next, 3*8);
        transition next_option;
    }
    
    state parse_tcp_option_s {
        verify(tcp_hdr_bytes_left >= 3, error.TcpOptionTooLongForHeader);
	/* set scale metadata field */
	meta.p0f_metadata.scale = b.lookahead<tcp_option_s_t>().scale;
	/* set excessive scale metadata field */
	meta.p0f_metadata.quirk_opt_exws = (bit<1>) (meta.p0f_metadata.scale > 14);	
	tcp_hdr_bytes_left = tcp_hdr_bytes_left - 3;
        b.extract(vec.next, 2*8);
        transition next_option;
    }
    
    state parse_tcp_option_sack_permitted {
	verify(tcp_hdr_bytes_left >= 2, error.TcpOptionTooLongForHeader);
	tcp_hdr_bytes_left = tcp_hdr_bytes_left - 2;
	b.extract(vec.next, 1*8);
	transition next_option;
    }
    
    state parse_tcp_option_sack {
        bit<8> n_sack_bytes = b.lookahead<tcp_option_sack_top_t>().length;
        // I do not have global knowledge of all TCP SACK
        // implementations, but from reading the RFC, it appears that
        // the only SACK option lengths that are legal are 2+8*n for
        // n=1, 2, 3, or 4, so set an error if anything else is seen.
        verify(n_sack_bytes == 10 || n_sack_bytes == 18 ||
               n_sack_bytes == 26 || n_sack_bytes == 34,
               error.TcpBadSackOptionLength);
        verify(tcp_hdr_bytes_left >= (bit<9>) n_sack_bytes,
               error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - (bit<9>) n_sack_bytes;
        b.extract(vec.next, (bit<32>) (8 * n_sack_bytes - 16));
        transition next_option;
    }
    
    state parse_tcp_option_timestamps {
	verify(tcp_hdr_bytes_left >= 10, error.TcpOptionTooLongForHeader);
	bit<32> tsval = b.lookahead<tcp_option_ts_t>().tsval;
	
	// set flag if own timestamp is zero
	meta.p0f_metadata.quirk_opt_zero_ts1 = (bit<1>) ((own_timestamp_seen != 0 && meta.p0f_metadata.quirk_opt_zero_ts1 != 0) || (own_timestamp_seen == 0 && tsval == 0));

	// set flag if peer timestamp is nonzero
	meta.p0f_metadata.quirk_opt_nz_ts2 = (bit<1>) (meta.p0f_metadata.quirk_opt_nz_ts2 != 0 || (own_timestamp_seen != 0 && tsval != 0));

	own_timestamp_seen = 1;
	
	tcp_hdr_bytes_left = tcp_hdr_bytes_left - 10;
	b.extract(vec.next, 9*8);
	transition next_option;
    }
}

/* Parser */
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    bit<9> ipv4_options_bytes;
    bit<9> tcp_options_bytes;

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
	packet.extract(hdr.ethernet);
	transition select(hdr.ethernet.etherType) {
	    TYPE_IPV4: parse_ipv4;
	    default: accept;
	}
    }

    state parse_ipv4 {
	packet.extract(hdr.ipv4);
	/* calculate and store length of ip header */
	ipv4_options_bytes = 4 * (bit<9>)(hdr.ipv4.ihl - 5);
	meta.p0f_metadata.olen = ipv4_options_bytes;
	/* extract ipv4 options */
	packet.extract(hdr.ipv4_options, (bit<32>) (8 * ipv4_options_bytes));
	transition select(hdr.ipv4.protocol) {
	    TYPE_TCP: parse_tcp;
	    default: accept;
	}
    }

    state parse_tcp {
	packet.extract(hdr.tcp);
	Tcp_option_parser.apply(packet, hdr.tcp.dataOffset, meta,
	                        hdr.tcp_options_vec);
	transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
	hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // i = current bit to test
    action divide_helper(bit<4> i) {
	bit<32> shifted_divisor = ((bit<32>) meta.division_metadata.divisor) << i;
	bit<16> or_mask = 1;
	or_mask = or_mask << i;
	
	if (meta.division_metadata.acc + shifted_divisor <= (bit<32>) meta.division_metadata.dividend) {
	    meta.division_metadata.acc = meta.division_metadata.acc + shifted_divisor;
	    meta.division_metadata.quotient = meta.division_metadata.quotient | or_mask;
	}
    }

    // Divides meta.division_metadata.dividend by meta.division_metadata.divisor, storing the result in meta.division_metadata.quotient.
    // Adapted from: https://www.geeksforgeeks.org/divide-two-integers-without-using-multiplication-division-mod-operator/ ("Efficient Approach")
    action divide() {
	divide_helper(15);
	divide_helper(14);
	divide_helper(13);
	divide_helper(12);
	divide_helper(11);
	divide_helper(10);
	divide_helper(9);
	divide_helper(8);
	divide_helper(7);
	divide_helper(6);
	divide_helper(5);
	divide_helper(4);
	divide_helper(3);
	divide_helper(2);
	divide_helper(1);
	divide_helper(0);
    }

    action set_result(bit<8> result) {
	meta.p0f_result.result = result;
    }

    table result_match {
	key = {
	    meta.p0f_metadata.ver: ternary;
	    meta.p0f_metadata.ttl: range;
	    /* it doesn't look like p0f.fp contains any signatures that have olen != 0 -> should we still include? */
	    meta.p0f_metadata.olen: exact;
	    meta.p0f_metadata.mss: ternary;
	    meta.p0f_metadata.wsize: ternary;
	    meta.p0f_metadata.wsize_div_mss: ternary;
	    meta.p0f_metadata.scale: ternary;
	    meta.p0f_metadata.olayout: exact;
	    /* it doesn't look like p0f.fp contains any signatures that have pclass != -> should we still include? */
	    meta.p0f_metadata.quirk_df: ternary;
	    meta.p0f_metadata.quirk_nz_id: ternary;
	    meta.p0f_metadata.quirk_zero_id: ternary;
	    meta.p0f_metadata.quirk_ecn: ternary;
	    meta.p0f_metadata.quirk_nz_mbz: exact;
	    meta.p0f_metadata.quirk_zero_seq: exact;
	    meta.p0f_metadata.quirk_nz_ack: exact;
	    meta.p0f_metadata.quirk_zero_ack: exact;
	    meta.p0f_metadata.quirk_nz_urg: exact;
	    meta.p0f_metadata.quirk_urg: exact;
	    meta.p0f_metadata.quirk_push: exact;
	    meta.p0f_metadata.quirk_opt_zero_ts1: exact;                   
	    meta.p0f_metadata.quirk_opt_nz_ts2: exact;
	    meta.p0f_metadata.quirk_opt_eol_nz: exact;
	    meta.p0f_metadata.quirk_opt_exws: exact;
	    meta.p0f_metadata.quirk_opt_bad: exact;
	    meta.p0f_metadata.pclass: exact;
	}
	actions = {
	    set_result;
	}
	size = 1024;
	default_action = set_result(255);
    }
    
    apply {
	if (hdr.ipv4.isValid()) {
	    /* IPv4 forwarding */
            ipv4_lpm.apply();
	}
	if (hdr.tcp.isValid()) {
	    /* FINGERPRINT FIELD PARSING */
	    /* for olen, mss, scale: see parser */
	    meta.p0f_metadata.ver = hdr.ipv4.version;  /* ver */    
	    meta.p0f_metadata.ttl = hdr.ipv4.ttl;      /* ttl */
	    meta.p0f_metadata.wsize = hdr.tcp.window;  /* wsize */

	    /* calculate wsize / mss */
	    meta.division_metadata.dividend = meta.p0f_metadata.wsize;
	    meta.division_metadata.divisor = meta.p0f_metadata.mss;
	    meta.division_metadata.acc = 0;
	    meta.division_metadata.quotient = 0;
	    divide();
	    meta.p0f_metadata.wsize_div_mss = meta.division_metadata.quotient;

	    /* pclass */
	    bit<32> ip_header_length;
	    if (hdr.ipv4.isValid()) {
		ip_header_length = 20 + (bit<32>) meta.p0f_metadata.olen;
	    } else {  // ipv6
		ip_header_length = 40 + (bit<32>) meta.p0f_metadata.olen;
	    }
	    meta.p0f_metadata.pclass =
	        standard_metadata.packet_length    // length of whole packet
	        - 4 * (bit<32>) hdr.tcp.dataOffset // length of TCP header
	        - ip_header_length                 // length of IP header
	        - 14;                              // length of Ethernet header

	    /* quirks */
	    /* IP-specific quirks */
	    if (hdr.ipv4.flags > 0x01) {  // 010, 011
		meta.p0f_metadata.quirk_df = 1;  /* df: "don't fragment" set */
		if (hdr.ipv4.identification != 0) {
		    meta.p0f_metadata.quirk_nz_id = 1;  /* id+: df set but IPID not zero */
		}
	    } else {
		if (hdr.ipv4.identification == 0) {
		    meta.p0f_metadata.quirk_zero_id = 1;  /* id-: df not set but IPID zero */
		}
	    }
	    if (hdr.ipv4.diffserv & 0x03 != 0) {
		meta.p0f_metadata.quirk_ecn = 1;  /* ecn support */
	    }
	    if (hdr.ipv4.flags > 0x03) {  // 100, 101, 110, 111
		meta.p0f_metadata.quirk_nz_mbz = 1;  /* 0+: "must be zero field" not zero */
	    }

	    /* TCP-specific quirks */
	    if (hdr.tcp.ecn & 0x03 != 0|| hdr.tcp.ecn & 0x04 != 0) {  // CWR and ECE flags both set, or only NS flag set
		meta.p0f_metadata.quirk_ecn = 1;  /* ecn: explicit congestion notification support */
	    }
	    
	    if (hdr.tcp.seqNo == 0) {
		meta.p0f_metadata.quirk_zero_seq = 1;  /* seq-: sequence number is zero */
	    }
	    if (hdr.tcp.ctrl & 0x10 != 0) {
		if (hdr.tcp.ackNo == 0) {
		    meta.p0f_metadata.quirk_zero_ack = 1;  /* ack-: ACK flag set but ACK number is zero */
		}
	    } else {
		if (hdr.tcp.ackNo != 0 && hdr.tcp.ctrl & 0x04 == 0) {  // ignore illegal ack numbers for RST packets -- see p0f-3.09b:process.c:492
		    meta.p0f_metadata.quirk_nz_ack = 1;  /* ack+: ACK flag not set but ACK number nonzero */
		}
	    }
	    if (hdr.tcp.ctrl & 0x20 != 0) {
		meta.p0f_metadata.quirk_urg = 1;  /* urgf+: URG flag set */
	    } else {
		if (hdr.tcp.urgentPtr != 0) {
		    meta.p0f_metadata.quirk_nz_urg = 1;  /* uptr+: URG pointer is non-zero, but URG flag not set */
		}
	    }
	    if (hdr.tcp.ctrl & 0x08 != 0) {
		meta.p0f_metadata.quirk_push = 1;  /* pushf+: PUSH flag used */
	    }
	    
	    result_match.apply();
	    
	}
	
	/* clone packet while retaining p0f_result metadata */
	clone3<p0f_result_t>(CloneType.I2E, MIRROR_SESSION_ID, meta.p0f_result);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    /* encapsulate packet with p0f header */
    action add_p0f_header() {
	hdr.p0f.setValid();
	hdr.p0f.result = meta.p0f_result.result;
    }
    
    apply {
	/* if packet is cloned, add p0f header */
	if (standard_metadata.instance_type == 1) {
	    add_p0f_header();
	}
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}


/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
	packet.emit(hdr.ipv4);
	packet.emit(hdr.ipv4_options);
	packet.emit(hdr.tcp);
	packet.emit(hdr.tcp_options_vec);
	packet.emit(hdr.p0f);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
