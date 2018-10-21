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

header tcp_options_t {
    varbit<320> options;
}

header p0f_t {
    bit<4> ver;
    bit<8> ttl;
    bit<9> olen;
}

struct p0f_metadata_t {
    bit<4> ver;
    bit<8> ttl;
    bit<9> olen;
}

struct metadata {
    p0f_metadata_t p0f_metadata;
}

struct headers {
    ethernet_t     ethernet;
    ipv4_t         ipv4;
    ipv4_options_t ipv4_options;
    tcp_t          tcp;
    tcp_options_t  tcp_options;
    p0f_t          p0f;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

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
	/* Data offset field stores total size of TCP header in 4B   */
	/* words. 5 -> 20 bytes == length of options-less TCP header */
	tcp_options_bytes = 4 * (bit<9>)(hdr.tcp.dataOffset - 5);
	packet.extract(hdr.tcp_options, (bit<32>) (8 * tcp_options_bytes));
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

    /* parse `ver` field of fingerprint */
    action parse_p0f_ver() {
	meta.p0f_metadata.ver = hdr.ipv4.version;
    }

    /* parse `ttl` field of fingerprint */
    action parse_p0f_ttl() {
	meta.p0f_metadata.ttl = hdr.ipv4.ttl;
    }
    
    apply {
	/* clone packet while retaining p0f metadata */
	clone3<p0f_metadata_t>(CloneType.I2E, MIRROR_SESSION_ID, meta.p0f_metadata);

	if (hdr.ipv4.isValid()) {
	    /* IPv4 forwarding */
            ipv4_lpm.apply();

	    /* FINGERPRINT FIELD PARSING */
	    parse_p0f_ver();
	    parse_p0f_ttl();
	}
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
	hdr.p0f.ver = meta.p0f_metadata.ver;
	hdr.p0f.ttl = meta.p0f_metadata.ttl;
	hdr.p0f.olen = meta.p0f_metadata.olen;
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
	packet.emit(hdr.tcp_options);
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
