/* -*- mode: P4-16 -*- */

#ifndef _PROTOCOL_HEADERS_P4_ 
#define _PROTOCOL_HEADERS_P4_ 

#include "types.p4"

header ethernet_t {
    mac_addr_t dst_mac_addr;
    mac_addr_t src_mac_addr;
    ethertype_t ethertype;
}

header vlan_t {
    bit <3> pcp;
    bit <1> cfi;
    vlan_id_t vid;
    ethertype_t ethertype;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    ip_proto_t  protocol;
    bit<16>     hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

header ipv4_options_t { 
    varbit<320> data;
}

header ipv6_t {
    bit<4>     version;
    bit<8>     traffic_class;
    bit<20>    flow_label;
    bit<16>    payload_len;
    ip_proto_t next_hdr;
    bit<8>     hop_limit;
    bit<128>   src_addr;
    bit<128>   dst_addr;
}

header ipv6_frag_t {
    ip_proto_t next_hdr;
    bit<8>     reserved;
    bit<13>    offset;
    bit<2>     reserved_2;
    bit<1>     more_fragments;
    bit<32>    id;
}

// RFC2784-style GRE header with RFC2890 extensions
header gre_base_h {
    bit<1> checksum_present;
    bit<1> reserved0;
    bit<1> key_present;
    bit<1> seq_present;
    bit<9> reserved1;
    bit<3> version;
    ethertype_t protocol;
}
header gre_checksum_h {
    bit<16> checksum;
}
header gre_key_h {
    bit<32> key;
}
header gre_sequence_h {
    bit<32> sequence;
}

struct gre_h {
    gre_base_h base;
    gre_checksum_h checksum;
    gre_key_h key;
    gre_sequence_h sequence;
}

// ERSPAN Type II https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03
// Uses a RFC1701-style GRE header exclusively with sequence number,
// which can be mapped to RF2784 + 2890
header erspan_typeII_h {
    bit<4> version;
    bit<12> vlan;
    bit<3> cos;
    bit<2> trunk_encap;
    bit<1> trunc;
    bit<10> session;
    bit<12> reserved;
    bit<20> index;
}

#endif // _PROTOCOL_HEADERS_P4_
