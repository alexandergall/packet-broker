/* -*- mode: P4_16 -*- */

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

#endif // _PROTOCOL_HEADERS_P4_
