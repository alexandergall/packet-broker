/* -*- mode: P4_16 -*- */

#ifndef _TYPES_P4_ 
#define _TYPES_P4_ 

typedef bit<8>   port_group_t;
typedef bit<48>  mac_addr_t;
typedef bit<12>  vlan_id_t;
typedef bit<32>  ipv4_addr_t;
typedef bit<128> ipv6_addr_t;

// The first two 16-bit words of the L4 header for TCP and UDP.
struct l4_lookup_t {
    bit<16>  word_1;
    bit<16>  word_2;
}

enum bit<8>  ip_proto_t {
    TCP       = 6,
    UDP       = 17,
    IPV6_FRAG = 44
}

enum bit<16> ethertype_t {
    VLAN = 0x8100,
    IPV4 = 0x0800,
    IPV6 = 0x86dd
}

enum bit<3> mirror_session_t {
    FLOW = 0
}

#endif // _TYPES_P4_
