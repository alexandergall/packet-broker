/* -*- mode: P4-16 -*- */

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
    IPV6_FRAG = 44,
    GRE       = 47
}

enum bit<16> ethertype_t {
    VLAN = 0x8100,
    IPV4 = 0x0800,
    IPV6 = 0x86dd,
    ERSPAN_II = 0x88be
}

// Modes of packet mirroring set by the act_mirror() action
typedef bit<2> mirror_mode_t;
enum mirror_mode_t mirror_modes {
    NONE = 0,
    INGRESS = 1,
    EGRESS  = 2
}

// Identifier to distinguish bridge and mirror packet headers. One bit
// would be enough but that triggers a cryptic compiler error "invalid
// SuperCluster was formed" (p4c v1.2.5.6)
typedef bit<8> packet_type_t;
enum packet_type_t packet_types {
    // Normal packet, no request for egress mirror
    BRIDGE = 0,
    // Mirrored packet (no distinction bewteen ingress/egress mirror)
    MIRROR = 1
}

// We use a single mirror type for ingress and egress mirroring. Note
// that type 0 is reserved for ingress mirroring (it is used to cancel
// a mirror operation that was requested earlier in the ingress
// pipeline). The types used for ingress and egress are independent.
const MirrorType_t DPRSR_MIRROR_TYPE = 1;

#endif // _TYPES_P4_
