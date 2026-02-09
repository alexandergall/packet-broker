/* -*- mode: P4_16 -*- */

#ifndef _HEADERS_P4_ 
#define _HEADERS_P4_ 

#include "protocol_headers.p4"

// Common first element of bridge and mirror headers to allow
// lookahead in the parser
#define PACKET_TYPE_HEADER  packet_type_t packet_type

// The @flexible pragma allows the compiler to change the order and
// padding of elements to facilitate PHV allocations. The headers are
// purely internal so their layout doesn't matter.

// Header for transporting metadata from ingress to egress (aka "bridged
// metadata"). It is prepended to every normal (non-mirroed) packet. It's
// packet_type is packet_types.BRIDGE.
@flexible
header bridge_t {
    PACKET_TYPE_HEADER;
    // Triggers egress mirroring if non-zero
    MirrorId_t eg_mirror_session;
    // Add future metadata here
}

// Header carried by mirrored packets when entering the egress
// parser. It's packet_type is packet_types.MIRROR.
@flexible
header mirror_t {
    PACKET_TYPE_HEADER;
    MirrorId_t session;
}

struct headers {
    bridge_t bridge;
    ethernet_t ethernet;
    vlan_t vlan;
    ipv4_t ipv4;
    ipv4_options_t ipv4_options;
    ipv6_t ipv6;
    ipv6_frag_t ipv6_frag;
}

#endif // _HEADERS_P4_
