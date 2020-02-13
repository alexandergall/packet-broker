/* -*- mode: P4_16 -*- */

#ifndef _HEADERS_P4_ 
#define _HEADERS_P4_ 

#include "protocol_headers.p4"

struct headers {
    ethernet_t ethernet;
    vlan_t vlan;
    ipv4_t ipv4;
    ipv4_options_t ipv4_options;
    ipv6_t ipv6;
    ipv6_frag_t ipv6_frag;
}

#endif // _HEADERS_P4_
