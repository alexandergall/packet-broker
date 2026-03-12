/* -*- mode: P4-16 -*- */

#ifndef _METADATA_P4_ 
#define _METADATA_P4_ 

#include "types.p4"
#include "headers.p4"

struct ingress_metadata_t {
    l4_lookup_t l4_lookup;
    bit<1> non_first_fragment;
    bit<1> drop;

    // This field is initialized in the ingress parser to
    // packet_types.MIRROR and is only referenced by the ingress
    // deparser. It only exists because the initializer in the
    // mirror.emit() method can't assign non-zero static data.
    packet_type_t packet_type;

    // These are set in the act_mirror() action when a packet matches
    // a mirroring rule.
    mirror_mode_t mirror_mode;
    MirrorId_t mirror_session;
}

struct egress_metadata_t {
    // Initialized to packet_types.MIRROR in the egress deparser, same
    // rationale as above
    packet_type_t packet_type;

    // The egress deparser extracts internal headers into these
    // metadata fields rather than the header used in emit() since they
    // must never be part of any packet that leaves the device.
    bridge_t bridge;
    mirror_t mirror;
}

#endif // _METADATA_P4
