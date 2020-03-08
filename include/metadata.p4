/* -*- mode: P4_16 -*- */

#ifndef _METADATA_P4_ 
#define _METADATA_P4_ 

#include "types.p4"

struct ingress_metadata_t {
    l4_lookup_t l4_lookup;
    MirrorId_t mirror_session;
    bit<1> non_first_fragment;
    bit<1> drop;
}

#endif // _METADATA_P4
