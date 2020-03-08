/* -*- mode: P4_16 -*- */

#ifndef _MIRROR_P4_ 
#define _MIRROR_P4_ 

#include <tofino.p4>
#include "types.p4"
#include "headers.p4"
#include "metadata.p4"

header mirror_header_t {};

action act_mirror(
    inout ingress_metadata_t ig_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    MirrorId_t mirror_session) {
    ig_dprsr_md.mirror_type = (bit<3>)mirror_session_t.FLOW;
    ig_md.mirror_session = mirror_session;
}

control ctl_mirror_flows_ipv4(
    in headers hdr,
    inout ingress_metadata_t ig_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    table tbl_mirror_flows_ipv4 {
        key = {
            hdr.ipv4.src_addr  : ternary @name("src_addr");
            hdr.ipv4.dst_addr  : ternary @name("dst_addr");
            ig_md.l4_lookup.word_1 : ternary @name("src_port");
            ig_md.l4_lookup.word_2 : ternary @name("dst_port");
        }
        actions = {
            act_mirror(ig_md, ig_dprsr_md);
            @defaultonly NoAction;
        }
        const default_action = NoAction;
    }
    
    apply {
        tbl_mirror_flows_ipv4.apply();
    }
}

control ctl_mirror_flows_ipv6(
    in headers hdr,
    inout ingress_metadata_t ig_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    table tbl_mirror_flows_ipv6 {
        key = {
            hdr.ipv6.src_addr  : ternary @name("src_addr");
            hdr.ipv6.dst_addr  : ternary @name("dst_addr"); 
            ig_md.l4_lookup.word_1 : ternary @name("src_port");
            ig_md.l4_lookup.word_2 : ternary @name("dst_port");
        }
        actions = {
            act_mirror(ig_md, ig_dprsr_md);
            @defaultonly NoAction;
        }
        const default_action = NoAction;
    }

    apply {
        tbl_mirror_flows_ipv6.apply();
    }
}

#endif // _MIRROR_P4_
