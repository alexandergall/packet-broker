/* -*- mode: P4_16 -*- */

#ifndef _MIRROR_P4_ 
#define _MIRROR_P4_ 

#include "types.p4"
#include "headers.p4"
#include "metadata.p4"

action act_mirror(
    inout ingress_metadata_t ig_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    MirrorId_t mirror_session) {
    ig_dprsr_md.mirror_type = (MirrorType_t)mirror_session_t.FLOW;
    ig_md.mirror_session = mirror_session;
}

control ctl_mirror_flows_ipv4(
    in headers hdr,
    in ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_metadata_t ig_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    table tbl_mirror_flows_ipv4 {
        key = {
            ig_intr_md.ingress_port : ternary @name("ingress_port");
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
    in ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_metadata_t ig_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    table tbl_mirror_flows_ipv6 {
        key = {
            ig_intr_md.ingress_port : ternary @name("ingress_port");
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

control ctl_mirror_flows_non_ip(
    in headers hdr,
    in ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_metadata_t ig_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    table tbl_mirror_flows_non_ip {
        key = {
            ig_intr_md.ingress_port : ternary @name("ingress_port");
        }
        actions = {
            act_mirror(ig_md, ig_dprsr_md);
            @defaultonly NoAction;
        }
        const default_action = NoAction;
    }

    apply {
        tbl_mirror_flows_non_ip.apply();
    }
}

#endif // _MIRROR_P4_
