/* -*- mode: P4-16 -*- */

#ifndef _MIRROR_P4_ 
#define _MIRROR_P4_ 

#include "types.p4"
#include "headers.p4"
#include "metadata.p4"
#include "table-sizes.p4"

action act_mirror(
    inout ingress_metadata_t ig_md,
    mirror_mode_t mirror_mode,
    MirrorId_t mirror_session) {

    ig_md.mirror_mode = mirror_mode;
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
            hdr.ipv4.protocol  : ternary @name("protocol");
            ig_md.l4_lookup.word_1 : ternary @name("src_port");
            ig_md.l4_lookup.word_2 : ternary @name("dst_port");
        }
        actions = {
            act_mirror(ig_md);
            @defaultonly NoAction;
        }
        size = TBL_FLOW_MIRROR_SIZE;
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
    ip_proto_t protocol;

    table tbl_mirror_flows_ipv6 {
        key = {
            ig_intr_md.ingress_port : ternary @name("ingress_port");
            hdr.ipv6.src_addr  : ternary @name("src_addr");
            hdr.ipv6.dst_addr  : ternary @name("dst_addr");
            protocol           : ternary @name("protocol");
            ig_md.l4_lookup.word_1 : ternary @name("src_port");
            ig_md.l4_lookup.word_2 : ternary @name("dst_port");
        }
        actions = {
            act_mirror(ig_md);
            @defaultonly NoAction;
        }
        size = TBL_FLOW_MIRROR_SIZE;
        const default_action = NoAction;
    }

    apply {
        if (hdr.ipv6_frag.isValid()){
            protocol = hdr.ipv6_frag.next_hdr;
        } else {
            protocol = hdr.ipv6.next_hdr;
        }
        tbl_mirror_flows_ipv6.apply();
    }
}

control ctl_mirror_flows_non_ip(
    in headers hdr,
    in ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_metadata_t ig_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    ethertype_t ethertype;

    table tbl_mirror_flows_non_ip {
        key = {
            ig_intr_md.ingress_port   : ternary @name("ingress_port");
            hdr.ethernet.src_mac_addr : ternary @name("src");
            hdr.ethernet.dst_mac_addr : ternary @name("dst");
            ethertype                 : ternary @name("type");
        }
        actions = {
            act_mirror(ig_md);
            @defaultonly NoAction;
        }
        size = TBL_FLOW_MIRROR_SIZE;
        const default_action = NoAction;
    }

    apply {
        if (hdr.vlan.isValid()) {
            ethertype = hdr.vlan.ethertype;
        } else{
            ethertype = hdr.ethernet.ethertype;
        }
        tbl_mirror_flows_non_ip.apply();
    }
}

#endif // _MIRROR_P4_
