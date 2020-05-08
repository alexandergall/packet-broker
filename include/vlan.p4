/* -*- mode: P4_16 -*- */

#ifndef _VLAN_P4_ 
#define _VLAN_P4_ 

#include <tofino.p4>
#include "metadata.p4"
#include "drop.p4"

control ctl_push_or_rewrite_vlan(
    inout headers hdr,
    in ingress_intrinsic_metadata_t ig_intr_md,
    inout ingress_metadata_t ig_md)
{
    action act_push_vlan(vlan_id_t vid) {
        hdr.vlan.ethertype = hdr.ethernet.ethertype;
        hdr.vlan.vid = vid;
        hdr.ethernet.ethertype = ethertype_t.VLAN;
        hdr.vlan.setValid();
    }
    
    table tbl_ingress_untagged {
        key = {
            ig_intr_md.ingress_port : exact @name("ingress_port");
        }
        actions = {
            act_push_vlan;
            @defaultonly act_mark_to_drop(ig_md);
        }
        const default_action = act_mark_to_drop(ig_md);
    }
    
    action act_rewrite_vlan(vlan_id_t vid) {
        hdr.vlan.vid = vid;
    }
    
    table tbl_ingress_tagged {
        key = {
            ig_intr_md.ingress_port : exact @name("ingress_port");
            hdr.vlan.vid            : exact @name("ingress_vid");
        }
        actions = {
            act_rewrite_vlan;
            @defaultonly act_mark_to_drop(ig_md);
        }
        const default_action = act_mark_to_drop(ig_md);
    }

    action act_rewrite_src_mac(mac_addr_t mac_addr) {
        hdr.ethernet.src_mac_addr = mac_addr;
    }

    action act_rewrite_dst_mac(mac_addr_t mac_addr) {
        hdr.ethernet.dst_mac_addr = mac_addr;
    }

    table tbl_ingress_src_mac_rewrite {
        key = {
            ig_intr_md.ingress_port   : exact @name("ingress_port");
            hdr.vlan.vid              : exact @name("ingress_vid");
            hdr.ethernet.src_mac_addr : exact @name("src_mac_addr");
        }
        actions = {
            act_rewrite_src_mac;
            @defaultonly NoAction;
        }
        const default_action = NoAction;
    }

    table tbl_ingress_dst_mac_rewrite {
        key = {
            ig_intr_md.ingress_port   : exact @name("ingress_port");
            hdr.vlan.vid              : exact @name("ingress_vid");
            hdr.ethernet.dst_mac_addr : exact @name("dst_mac_addr");
        }
        actions = {
            act_rewrite_dst_mac;
            @defaultonly NoAction;
        }
        const default_action = NoAction;
    }

    apply {
        if (hdr.vlan.isValid()) {
            tbl_ingress_src_mac_rewrite.apply();
            tbl_ingress_dst_mac_rewrite.apply();
            tbl_ingress_tagged.apply();
        } else {
            tbl_ingress_untagged.apply();
        }
    }     
}

#endif // _VLAN_P4_
