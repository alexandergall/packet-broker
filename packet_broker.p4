/* -*- mode: P4_16 -*- */

#include <core.p4>
#include <tofino.p4>
#include <tna.p4>

#include "include/types.p4"
#include "include/protocol_headers.p4"
#include "include/metadata.p4"
#include "include/headers.p4"

#include "include/parser.p4"
#include "include/drop.p4"
#include "include/vlan.p4"
#include "include/filter.p4"
#include "include/hash.p4"
#include "include/forward.p4"
#include "include/egress.p4"
#include "include/mirror.p4"

control ig_ctl(
    inout headers hdr, inout ingress_metadata_t ig_md,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
    bit<32> sel_hash = 0;

    apply {
        if (ig_prsr_md.parser_err != PARSER_ERROR_OK) {
            // Fail hard if the parser terminated with an error
            ig_dprsr_md.drop_ctl = 1;
            exit;
        }

        ctl_maybe_drop_fragment.apply(ig_md);
        ctl_maybe_exclude_l4_from_hash.apply(ig_md);
        ctl_push_or_rewrite_vlan.apply(hdr, ig_intr_md, ig_md);
        
        if (hdr.ipv4.isValid()) {
            ctl_filter_source_ipv4.apply(hdr, ig_md);
            ctl_calc_ipv4_hash.apply(hdr, ig_md, sel_hash);
            ctl_mirror_flows_ipv4.apply(hdr, ig_md, ig_dprsr_md);
        } else if (hdr.ipv6.isValid()) {
            ctl_filter_source_ipv6.apply(hdr, ig_md);
            ctl_calc_ipv6_hash.apply(hdr, ig_md, sel_hash);
            ctl_mirror_flows_ipv6.apply(hdr, ig_md, ig_dprsr_md);
        } else {
            ctl_calc_ethernet_hash.apply(hdr, sel_hash);
            ctl_maybe_drop_non_ip.apply(ig_md);
        }
        ctl_forward_packet.apply(ig_intr_md, sel_hash, ig_md, ig_tm_md);

        // Some of the controls above can request the packet to
        // be dropped (or sent to a port for inspection).  The
        // drop is enforced in the traffic manager.
        if (ig_md.drop == 1) {
            ctl_drop_packet.apply(ig_dprsr_md, ig_tm_md);
        }
    }
    
}

control ig_ctl_dprs(
    packet_out pkt,
    inout headers hdr,
    in ingress_metadata_t ig_md,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Mirror() mirror;

    apply {
        if (ig_dprsr_md.mirror_type == (bit<3>)mirror_session_t.FLOW) {
            mirror.emit<mirror_header_t>(ig_md.mirror_session, {});
        }
        pkt.emit(hdr);
    }
}

Pipeline(
    ig_prs(), ig_ctl(), ig_ctl_dprs(),
    eg_prs(), eg_ctl(), eg_ctl_dprs()) pipe;

Switch(pipe) main;
