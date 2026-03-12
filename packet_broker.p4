/* -*- mode: P4-16 -*- */

#include <core.p4>
#if __TARGET_TOFINO__ == 3
#include <t3na.p4>
#elif __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

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
#include "include/mirror.p4"
#include "include/mirror-encap.p4"

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
            ctl_mirror_flows_ipv4.apply(hdr, ig_intr_md, ig_md, ig_dprsr_md);
        } else if (hdr.ipv6.isValid()) {
            ctl_filter_source_ipv6.apply(hdr, ig_md);
            ctl_calc_ipv6_hash.apply(hdr, ig_md, sel_hash);
            ctl_mirror_flows_ipv6.apply(hdr, ig_intr_md, ig_md, ig_dprsr_md);
        } else {
            ctl_calc_ethernet_hash.apply(hdr, sel_hash);
            ctl_mirror_flows_non_ip.apply(hdr, ig_intr_md, ig_md, ig_dprsr_md);
            ctl_maybe_drop_non_ip.apply(ig_md);
        }
        ctl_forward_packet.apply(ig_intr_md, sel_hash, ig_md, ig_tm_md);

        // Some of the controls above can request the packet to
        // be dropped (or sent to a port for inspection).  The
        // drop is enforced in the traffic manager.
        if (ig_md.drop == 1) {
            ctl_drop_packet.apply(ig_dprsr_md, ig_tm_md);
        }

        if (ig_md.mirror_mode == mirror_modes.INGRESS) {
            ig_dprsr_md.mirror_type = DPRSR_MIRROR_TYPE;
        }

        // Add the header for passing metadata from ingress to egress.
        hdr.bridge.setValid();
        hdr.bridge.packet_type = packet_types.BRIDGE;
        // A non-zero value of eg_mirror_session triggers egress
        // mirroring in the egress pipe. I.e. it needs to be zero for
        // non- or ingress-mirrored packets.
        if (ig_md.mirror_mode == mirror_modes.EGRESS) {
            hdr.bridge.eg_mirror_session = ig_md.mirror_session;
        } else {
            hdr.bridge.eg_mirror_session = 0;
        }
    }
}

// The egress pipeline is currently only used for packet mirroring. All
// packets entering the egress deparser have a header of either type
// "bridge" or "mirror". They have a common first element that designates
// the type of header.
//
// A bridge header is followed by a regular packet and a mirror header is
// followed by packet that was created by ingress or egress mirroring. A
// non-zero value of the eg_mirror_session field of a bridge header
// triggers mirroring of the packet in the egress deparser.
//
// For mirrored packets, the egress pipe can apply optional encapsulation
// based on the mirror session identifier to implement ERSPAN-type
// functionality.

control eg_ctl(
    inout erspan_headers hdr,
    inout egress_metadata_t eg_md,
    in    egress_intrinsic_metadata_t eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
    action act_eg_mirror() {
        // NOTE: eg_md.packet_type is initialized to MIRROR in the
        // ingress parser.
        eg_dprsr_md.mirror_type = DPRSR_MIRROR_TYPE;

        // Found this in the tna_mirror.p4 of the SDE p4-16 examples
        // collection. It doesn't seem to make a difference on the
        // Tofino model, but maybe it does on the hardware (didn't
        // check).
#if __TARGET_TOFINO__ == 2
        eg_dprsr_md.mirror_io_select = 1; // E2E mirroring for Tofino2
#endif
    }

    apply {
        if (eg_md.bridge.isValid() && eg_md.bridge.eg_mirror_session != 0) {
            // Egress mirroring was requested by the ingress pipe.
            act_eg_mirror();
        }
        if (eg_md.mirror.isValid()) {
           ctl_mirror_encap.apply(hdr, eg_md, eg_intr_md);
        }
    }
}

Pipeline(
    ig_prs(), ig_ctl(), ig_ctl_dprs(),
    eg_prs(), eg_ctl(), eg_ctl_dprs()) pipe;

Switch(pipe) main;
