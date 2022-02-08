/* -*- mode: P4_16 -*- */

#ifndef _EGRESS_P4_
#define _EGRESS_P4_

#include <core.p4>

// We don't use any egress processing, but these declarations
// are required by the TNA.

struct egress_headers_t {
}

struct egress_metadata_t {
}

parser eg_prs(packet_in pkt,
    /* User */
    out egress_headers_t eg_hdr, out egress_metadata_t eg_md,
    /* Intrinsic */
    out egress_intrinsic_metadata_t eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control eg_ctl(
    /* User */
    inout egress_headers_t eg_hdr, inout egress_metadata_t eg_md,
    /* Intrinsic */
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t eg_oport_md)
{
    apply {
    }
}


control eg_ctl_dprs(packet_out pkt,
    /* User */
    inout egress_headers_t eg_hdr, in egress_metadata_t eg_md,
    /* Intrinsic */
    in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    apply {
        pkt.emit(eg_hdr);
    }
}

#endif // _EGRESS_P4_
