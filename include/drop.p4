/* -*- mode: P4_16 -*- */

#ifndef _DROP_P4_ 
#define _DROP_P4_ 

#include "metadata.p4"

action act_mark_to_drop(inout ingress_metadata_t ig_md) {
    ig_md.drop = 1;
}

control ctl_drop_packet(
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
    action real_drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action send_to_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table tbl_drop {
        actions = {
            real_drop;
            send_to_port;
        }
        default_action = real_drop;
    }

    apply {
        tbl_drop.apply();
    }
}

control ctl_maybe_drop_fragment(inout ingress_metadata_t ig_md)
{
    table tbl_maybe_drop_fragment {
        actions = {
            act_mark_to_drop(ig_md);
            NoAction;
        }
        size = 1;
        default_action = NoAction;
    }

    apply {
        if (ig_md.non_first_fragment == 1) {
            tbl_maybe_drop_fragment.apply();
        }
    }
}

control ctl_maybe_drop_non_ip(inout ingress_metadata_t ig_md)
{
    table tbl_maybe_drop_non_ip {
        actions = {
            act_mark_to_drop(ig_md);
            NoAction;
        }
        size = 1;
        default_action = NoAction;
    }

    apply {
        tbl_maybe_drop_non_ip.apply();
    }
}

#endif // _DROP_P4_
