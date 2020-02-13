/* -*- mode: P4_16 -*- */

#ifndef _FILTER_P4_ 
#define _FILTER_P4_ 

#include "metadata.p4"
#include "headers.p4"
#include "drop.p4"

DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) filter_ipv4_stats;

control ctl_filter_source_ipv4(
    in headers hdr,
    inout ingress_metadata_t ig_md)
{
    action act_drop() {
        filter_ipv4_stats.count();
        act_mark_to_drop(ig_md);
    }
    
    table tbl_filter_source_ipv4 {
        key = {
            hdr.ipv4.src_addr : lpm;
        }
        actions = {
            act_drop();
            @defaultonly NoAction;
        }
        counters = filter_ipv4_stats;
        const default_action = NoAction;
    }

    apply {
        tbl_filter_source_ipv4.apply();
    }
}

DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) filter_ipv6_stats;

control ctl_filter_source_ipv6(
    in headers hdr,
    inout ingress_metadata_t ig_md)
{
    action act_drop() {
        filter_ipv6_stats.count();
        act_mark_to_drop(ig_md);
    }
    
    table tbl_filter_source_ipv6 {
        key = {
            hdr.ipv6.src_addr : lpm;
        }
        actions = {
            act_drop();
            @defaultonly NoAction;
        }
        counters = filter_ipv6_stats;
        const default_action = NoAction;
    }

    apply {
        tbl_filter_source_ipv6.apply();
    }
}

#endif // _FILTER_P4_
