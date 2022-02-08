/* -*- mode: P4_16 -*- */

#ifndef _HASH_P4_ 
#define _HASH_P4_ 

#include "metadata.p4"
#include "headers.p4"

CRCPolynomial<bit<32>>(
    coeff    = 0x04C11DB7,
    reversed = true,
    msb      = false,
    extended = false,
    init     = 0xFFFFFFFF,
    xor      = 0xFFFFFFFF) poly;

control ctl_maybe_exclude_l4_from_hash(inout ingress_metadata_t ig_md)
{
    action act_exclude_l4() {
        ig_md.l4_lookup = { 0, 0};
    }
    
    table tbl_maybe_exclude_l4 {
        actions = {
            act_exclude_l4;
            NoAction;
        }
        size = 1;
        default_action = NoAction;
    }

    apply {
        tbl_maybe_exclude_l4.apply();
    }
}

control ctl_calc_ipv4_hash(
    in headers hdr,
    in ingress_metadata_t ig_md,
    inout bit<32> sel_hash)
{
    Hash<bit<32>>(HashAlgorithm_t.CRC32, poly) hash;
    
    apply {
        sel_hash = hash.get(
            {
                hdr.ipv4.src_addr,
                hdr.ipv4.dst_addr,
                hdr.ipv4.protocol,
                ig_md.l4_lookup.word_1,
                ig_md.l4_lookup.word_2
            }
        );
    }
}

control ctl_calc_ipv6_hash(
    in headers hdr,
    in ingress_metadata_t ig_md,
    inout bit<32> sel_hash)
{
    Hash<bit<32>>(HashAlgorithm_t.CRC32, poly) hash;

    apply {
        ip_proto_t ulp = hdr.ipv6.next_hdr;

        if (hdr.ipv6_frag.isValid()) {
            ulp = hdr.ipv6_frag.next_hdr;
        }
        sel_hash = hash.get(
            {
                hdr.ipv6.src_addr,
                hdr.ipv6.dst_addr,
                ulp,
                ig_md.l4_lookup.word_1,
                ig_md.l4_lookup.word_2
            }
        );
    }
}

control ctl_calc_ethernet_hash(in headers hdr, out bit<32> sel_hash)
{
    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash;

    apply {
        sel_hash = hash.get(
            {
                hdr.ethernet.dst_mac_addr,
                hdr.ethernet.src_mac_addr,
                hdr.ethernet.ethertype
            }
        );
    }
}

#endif // _HASH_P4_
