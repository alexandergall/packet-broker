/* -*- mode: P4-16 -*- */

#ifndef _MIRROR_ENCAP_P4_
#define _MIRROR_ENCAP_P4_

#include "types.p4"
#include "headers.p4"

control ctl_mirror_encap(
    inout erspan_headers hdr,
    inout egress_metadata_t eg_md,
    in    egress_intrinsic_metadata_t eg_intr_md)
{

    // Size of the encapsulated packet adjusted for the mirror header.
    // Somehow, this number is off by 4 bytes. Don't understand why :/
    bit<16> encap_packet_length = eg_intr_md.pkt_length - (bit<16>)eg_md.mirror.minSizeInBytes() - 4;

    // One sequence number counter per mirror session. Caveat: mirror
    // sessions start at 1 but the register array index starts at
    // 0. We want to use the same index for both.
    Register<bit<32>, MirrorId_t>(TBL_MIRROR_SESSIONS_SIZE+1) sequence;
    RegisterAction<bit<32>, MirrorId_t, bit<32>>(sequence) ract_inc_seq = {
        void apply(inout bit<32> in_seq, out bit<32> seq) {
            seq = in_seq + 1;
            in_seq = seq;
        }
    };

    action act_mirror_encap_l2 (
        mac_addr_t src_mac,
        mac_addr_t dst_mac,
        ethertype_t ethertype
    ) {
        hdr.ethernet.setValid();
        hdr.ethernet = { dst_mac, src_mac, ethertype };
    }

    action act_mirror_encap_l2_vlan (
        mac_addr_t src_mac,
        mac_addr_t dst_mac,
        ethertype_t ethertype,
        vlan_id_t vid
    ) {
        hdr.ethernet.setValid();
        hdr.ethernet = { dst_mac, src_mac, ethertype_t.VLAN };
        hdr.vlan.setValid();
        hdr.vlan = { 0, 0, vid, ethertype };
    }

    action act_mirror_encap_ipv4(
        ipv4_addr_t src,
        ipv4_addr_t dst,
        ip_proto_t proto,
        bit<16> length,
        bit<8> ttl
    ) {
        hdr.ipv4.setValid();
        hdr.ipv4 = {
            4, 5, 0, // version, ihl, diffserv
            length + encap_packet_length,
            0, // id
            2, // flags: don't fragment
            0, // fragment offset
            ttl, proto, 0, // TTL, protocol, checksum
            src, dst
        };
    }

    action act_mirror_encap_ipv6(
        ipv6_addr_t src,
        ipv6_addr_t dst,
        ip_proto_t proto,
        bit<16> length,
        bit<8> ttl
    ) {
        hdr.ipv6.setValid();
        hdr.ipv6 = {
            6, 0, 0, // version, traffic_class, flow_label
            length + encap_packet_length,
            proto, ttl, src, dst
        };
    }

    action act_mirror_encap_erspan(
        bit<10> session
    ) {
        hdr.gre.base.setValid();
        hdr.gre.base = {
            0, 0, 0, 1, 0, 0, // sequence number present
            ethertype_t.ERSPAN_II
        };
        hdr.gre.sequence.setValid();
        hdr.gre.sequence.sequence = ract_inc_seq.execute(eg_md.mirror.session);
        hdr.erspan.setValid();
        hdr.erspan = {
            1, // version ERSPAN type II
            0, // original VLAN
            0, // original COS
            3, // encapsulation: preserve VLAN
               // VLAN/COS irrelevant in this mode
            0, // truncation flag, not supported
            session, // session ID
            0, // reserved
            0  // index, unused
        };
    }

    table tbl_mirror_encap_l2 {
        key = {
            eg_md.mirror.session : exact @name("mirror_session");
        }
        actions = {
            act_mirror_encap_l2;
            act_mirror_encap_l2_vlan;
            @defaultonly NoAction;
        }
        size = TBL_MIRROR_SESSIONS_SIZE;
        const default_action = NoAction;
    }

    table tbl_mirror_encap_l3 {
        key = {
            eg_md.mirror.session : exact @name("mirror_session");
        }
        actions = {
            act_mirror_encap_ipv4;
            act_mirror_encap_ipv6;
            @defaultonly NoAction;
        }
        size = TBL_MIRROR_SESSIONS_SIZE;
        const default_action = NoAction;
    }

    table tbl_mirror_encap_l4 {
        key = {
            eg_md.mirror.session : exact @name("mirror_session");
        }
        actions = {
            act_mirror_encap_erspan;
            @defaultonly NoAction;
        }
        size = TBL_MIRROR_SESSIONS_SIZE;
        const default_action = NoAction;
    }

    apply {
        tbl_mirror_encap_l2.apply();
        tbl_mirror_encap_l3.apply();
        tbl_mirror_encap_l4.apply();
    }

}

#endif // _MIRROR_ENCAP_P4_
