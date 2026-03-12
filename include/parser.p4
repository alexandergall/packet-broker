/* -*- mode: P4-16 -*- */

#ifndef _PARSER_P4_ 
#define _PARSER_P4_ 

#include "types.p4"
#include "headers.p4"
#include "metadata.p4"

//
// Ingress
//

parser ig_prs(
    packet_in pkt,
    out headers hdr,
    out ingress_metadata_t ig_md,
    out ingress_intrinsic_metadata_t ig_intr_md)
{
    /* This is a mandatory state, required by the Tofino Architecture */
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        
        transition meta_init;
    }

    state meta_init {
        packet_type_t packet_type_mirror = packet_types.MIRROR;
        mirror_mode_t mirror_mode_none = mirror_modes.NONE;
        ig_md = { { 0, 0 }, 0, 0, packet_type_mirror, mirror_mode_none, 0 };

        transition prs_ethernet;
    }
    
    state prs_ethernet {
        pkt.extract(hdr.ethernet);
        
        transition select(hdr.ethernet.ethertype) {
            ethertype_t.VLAN: prs_vlan;
            ethertype_t.IPV4: prs_ipv4;
            ethertype_t.IPV6: prs_ipv6;
            default: accept;
        }
    }

    state prs_vlan {
        pkt.extract(hdr.vlan);

        transition select(hdr.vlan.ethertype) {
            ethertype_t.IPV4: prs_ipv4;
            ethertype_t.IPV6: prs_ipv6;
            default: accept;
        }
    }

    state prs_ipv4 {
        pkt.extract(hdr.ipv4);
        
        transition select(hdr.ipv4.ihl) {
            5         : prs_ipv4_no_options;
            6 &&& 0xE : prs_ipv4_options;
            8 &&& 0x8 : prs_ipv4_options;
            default   : reject;
        }
    }
    
    state prs_ipv4_options {
        pkt.extract(hdr.ipv4_options, ((bit<32>)(hdr.ipv4.ihl - 5) * 32));
        
        transition prs_ipv4_no_options;
    }
    
    state prs_ipv4_no_options {
        transition select(hdr.ipv4.frag_offset, hdr.ipv4.protocol) {
            ( 0, ip_proto_t.TCP  ) : prs_l4;
            ( 0, ip_proto_t.UDP  ) : prs_l4;
            ( 0, _ )               : accept;
            default: non_first_fragment;
        }
    }

    state prs_ipv6 {
        pkt.extract(hdr.ipv6);
        
        transition select(hdr.ipv6.next_hdr) {
            ip_proto_t.TCP: prs_l4;
            ip_proto_t.UDP: prs_l4;
            ip_proto_t.IPV6_FRAG : prs_ipv6_frag;
            default: accept;
        }
    }

    state prs_ipv6_frag {
        pkt.extract(hdr.ipv6_frag);

        transition select(hdr.ipv6_frag.offset, hdr.ipv6_frag.next_hdr) {
            ( 0, ip_proto_t.TCP ) : prs_l4;
            ( 0, ip_proto_t.UDP ) : prs_l4;
            ( 0, _ )              : accept;
            default: non_first_fragment;
        }
    }

    state non_first_fragment {
        ig_md.non_first_fragment = 1;

        transition accept;
    }
    
    state prs_l4 {
        ig_md.l4_lookup = pkt.lookahead<l4_lookup_t>();
        
        transition accept;
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
        if (ig_dprsr_md.mirror_type == DPRSR_MIRROR_TYPE) {
            // The mirrored packet contains the originial unmodified
            // packet with the packet type set to MIRROR in the
            // metadata header.
            mirror.emit<mirror_t>(ig_md.mirror_session,
                { ig_md.packet_type, ig_md.mirror_session });
        }
        pkt.emit(hdr);
    }
}

//
// Egress
//

parser eg_prs(
    packet_in pkt,
    out erspan_headers hdr,
    out egress_metadata_t eg_md,
    out egress_intrinsic_metadata_t eg_intr_md)
{
    state start {
        pkt.extract(eg_intr_md);
        eg_md.packet_type = packet_types.MIRROR;
        transition select(pkt.lookahead<packet_type_t>()) {
            packet_types.BRIDGE: prs_bridge;
            packet_types.MIRROR: prs_mirror;
        }
    }

    state prs_bridge {
        pkt.extract(eg_md.bridge);
        transition accept;
    }

    state prs_mirror {
        pkt.extract(eg_md.mirror);
        transition accept;
    }
}

control eg_ctl_dprs(
    packet_out pkt,
    inout erspan_headers hdr,
    in egress_metadata_t eg_md,
    in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md)
{
    Mirror() mirror;
    Checksum() ipv4_checksum;

    apply {
        if (eg_dprsr_md.mirror_type == DPRSR_MIRROR_TYPE) {
            // The mirrored packet contains the fully processed packet
            // with the packet type set to MIRROR in the metadata
            // header.
            mirror.emit<mirror_t>(eg_md.bridge.eg_mirror_session,
                { eg_md.packet_type, eg_md.bridge.eg_mirror_session });
        }
        if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdr_checksum = ipv4_checksum.update({
                    hdr.ipv4.version,
                    hdr.ipv4.ihl,
                    hdr.ipv4.diffserv,
                    hdr.ipv4.total_len,
                    hdr.ipv4.identification,
                    hdr.ipv4.flags,
                    hdr.ipv4.frag_offset,
                    hdr.ipv4.ttl,
                    hdr.ipv4.protocol,
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
           });
        }
        pkt.emit(hdr);
    }
}

#endif // _PARSER_P4_
