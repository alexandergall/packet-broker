/* -*- mode: P4_16 -*- */

#ifndef _PARSER_P4_ 
#define _PARSER_P4_ 

#include "headers.p4"
#include "metadata.p4"

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
        ig_md.l4_lookup          = { 0, 0 };
        ig_md.non_first_fragment = 0;
        ig_md.drop               = 0;
        ig_md.mirror_session     = 0;

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
        pkt.extract(hdr.ipv4_options, ((bit<32>)hdr.ipv4.ihl - 5) * 32);
        
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

#endif // _PARSER_P4_
