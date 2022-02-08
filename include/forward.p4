/* -*- mode: P4_16 -*- */

#ifndef _FORWARD_P4_ 
#define _FORWARD_P4_ 

#include "metadata.p4"
#include "drop.p4"

#define MAX_OUTPUT_PORTS 16
#define MAX_PORTS_PER_OUTPUT_GROUP 16
#define MAX_OUTPUT_GROUPS 8

control ctl_forward_packet(
    in ingress_intrinsic_metadata_t ig_intr_md,
    in bit<32> sel_hash,
    inout ingress_metadata_t ig_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md)
{
    port_group_t egress_group = 0;
    
    action act_output_group(port_group_t group) {
        egress_group = group;
    }
    
    table tbl_select_output {
        key = {
            ig_intr_md.ingress_port : exact @name("ingress_port");
        }
        actions = {
            act_output_group;
            @defaultonly act_mark_to_drop(ig_md);
        }
        const default_action = act_mark_to_drop(ig_md);
    }
    
    action act_send(PortId_t egress_port) {
        ig_tm_md.ucast_egress_port = egress_port;
        ig_tm_md.bypass_egress = 1;
    }
    
    // 14 hash bits are required by Tofino for fair-hashing with at
    // most 120 ports per group. Use IDENTITY hash here because
    // the hash has been pre-computed (passed in sel_hash)
    Hash<bit<14>> (HashAlgorithm_t.IDENTITY) final_hash;
    
    ActionProfile(size = MAX_OUTPUT_PORTS) port_groups;
    ActionSelector(action_profile = port_groups,
        hash = final_hash,
        mode = SelectorMode_t.FAIR,
        max_group_size = MAX_PORTS_PER_OUTPUT_GROUP,
        num_groups = MAX_OUTPUT_GROUPS) port_groups_sel;
    
    table tbl_forward {
        key = {
            egress_group : exact;
            sel_hash     : selector;
        }
        actions = {
            act_send;
            @defaultonly act_mark_to_drop(ig_md);
        }
        size = 256;
        implementation = port_groups_sel;
        const default_action = act_mark_to_drop(ig_md);
    }

    apply {
        tbl_select_output.apply();
        tbl_forward.apply();
    }     
}

#endif // _FORWARD_P4_
