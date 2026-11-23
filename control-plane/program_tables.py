### Names and field annotations of the program-dependent P4
### tables. These have to be kept in sync with the P4 code.

ctls = {
    'vlan' : 'pipe.ig_ctl.ctl_push_or_rewrite_vlan',
    'forward' : 'pipe.ig_ctl.ctl_forward_packet',
    'filter_ipv4' : 'pipe.ig_ctl.ctl_filter_source_ipv4',
    'filter_ipv6' : 'pipe.ig_ctl.ctl_filter_source_ipv6',
    'mirror_ipv4' : 'pipe.ig_ctl.ctl_mirror_flows_ipv4',
    'mirror_ipv6' : 'pipe.ig_ctl.ctl_mirror_flows_ipv6',
    'mirror_non_ip' : 'pipe.ig_ctl.ctl_mirror_flows_non_ip',
    'mirror_encap': 'pipe.eg_ctl.ctl_mirror_encap',
    'maybe_exclude_l4_from_hash' : 'pipe.ig_ctl.ctl_maybe_exclude_l4_from_hash',
    'maybe_drop_fragment' : 'pipe.ig_ctl.ctl_maybe_drop_fragment',
    'maybe_drop_non_ip' : 'pipe.ig_ctl.ctl_maybe_drop_non_ip',
    'drop' : 'pipe.ig_ctl.ctl_drop_packet'
}
tables = {
    ### Program tables
    ## Keys: ingress_port
    'ingress_untagged': ctls['vlan'] + '.tbl_ingress_untagged',
    ## Keys: ingress_port, ingress_vid
    'ingress_tagged': ctls['vlan'] + '.tbl_ingress_tagged',
    ## Keys: ingress_port, ingress_vid, src_mac_addr
    'ingress_src_mac_rewrite': ctls['vlan'] + '.tbl_ingress_src_mac_rewrite',
    ## Keys: ingress_port, ingress_vid, src_mac_addr
    'ingress_dst_mac_rewrite': ctls['vlan'] + '.tbl_ingress_dst_mac_rewrite',
    ## Keys: src_addr
    'filter_ipv4': ctls['filter_ipv4'] + '.tbl_filter_source_ipv4',
    ## Keys: src_addr
    'filter_ipv6': ctls['filter_ipv6'] + '.tbl_filter_source_ipv6',
    ## Keys: src_addr, dst_addr, src_port, dst_port
    'mirror_ipv4': ctls['mirror_ipv4'] + '.tbl_mirror_flows_ipv4',
    ## Keys: src_addr, dst_addr, src_port, dst_port
    'mirror_ipv6': ctls['mirror_ipv6'] + '.tbl_mirror_flows_ipv6',
    ## Keys: ingress_port, src_mac, dst_mac, ethertype
    'mirror_non_ip': ctls['mirror_non_ip'] + '.tbl_mirror_flows_non_ip',
    ## Keys: mirror_session
    'mirror_encap_l2': ctls['mirror_encap'] + '.tbl_mirror_encap_l2',
    ## Keys: mirror_session
    'mirror_encap_l3': ctls['mirror_encap'] + '.tbl_mirror_encap_l3',
    ## Keys: mirror_session
    'mirror_encap_l4': ctls['mirror_encap'] + '.tbl_mirror_encap_l4',
    ## Keys: ingress_port
    'select_output': ctls['forward'] + '.tbl_select_output',
    ## Keys: egress_group
    'forward': ctls['forward'] + '.tbl_forward',
    ## Keys: $ACTION_MEMBER_ID
    'port_groups': ctls['forward'] + '.port_groups',
    ## Keys: $SELECTOR_GROUP_ID
    'port_groups_sel': ctls['forward'] + '.port_groups_sel',
    ## Keys: None
    'maybe_exclude_l4': ctls['maybe_exclude_l4_from_hash'] + '.tbl_maybe_exclude_l4',
    ## Keys: None
    'drop': ctls['drop'] + '.tbl_drop',
    ## Keys: None
    'maybe_drop_fragment': ctls['maybe_drop_fragment'] + '.tbl_maybe_drop_fragment',
    ## Keys: None
    'maybe_drop_non_ip': ctls['maybe_drop_non_ip'] + '.tbl_maybe_drop_non_ip',

    ### Register tables
    ### Key: register index
    'encap_sequence': ctls['mirror_encap'] + '.sequence'

}
field_annotations = {
    'ingress_src_mac_rewrite': {
        'key': [
            [ 'src_mac_addr', 'mac' ]
        ],
        'data': [
            [ 'mac_addr', 'act_rewrite_src_mac', 'mac' ],
        ]
    },
    'ingress_dst_mac_rewrite': {
        'key': [
            [ 'dst_mac_addr', 'mac' ]
        ],
        'data': [
            [ 'mac_addr', 'act_rewrite_dst_mac', 'mac' ],
        ]
    },
    'filter_ipv4': {
        'key': [
            [ 'src_addr', 'ipv4' ]
        ]
    },
    'filter_ipv6': {
        'key': [
            [ 'src_addr', 'ipv6' ]
        ]
    },
    'mirror_encap_l2': {
        'data': [
            [ 'src_mac', 'act_mirror_encap_l2', 'mac' ],
            [ 'dst_mac', 'act_mirror_encap_l2', 'mac' ],
            [ 'src_mac', 'act_mirror_encap_l2_vlan', 'mac' ],
            [ 'dst_mac', 'act_mirror_encap_l2_vlan', 'mac' ]
        ]
    },
    'mirror_encap_l3': {
        'data': [
            [ 'src', 'act_mirror_encap_ipv4', 'ipv4' ],
            [ 'dst', 'act_mirror_encap_ipv4', 'ipv4' ],
            [ 'src', 'act_mirror_encap_ipv6', 'ipv6' ],
            [ 'dst', 'act_mirror_encap_ipv6', 'ipv6' ]
        ]
    },
    'mirror_non_ip': {
        'key': [
            [ 'src', 'mac' ],
            [ 'dst', 'mac' ]
        ]
    },
    'mirror_ipv4': {
        'key': [
            [ 'src_addr', 'ipv4' ],
            [ 'dst_addr', 'ipv4' ]
        ]
    },
    'mirror_ipv6': {
        'key': [
            [ 'src_addr', 'ipv6' ],
            [ 'dst_addr', 'ipv6' ]
        ]
    },
    'filter_ipv4': {
        'key': [
            [ 'src_addr', 'ipv4' ]
        ]
    },
    'filter_ipv6': {
        'key': [
            [ 'src_addr', 'ipv6' ]
        ]
    }
}
