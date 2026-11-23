import re
from copy import deepcopy
import logging

logger = logging.getLogger(__name__)

## Action data for the mirror_* tables to specify wheter packets
## should be mirrored on ingress or egress.
mirror_modes = {
    "ingress": 1,
    "egress":  2
}

## Mappings of values of the $SPEED field in the
## $PORT table to bps. Used in the ifMIB to set
## the ifSpeed/ifHighSpeed elements.
if_speed = {
    'BF_SPEED_NONE':                         0,
    'BF_SPEED_1G':                  1000000000,
    'BF_SPEED_10G':                10000000000,
    'BF_SPEED_25G':                25000000000,
    'BF_SPEED_40G':                40000000000,
    'BF_SPEED_40G_NB':             40000000000,
    'BF_SPEED_40G_NON_BREAKABLE':  40000000000,
    'BF_SPEED_50G':                50000000000,
    'BF_SPEED_100G':              100000000000,
    'BF_SPEED_200G':              200000000000,
    'BF_SPEED_400G':              400000000000,
    ## On Tofino2, some speeds can be realized in distinct
    ## configurations that use different numbers of lanes, e.g. 100G
    ## as 4x25 or 2x50. The following names are not legal values for
    ## $SPEED but appear with similar names in the bfshell port
    ## manager.
    'BF_SPEED_50G_R1':             50000000000, ## BF_SPEED_50G defaults to 2 lanes
    'BF_SPEED_100G_R2':           100000000000, ## BF_SPEED_100G defaults to 4 lanes
    'BF_SPEED_200G_R8':           200000000000, ## BF_SPEED_200G defaults to 4 lanes
}

class State:
    def __init__(self, bfrt, dev):
        self.t = bfrt.tables
        self.dev = dev
        ## Actual state
        self.system = {}
        self.ports = {}
        self.groups = {}
        self.groups_ref = {}
        self.ingress = {}
        self.source_filter = []
        self.monitor_sessions = {}
        self.flow_mirror = []
        self.features = {}

    def get_src_mac(self, dev_port):
        if 'port-macs' not in self.system:
            raise Exception('MAC address pool configuration required')
        if dev_port in self.system['port-macs']:
            return self.system['port-macs'][dev_port]
        try:
            mac = self.system['system-macs'].pop(0)
        except:
            raise Exception("Can't assign MAC address to port " +
                            f'{dev_port}, system pool exhausted')
        return mac

    def set_action_selector(self, method, group, members):
        id = [ member['id'] for member in members.values() ]
        status = [ member['status'] for member in members.values() ]
        method(
            [ { 'name': '$SELECTOR_GROUP_ID', 'value': group } ],
            None,
            [ { 'name': '$MAX_GROUP_SIZE', 'val': 8 },
              ## References action_member_ids from profile
              { 'name': '$ACTION_MEMBER_ID', 'int_arr_val': id },
              { 'name': '$ACTION_MEMBER_STATUS',
                'bool_arr_val': status } ])

    def apply(self, prev_state):
        t = self.t

        ### Action profile and selector
        ## Order matters here
        t.forward.clear()
        t.port_groups_sel.clear()
        t.port_groups.clear()

        member_id = 1
        for group, members in self.groups.items():
            ## Group is not referenced from
            ## the forwarding table
            self.groups_ref[group] = False
            for dev_port, member in members.items():
                member['id'] = member_id
                member['status'] = False
                t.port_groups.entry_add(
                    [ { 'name': '$ACTION_MEMBER_ID', 'value': member_id } ],
                    'act_send',
                    [ { 'name': 'egress_port', 'val': dev_port } ])
                member_id += 1
            self.set_action_selector(t.port_groups_sel.entry_add, group, members)

        t.select_output.clear()
        t.ingress_untagged.clear()
        t.ingress_src_mac_rewrite.clear()
        t.ingress_dst_mac_rewrite.clear()
        t.ingress_tagged.clear()
        for dev_port, dict in sorted(self.ingress.items()):
            vlans = dict['vlans']
            egress_group = dict['egress_group']
            t.select_output.entry_add(
                [ { 'name': 'ingress_port', 'value': dev_port } ],
                'act_output_group',
                [ { 'name': 'group', 'val': egress_group } ])

            if 'push' in vlans:
                t.ingress_untagged.entry_add(
                    [ { 'name': 'ingress_port', 'value': dev_port } ],
                    'act_push_vlan',
                    [ { 'name': 'vid', 'val': vlans['push'] } ])

            if 'accept' in vlans:
                for rule in vlans['accept']:
                    t.ingress_tagged.entry_add(
                        [ { 'name': 'ingress_port', 'value': dev_port },
                          { 'name': 'ingress_vid', 'value': rule['vid'],
                            'mask':  int(rule['mask'], 0) } ],
                        'NoAction')

            if 'rewrite' in vlans:
                for rule in vlans['rewrite']:
                    t.ingress_tagged.entry_add(
                        [ { 'name': 'ingress_port', 'value': dev_port },
                          { 'name': 'ingress_vid', 'value': rule['in'],
                            'mask': 4095 } ],
                        'act_rewrite_vlan',
                        [ { 'name': 'vid', 'val': rule['out'] } ])
                    rewrite = rule.get("mac-rewrite", {})
                    for dir, spec in rewrite.items():
                        ## Note: the rewrite table is applied before
                        ## the ingress_tagged table, hence the value
                        ## of the VLAN tag must be the one of the
                        ## original packet.
                        if dir == "src":
                            tbl = t.ingress_src_mac_rewrite
                        else:
                            tbl = t.ingress_dst_mac_rewrite
                        field = dir + "_mac_addr"
                        action = "act_rewrite_" + dir + "_mac"
                        for addr, new_addr in spec.items():
                            tbl.entry_add(
                                [ { 'name': 'ingress_port', 'value': dev_port },
                                  { 'name': 'ingress_vid', 'value': rule['in'] },
                                  { 'name': field, 'value': addr } ],
                                action,
                                [ { 'name': 'mac_addr', 'val': new_addr } ])

        t.filter_ipv4.clear()
        t.filter_ipv6.clear()
        for prefix in self.source_filter:
            if prefix.version == 4:
                tbl = t.filter_ipv4
            else:
                tbl = t.filter_ipv6
            tbl.entry_add(
                [ { 'name': 'src_addr', 'value': prefix.network_address.exploded,
                    'prefix_len': prefix.prefixlen } ],
                'act_drop', [])

        t.mirror_cfg.clear()
        t.mirror_ipv4.clear()
        t.mirror_ipv6.clear()
        t.mirror_non_ip.clear()
        t.mirror_encap_l2.clear()
        t.mirror_encap_l3.clear()
        t.mirror_encap_l4.clear()
        for session_name, session in self.monitor_sessions.items():
            ## Configure the mirror session parameters. We use BOTH as
            ## direction because a monitor session can contain
            ## flow-mirrors with either direction.
            mirror_session = session['mirror_session']
            t.mirror_cfg.entry_add(
                [ { 'name': '$sid', 'value': mirror_session } ],
                '$normal',
                [ { 'name': '$session_enable', 'bool_val': True },
                  { 'name': '$direction', 'str_val': "BOTH" },
                  { 'name': '$ucast_egress_port', 'val': session['egress-port'] },
                  { 'name': '$ucast_egress_port_valid', 'bool_val': True },
                  { 'name': '$max_pkt_len', 'val': session['max-packet-length'] } ])

            if 'encapsulation' in session:
                encap = session['encapsulation']['erspan']

                ### L2
                if encap['ip']['src'].version == 4:
                    ethertype = 0x0800
                else:
                    ethertype = 0x86dd
                if 'vlan' not in encap['ethernet']:
                    t.mirror_encap_l2.entry_add(
                        [ { 'name': 'mirror_session', 'value': mirror_session } ],
                        'act_mirror_encap_l2',
                        [ { 'name': 'src_mac', 'val': encap['ethernet']['src'] },
                          { 'name': 'dst_mac', 'val': encap['ethernet']['dst'] },
                          { 'name': 'ethertype', 'val': ethertype } ])
                else:
                    t.mirror_encap_l2.entry_add(
                        [ { 'name': 'mirror_session', 'value': mirror_session } ],
                        'act_mirror_encap_l2_vlan',
                        [ { 'name': 'src_mac', 'val': encap['ethernet']['src'] },
                          { 'name': 'dst_mac', 'val': encap['ethernet']['dst'] },
                          { 'name': 'ethertype', 'val': ethertype },
                          { 'name': 'vid', 'val': encap['ethernet']['vlan'] } ])

                ### L3
                if encap['ip']['src'].version == 4:
                    action = 'act_mirror_encap_ipv4'
                    ## total length: IP(20) + GRE(8) + ERSPAN(8)
                    length = 36
                else:
                    action = 'act_mirror_encap_ipv6'
                    ## payload length: GRE(8) + ERSPAN(8)
                    length = 16
                t.mirror_encap_l3.entry_add(
                    [ { 'name': 'mirror_session', 'value': mirror_session } ],
                    action,
                    [ { 'name': 'src', 'val': encap['ip']['src'].exploded },
                      { 'name': 'dst', 'val': encap['ip']['dst'].exploded },
                      ## IP protocol number for GRE
                      { 'name': 'proto', 'val': 47 },
                      { 'name': 'length', 'val': length },
                      { 'name': 'ttl', 'val': encap['ip']['ttl'] } ])

                ### L4
                if encap['reset-seq']:
                    reg_name = t.encap_sequence.__dict__['loc'].removeprefix('pipe.') + '.f1'
                    t.encap_sequence.entry_mod(
                        [ { 'name': '$REGISTER_INDEX', 'value': mirror_session } ],
                        None,
                        [ { 'name': reg_name, 'val': 0 } ]
                    )
                    logger.info(f'Reset sequence number for new ERSPAN session {session_name}')
                t.mirror_encap_l4.entry_add(
                    [ { 'name': 'mirror_session', 'value':   mirror_session} ],
                    'act_mirror_encap_erspan',
                    [ { 'name': 'session', 'val': int(encap['session-id']) } ])

        for flow in self.flow_mirror:
            if not flow['enable']:
                continue
            mirror_session = self.monitor_sessions[flow['monitor-session']]['mirror_session']
            ports = flow['ingress-ports']
            port_mask = 0x1ff;
            if len(ports) == 0:
                ports = [ 0 ]
                port_mask = 0

            rules = flow['rules']
            mirror_mode = mirror_modes[flow['mirror-mode']]
            for port in ports:
                if flow['rule-type'] == 'l3':
                    if rules['af'] == 4:
                        tbl = t.mirror_ipv4
                    else:
                        tbl = t.mirror_ipv6
                    def add_with_proto(value, mask):
                        tbl.entry_add(
                            [ { 'name': 'ingress_port',
                                'value': port,
                                'mask': port_mask },
                              { 'name': 'src_addr',
                                'value': rules['src'],
                                'mask': rules['src-mask'] },
                              { 'name': 'dst_addr',
                                'value': rules['dst'],
                                'mask': rules['dst-mask'] },
                              { 'name': 'protocol',
                                'value': value,
                                'mask': mask },
                              { 'name': 'src_port',
                                'value': rules['src-port']['port'],
                                'mask': int(rules['src-port']['mask'], 0) },
                              { 'name': 'dst_port',
                                'value': rules['dst-port']['port'],
                                'mask': int(rules['dst-port']['mask'], 0) } ],
                            'act_mirror',
                            [ { 'name': 'mirror_session', 'val': mirror_session },
                              { 'name': 'mirror_mode' , 'val': mirror_mode } ])
                    if rules['protocols']:
                        for protocol in rules['protocols']:
                            add_with_proto(protocol, 0xFF)
                    else:
                        add_with_proto(0, 0)
                else:
                    rules = flow['rules']
                    t.mirror_non_ip.entry_add(
                        [ { 'name': 'ingress_port',
                            'value': port,
                            'mask': port_mask },
                          { 'name': 'src',
                            'value': rules['src']['address'],
                            'mask': rules['src']['mask'] },
                          { 'name': 'dst',
                            'value': rules['dst']['address'],
                            'mask': rules['dst']['mask'] },
                          { 'name': 'type',
                            'value': 0 if rules['type'] is None else int(rules['type'], 0),
                            'mask': 0 if rules['type'] is None else 0xFFFF },
                         ],
                        'act_mirror',
                        [ { 'name': 'mirror_session', 'val': mirror_session },
                          { 'name': 'mirror_mode', 'val': mirror_mode } ])

        t.drop.default_entry_reset()
        t.maybe_drop_fragment.default_entry_reset()
        t.maybe_exclude_l4.default_entry_reset()
        t.maybe_drop_non_ip.default_entry_reset()

        if 'deflect-on-drop' in self.features.keys():
            t.drop.default_entry_set(
                'ig_ctl.ctl_drop_packet.send_to_port',
                [ { 'name': 'port',  'val': self.features['deflect-on-drop'] } ])

        if self.features['drop-non-initial-fragments']:
            t.maybe_drop_fragment.default_entry_set('act_mark_to_drop')

        if  self.features['exclude-ports-from-hash']:
            t.maybe_exclude_l4.default_entry_set('act_exclude_l4')

        if  self.features['drop-non-ip']:
            t.maybe_drop_non_ip.default_entry_set('act_mark_to_drop')

        prev_ports = deepcopy(prev_state.ports)
        for dev_port, pconfig in sorted(self.ports.items()):
            if dev_port in prev_ports:
                if prev_ports[dev_port] == pconfig:
                    method = None
                else:
                    method = t.port.entry_mod
                    if prev_ports[dev_port]['shutdown'] != pconfig['shutdown']:
                        logger.info("port {0} administrative status changed to {1}".
                                    format(dev_port, 'down' if pconfig['shutdown'] else 'up'))
                del prev_ports[dev_port]
            else:
                method = t.port.entry_add
            if method is not None:
                port_config = [ { 'name': '$FEC', 'str_val':  str(pconfig['fec']) },
                                { 'name': '$PORT_ENABLE', 'bool_val': not pconfig['shutdown'] },
                                { 'name': '$RX_MTU', 'val': pconfig['mtu'] },
                                { 'name': '$TX_MTU', 'val': pconfig['mtu'] } ]
                speed = str(pconfig['speed'])
                lanes_match = re.match('.*_R[1-8]$', speed)
                if lanes_match:
                    port_config.append({ 'name': '$N_LANES', 'val': lanes_match.group(1) })
                    speed = re.sub('_R[0-9]$', '', speed)
                port_config.append({ 'name': '$SPEED', 'str_val': speed }),
                method([ { 'name': '$DEV_PORT', 'value': dev_port } ], None, port_config)

            ## Use front-port names in the interface MIB. Dev ports
            ## that are not associated with such a name are not
            ## represented there. Note that the PCIe CPU port never
            ## occurs here because it is not allowed in the list of
            ## configured ports.
            if dev_port in self.dev.ports_dev2name:
                port_name = self.dev.ports_dev2name[dev_port]
                self.dev.update_mib_for_port(dev_port, port_name,
                    { 'ifDescr': port_name.encode('ascii'),
                      'ifName': port_name.encode('ascii'),
                      'ifAlias': pconfig['description'].encode('ascii'),
                      'ifMtu': pconfig['mtu'],
                      'speed': if_speed[pconfig['speed']] })

        ## The old state now only contains ports that are not present
        ## in the new config
        for dev_port in sorted(prev_ports.keys()):
            t.port.entry_del([ { 'name': '$DEV_PORT', 'value': dev_port } ])
            self.dev.delete_mib_for_port(dev_port)

    def update_stats(self):
        t = self.t
        dev = self.dev
        status = {}
        for dev_port, ifTable in dev.ifmibs.items():
            port_t = t.port.entry_get(
                [ { 'name': '$DEV_PORT', 'value': dev_port } ])
            stat_t = t.port_stat.entry_get(
                [ { 'name': '$DEV_PORT', 'value': dev_port } ])
            old_oper_status, new_oper_status = ifTable.update(port_t, stat_t)
            port_name = port_t['$PORT_NAME']
            status[dev_port] = port_t['$PORT_UP']
            if old_oper_status != new_oper_status:
                logger.info("port {0} operational status changed to {1}".
                      format(port_name, 'up' if new_oper_status == 1 else 'down'))

        for group, members in self.groups.items():
            update = False
            at_least_one_valid = False
            for port, member in members.items():
                at_least_one_valid = at_least_one_valid or status[port]
                if member['status'] != status[port]:
                   member['status'] = status[port]
                   logger.info("egress group {0} status of member port {1} changed to {2}".
                         format(group, dev.get_port_name(port), 'up' if status[port] else 'down'))
                   update = True
            if update:
                if not at_least_one_valid:
                    ## All members are now invalid. We need to remove
                    ## the reference to the group from the forwarding
                    ## table before we can set this status for the
                    ## action selector
                    logger.warning("egress group {0} all member ports are down".format(group))
                    t.forward.entry_del([ { 'name': 'egress_group', 'value': group } ])
                    self.groups_ref[group] = False

                self.set_action_selector(t.port_groups_sel.entry_mod,
                                         group, members)

                if at_least_one_valid and not self.groups_ref[group]:
                    t.forward.entry_add([ { 'name': 'egress_group', 'value': group } ],
                                             None,
                                             [ { 'name': '$SELECTOR_GROUP_ID', 'val': group } ])
                    self.groups_ref[group] = True
