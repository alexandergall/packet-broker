import os
import re
import json
import jsonschema
import ipaddress
import mib

MIRROR_SESSION_ID = 1

ctls = {
    'vlan' : 'pipe.ig_ctl.ctl_push_or_rewrite_vlan',
    'forward' : 'pipe.ig_ctl.ctl_forward_packet',
    'filter_ipv4' : 'pipe.ig_ctl.ctl_filter_source_ipv4',
    'filter_ipv6' : 'pipe.ig_ctl.ctl_filter_source_ipv6',
    'mirror_ipv4' : 'pipe.ig_ctl.ctl_mirror_flows_ipv4',
    'mirror_ipv6' : 'pipe.ig_ctl.ctl_mirror_flows_ipv6',
    'maybe_exclude_l4_from_hash' : 'pipe.ig_ctl.ctl_maybe_exclude_l4_from_hash',
    'maybe_drop_fragment' : 'pipe.ig_ctl.ctl_maybe_drop_fragment',
    'drop' : 'pipe.ig_ctl.ctl_drop_packet'
}
tables = {
    ### Internal tables
    ## Keys: $DEV_PORT'
    'port': '$PORT', 
    ## Keys: $DEV_PORT'
    'port_stat': '$PORT_STAT',
    ## Keys: $PORT_NAME
    'port_str_info': '$PORT_STR_INFO', 
    ## Keys: $CONN_ID, $CHNL_ID
    'port_hdl_info': '$PORT_HDL_INFO',
    ## Keys: $sid
    'mirror_cfg': '$mirror.cfg',
    
    ### Program tables
    ## Keys: ingress_port
    'ingress_untagged': ctls['vlan'] + '.tbl_ingress_untagged',
    ## Keys: ingress_port, ingress_vid
    'ingress_tagged': ctls['vlan'] + '.tbl_ingress_tagged',
    ## Keys: src_addr
    'filter_ipv4': ctls['filter_ipv4'] + '.tbl_filter_source_ipv4',
    ## Keys: src_addr
    'filter_ipv6': ctls['filter_ipv6'] + '.tbl_filter_source_ipv6',
    ## Keys: src_addr, dst_addr, src_port, dst_port
    'mirror_ipv4': ctls['mirror_ipv4'] + '.tbl_mirror_flows_ipv4',
    ## Keys: src_addr, dst_addr, src_port, dst_port
    'mirror_ipv6': ctls['mirror_ipv6'] + '.tbl_mirror_flows_ipv6',
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
    'maybe_drop_fragment': ctls['maybe_drop_fragment'] + '.tbl_maybe_drop_fragment'
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
    'BF_SPEED_400G':              400000000000
}

class semantic_error(Exception):
    def __init(self, expresssion, message):
        self.expression = expresssion
        self.message = message

def json_load(name):
    with open(name) as file:
        parsed = json.load(file)
    file.close()
    return parsed

class Config:
    def __init__(self, bfrt, config_dir, ifmibs_dir):
        self.bfrt = bfrt
        self.config_dir = config_dir
        self.ifmibs_dir = ifmibs_dir
        self.json_mtime = 0

        for name, loc in tables.items():
            bfrt.register_table(name, loc)

        self.old_ports = {}

        ## In 9.1.0, the "internal" tables can't be traversed by using
        ## "None" as the key to entry_get(), as normal P4 tables can
        ## (at least not in a reliable manner). The following logic
        ## finds all "active" interfaces by looking up the the
        ## port-to-physical-port mapping in the "port_str_info"
        ## table. This is specific to the WEDGE100-32X (note that port
        ## 33 is used for the 10G CPU ports on this model).
        ##
        ## "active" in this context means that the port has been added
        ## to the internal table called "port", either by a previous
        ## instance of this script or by issuing a "port-add" command
        ## on the ucli command line.
        for conn in range(1, 34):
            for chnl in range(0,4):
                res = bfrt.Tables.port_hdl_info.entry_get(
                    [ { 'name': '$CONN_ID', 'value': conn },
                      { 'name': '$CHNL_ID', 'value': chnl } ])
                if res is not None:
                    dev_port = res['$DEV_PORT']
                    res = bfrt.Tables.port.entry_get(
                        [{ 'name': '$DEV_PORT', 'value': dev_port }],
                        [ { 'name': '$PORT_NAME' }, { 'name': '$IS_VALID' } ])
                    if res is not None:
                        self.old_ports[res['$PORT_NAME']] = True

    def _indent(self, msg):
        print(' ' * self.indent_level * 4 + msg)
        
    def _indent_up(self):
        self.indent_level += 1
        
    def _indent_down(self):
        self.indent_level -= 1

    def _get_dev_port(self, port):
        info = self.bfrt.Tables.port_str_info.entry_get(
            [{ 'name': '$PORT_NAME', 'value': port }])
        assert(info is not None)
        return info['$DEV_PORT']

    def _format_port(self, port):
        if re.match("^[0-9]+$", port):
            return "physical port {0:d}".format(int(port))
        return "{0:s} (physical port {1:d})". format(port, self._get_dev_port(port))
    def configure(self):
            if self.read():
                try:
                    self.parse()
                except Exception as e:
                    print("Error parsing configuration: {}".format(e))
                else:
                    self.push()

    def read(self):
        json_file = self.config_dir + '/config.json'
        mtime = os.path.getmtime(json_file)
        if mtime > self.json_mtime:
            print("Configuration file change detected, rereading")
            try:
                self.json = json_load(json_file)
            except Exception as e:
                print("JSON parse error on {0:s}: {1:s}".
                      format(json_file, e))
                return False
            try:
                schema = json_load(self.config_dir + '/schema.json')
            except Exception as e:
                print("BUG: JSON parse error on schema: {}".format(e))
                return False
            try:
                jsonschema.validate(self.json, schema)
            except Exception as e:
                print("JSON validation error: {}".format(e))
                return False
            self.json_mtime = mtime
            return True
        else:
            print("Configuration unchanged, doing nothing")
            return False
        
    def parse(self):
        self.ports = {}
        self.groups = {}
        self.ingress = {}
        self.source_filter = []
        self.flow_mirror = []
        self.features = {
            'drop-non-initial-fragments': False,
            'exclude-ports-from-hash': False
        }
        self.indent_level = 0
        
        def add_port(port, config):
            if port in self.ports.keys():
                raise semantic_error("port {0:s} already defined".format(port))
            self.ports[port] = config

        self._indent("Setting up egress port groups")
        self._indent_up()
        for group in self.json['ports']['egress']:
            id = group['group-id']
            if id in self.groups.keys():
                raise semantic_error("group id {0:d} already defined".format(id))
            
            self._indent("Group {0:d}".format(id))
            self._indent_up()
            self.groups[id] = []
            for port, dict in sorted(group['members'].items()):
                self._indent("Port " + self._format_port(port))
                add_port(port, dict['config'])
                self.groups[id].append(port)
            self._indent_down()
        self._indent_down()

        self._indent("Setting up ingress ports")
        self._indent_up()
        for port, dict in sorted(self.json['ports']['ingress'].items()):
            self._indent("Port " + self._format_port(port))
            add_port(port, dict['config'])
            egress_group = dict['egress-group']
            self.ingress[port] = {
                'vlans' : dict['vlans'],
                'egress_group' : egress_group
            }
            if not egress_group in self.groups.keys():
                semantic_error("Undefined egress group {0:d}".format(egress_group))
        self._indent_down()
        
        self._indent("Setting up other ports")
        self._indent_up()
        for port, dict in sorted(self.json['ports']['other'].items()):
            self._indent("Port " + self._format_port(port))
            add_port(port, dict['config'])
        self._indent_down()

        if 'source-filter' in self.json.keys():
            self._indent("Setting source filters")
            self._indent_up()
            for str in self.json['source-filter']:
                prefix = ipaddress.ip_network(str)
                self._indent(prefix.with_prefixlen)
                self.source_filter.append(prefix)
            self._indent_down()

        if 'flow-mirror' in self.json.keys():
            self._indent("Setting flow mirrors")
            self._indent_up()
            
            def format_l4_port(spec):
                return("port 0x{0:04X}({0:d}) mask 0x{1:04X}".format(
                    spec['port'], spec['mask']))

            def add_flow(flow_id, flow):
                src = ipaddress.ip_network(flow['src'])
                dst = ipaddress.ip_network(flow['dst'])
                src_port = flow['src_port']
                dst_port = flow['dst_port']

                self._indent("[{0:d}] {1:s} {2:s} -> {3:s} {4:s}".format(
                    flow_id,
                    src.with_prefixlen, format_l4_port(src_port),
                    dst.with_prefixlen, format_l4_port(dst_port)))
                if src.version != dst.version:
                    raise semantic_error("address family mismatch")
                self.flow_mirror.append([ src, dst, src_port, dst_port, flow_id ])

            flow_id = 1
            for flow in self.json['flow-mirror']:
                if 'enable' in flow.keys() and not flow['enable']:
                    continue
                if (not 'features' in self.json.keys() or
                    not 'flow-mirror' in self.json['features'].keys()):
                    raise semantic_error("mirror destination missing")

                add_flow(flow_id, flow)
                flow_id += 1
                if not 'bidir' in flow.keys() or flow['bidir']:
                    add_flow(flow_id, { 'src': flow['dst'],
                                        'dst': flow['src'],
                                        'src_port': flow['dst_port'],
                                        'dst_port': flow['src_port'] })
                    flow_id += 1
            self._indent_down()

        if 'features' in self.json.keys():
            self._indent("Setting features")
            self._indent_up()
    
            for feature, value in self.json['features'].items():
                if feature == 'deflect-on-drop':
                    self._indent("Deflect-on-drop to port " +
                                 self._format_port(value))
                    if not re.match("^[0-9]+$", value):
                        value = self._get_dev_port(value)
                    self.features['deflect-on-drop'] = value

                if feature == 'flow-mirror':
                    self._indent("Flow mirror")
                    self._indent_up()
                    cfg = value

                    port = cfg['port']
                    self._indent("Destination port " +
                                 self._format_port(port))
                    if not re.match("^[0-9]+$", port):
                        port = self._get_dev_port(port)

                    if 'max-packet-length' in cfg.keys():
                        max_pkt_len = cfg['max-packet-length']
                    else:
                        max_pkt_len = 16384
                    self._indent("Maximum packet length {0:d}".format(max_pkt_len))
                    self.features['flow-mirror'] = {
                        'port': port,
                        'max_pkt_len': max_pkt_len
                    }
                    self._indent_down()

                if feature == 'drop-non-initial-fragments' and value:
                    self._indent("Drop non-initial fragemnts")
                    self.features['drop-non-initial-fragments'] = True

                if feature == 'exclude-ports-from-hash' and value:
                    self._indent("Exclude L4 ports from hash")
                    self.features['exclude-ports-from-hash'] = True

            self._indent_down()

    def push(self):
        get_dev_port = self._get_dev_port
        format_port = self._format_port
        t = self.bfrt.Tables
        
        self._indent("Programming tables")
        self._indent_up()

        ### Action profile and selector
        ## Order matters here
        t.forward.clear()
        t.port_groups_sel.clear()
        t.port_groups.clear()
        
        member_id = 1
        for group, ports in self.groups.items():
            member_list = []
            for port in ports:
                dev_port = get_dev_port(port)
                self._indent("Adding action profile member {0:d} port {1:s}".
                       format(member_id, format_port(port)))
                member_list.append(member_id)
                t.port_groups.entry_add(
                    [ { 'name': '$ACTION_MEMBER_ID', 'value': member_id } ],
                    'act_send',
                    [ { 'name': 'egress_port', 'val': dev_port } ])
                member_id += 1

        self._indent("Adding action selector group #{0:d}".format(group))
        t.port_groups_sel.entry_add(
            [ { 'name': '$SELECTOR_GROUP_ID', 'value': group } ],
            None,
            [ { 'name': '$MAX_GROUP_SIZE', 'val': 8 },
              ## References action_member_ids from profile
              { 'name': '$ACTION_MEMBER_ID', 'int_arr_val': member_list },
              { 'name': '$ACTION_MEMBER_STATUS',
                'bool_arr_val': [ True ] * len(member_list) } ])
        t.forward.entry_add([ { 'name': 'egress_group', 'value': group } ],
                            None,
                            [ { 'name': '$SELECTOR_GROUP_ID', 'val': group } ])
        
        t.select_output.clear()
        t.ingress_untagged.clear()
        t.ingress_tagged.clear()
        for port, dict in sorted(self.ingress.items()):
            dev_port = get_dev_port(port)
            vlans = dict['vlans']
            egress_group = dict['egress_group']
            self._indent("Output group for port {0:s} is {1:d}".
                         format(port, egress_group))
            t.select_output.entry_add(
                [ { 'name': 'ingress_port', 'value': dev_port } ],
                'act_output_group',
                [ { 'name': 'group', 'val': egress_group } ])

            if 'push' in vlans:
                t.ingress_untagged.entry_add(
                    [ { 'name': 'ingress_port', 'value': dev_port } ],
                    'act_push_vlan',
                    [ { 'name': 'vid', 'val': vlans['push'] } ])

            if 'rewrite' in vlans:
                for rule in vlans['rewrite']:
                    t.ingress_tagged.entry_add(
                        [ { 'name': 'ingress_port', 'value': dev_port },
                          { 'name': 'ingress_vid', 'value': rule['in'] } ],
                        'act_rewrite_vlan',
                        [ { 'name': 'vid', 'val': rule['out'] } ])

        t.filter_ipv4.clear()
        t.filter_ipv6.clear()
        for prefix in self.source_filter:
            if prefix.version == 4:
                tbl = t.filter_ipv4
                ## Makes entry_add() accept "src_addr" as a string rather than
                ## a byte array
                tbl.table.info.key_field_annotation_add("src_addr", "ipv4")
            else:
                tbl = t.filter_ipv6
            tbl.table.info.key_field_annotation_add("src_addr", "ipv6")
            tbl.entry_add(
                [ { 'name': 'src_addr', 'value': prefix.network_address.exploded,
                    'prefix_len': prefix.prefixlen } ],
                'act_drop', [])

        t.mirror_ipv4.clear()
        t.mirror_ipv6.clear()
        if 'flow-mirror' in self.features.keys():
            for flow in self.flow_mirror:
                src = flow[0]
                dst = flow[1]
                src_port = flow[2]
                dst_port = flow[3]
                id = flow[4]
                if src.version == 4:
                    tbl = t.mirror_ipv4
                    tbl.table.info.key_field_annotation_add("src_addr", "ipv4")
                    tbl.table.info.key_field_annotation_add("dst_addr", "ipv4")
                else:
                    tbl = t.mirror_ipv6
                    tbl.table.info.key_field_annotation_add("src_addr", "ipv6")
                    tbl.table.info.key_field_annotation_add("dst_addr", "ipv6")
                try:
                    tbl.entry_add(
                        [ { 'name': 'src_addr', 'value': src.network_address.exploded,
                            'mask': int(src.netmask) },
                          { 'name': 'dst_addr', 'value': dst.network_address.exploded,
                            'mask': int(dst.netmask) },
                          { 'name': 'src_port', 'value': src_port['port'],
                            'mask': src_port['mask'] },
                          { 'name': 'dst_port', 'value': dst_port['port'],
                            'mask': dst_port['mask'] } ],
                        'act_mirror',
                        [ { 'name': 'mirror_session', 'val': MIRROR_SESSION_ID } ])
                except Exception as e:
                    print("error while programming flow mirror rule #{0:d}: {1}".format(id, e))
            
            flow_mirror = self.features['flow-mirror']
            t.mirror_cfg.entry_add(
                [ { 'name': '$sid', 'value': MIRROR_SESSION_ID } ],
                '$normal',
                [ { 'name': '$session_enable', 'bool_val': True },
                  { 'name': '$direction', 'str_val': 'INGRESS' },
                  { 'name': '$ucast_egress_port', 'val': flow_mirror['port'] },
                  { 'name': '$ucast_egress_port_valid', 'bool_val': True },
                  { 'name': '$max_pkt_len', 'val': flow_mirror['max_pkt_len'] } ])
            
        self._indent_down()

        self._indent("Programming features")
        self._indent_up()

        t.drop.default_entry_reset()
        t.maybe_drop_fragment.default_entry_reset()
        t.maybe_exclude_l4.default_entry_reset()

        if 'deflect-on-drop' in self.features.keys():
            self._indent("deflect-on-drop to physical port {0:d}".
                         format(self.features['deflect-on-drop']))
            t.drop.default_entry_set(
                'ig_ctl.ctl_drop_packet.send_to_port',
                [ { 'name': 'port',  'val': self.features['deflect-on-drop'] } ])

        if self.features['drop-non-initial-fragments']:
            self._indent("drop-non-initial-fragments")
            t.maybe_drop_fragment.default_entry_set('act_mark_to_drop')

        if  self.features['exclude-ports-from-hash']:
            self._indent("exclude-ports-from-hash")
            t.maybe_exclude_l4.default_entry_set('act_exclude_l4')

        self._indent_down()
            
        self._indent("Programming ports")
        self._indent_up()

        self.ifmibs = {}
        ## Remove all shared memory segments to get rid of left-overs
        ## from previous runs
        for root, dirs, files in os.walk(self.ifmibs_dir):
            for file in files:
                os.unlink(self.ifmibs_dir+'/'+file)

        for port, config in sorted(self.ports.items()):
            dev_port = get_dev_port(port)
            speed = config['speed']
            mtu = config['mtu']
            fec = config.get('fec', "BF_FEC_TYP_NONE")

            self._indent("Port " + format_port(port))
            self._indent_up()
            if 'description' in config.keys():
                self._indent("Description: {0}".format(config['description']))
            else:
                config['description'] = ''
            self._indent("Speed: {0}".format(speed))
            self._indent("MTU  : {0}".format(mtu))
            self._indent("FEC  : {0}".format(fec))
            self._indent_down()
    
            if port in self.old_ports.keys():
                method = t.port.entry_mod
                del self.old_ports[port]
            else:
                method = t.port.entry_add
            method([ { 'name': '$DEV_PORT', 'value': dev_port } ],
                   None,
                   [ { 'name': '$SPEED', 'str_val': speed.encode('ascii') },
                     { 'name': '$FEC', 'str_val':  fec.encode('ascii') } ])
            t.port.entry_mod([ { 'name': '$DEV_PORT', 'value': dev_port } ],
                             None,
                             [ { 'name': '$PORT_ENABLE', 'bool_val': True },
                               { 'name': '$RX_MTU', 'val': mtu },
                               { 'name': '$TX_MTU', 'val': mtu } ])

            port_massaged = re.sub('/', '_', port)
            self.ifmibs[dev_port] = mib.ifmib(self.ifmibs_dir+'/'+port_massaged,
                                              { 'ifDescr': port,
                                                'ifName': port.encode('ascii'),
                                                'ifAlias': config['description'].encode('ascii'),
                                                'ifMtu': mtu,
                                                'speed': if_speed[speed] })

        for port in sorted(self.old_ports.keys()):
            dev_port = get_dev_port(port)
            self._indent("Removing unsued port {0} (phys port {1})".
                         format(port, dev_port))
            t.port.entry_del([ { 'name': '$DEV_PORT', 'value': dev_port } ])
        self.old_ports = { port: True for port in self.ports.keys() }

        self._indent_down()

    def update_stats(self):
        for dev_port, ifTable in self.ifmibs.items():
            port = self.bfrt.Tables.port.entry_get(
                [ { 'name': '$DEV_PORT', 'value': dev_port } ])
            stat = self.bfrt.Tables.port_stat.entry_get(
                [ { 'name': '$DEV_PORT', 'value': dev_port } ])
            ifTable.update(port, stat)
