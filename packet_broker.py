import os
import logging
import re
import json as JSON
import jsonschema
import ipaddress
import mib

logger = logging.getLogger(__name__)

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
    pass

def json_load(name):
    with open(name) as file:
        parsed = JSON.load(file)
    file.close()
    return parsed

class Config:
    def __init__(self):
        self.ports = {}
        self.groups = {}
        self.groups_ref = {}
        self.ingress = {}
        self.source_filter = []
        self.source_filter_d = []
        self.flow_mirror = []
        self.features = {
            'drop-non-initial-fragments': False,
            'exclude-ports-from-hash': False
        }

class PacketBroker:
    ## Pseudo class to let us refer to tables via
    ## attributes
    class t:
        pass

    def __init__(self, bfrt, config_dir, ifmibs_dir):
        self.bfrt = bfrt
        self.config_dir = config_dir
        self.ifmibs_dir = ifmibs_dir

        for name, loc in tables.items():
            setattr(self.t, name, bfrt.table(name, loc))

        ## Remove all shared memory segments to get rid of left-overs
        ## from previous runs
        for root, dirs, files in os.walk(self.ifmibs_dir):
            for file in files:
                os.unlink(self.ifmibs_dir+'/'+file)
        self.ifmibs = {}

        ## Whenever a new configuration is pushed to the device, all
        ## tables are cleared and re-programmed, except for the
        ## interfaces to avoid links going down during
        ## reconfiguration.  This is done by using the port-specific
        ## part of the current configuration in the configure() method
        ## to perform a smooth transition to the new port
        ## configuration.  When the config daemon starts, we create an
        ## initial pseudo-configuration here that only contains the
        ## state of the ports as read from the device for
        ## bootstrapping.

        ## In 9.1.1, the "internal" tables can't be traversed by using
        ## "None" as the key to entry_get(), as normal P4 tables can
        ## (at least not in a reliable manner). The following logic
        ## finds all "active" interfaces by looking up the the
        ## port-to-physical-port mapping in the "port_str_info"
        ## table. This is specific to the WEDGE100-32X (note that port
        ## 33 is used for the 10G CPU ports on this model).
        ##
        ## "active" in this context means that the port has been added
        ## to the internal table called "$PORT", either by a previous
        ## instance of this script or by issuing a "port-add" command
        ## on the ucli command line.
        config = Config()
        for conn in range(1, 34):
            for chnl in range(0,4):
                res = self.t.port_hdl_info.entry_get(
                    [ { 'name': '$CONN_ID', 'value': conn },
                      { 'name': '$CHNL_ID', 'value': chnl } ])
                if res is not None:
                    dev_port = res['$DEV_PORT']
                    ## Every entry in the table has the field
                    ## '$PORT_NAME' but only the active ports have any
                    ## other fields.  We use this to determine which
                    ## ports are active by looking for an arbitrary
                    ## field.  This will cause bf_switchd to log an
                    ## error for each non-active entry.
                    res = self.t.port.entry_get(
                        [{ 'name': '$DEV_PORT', 'value': dev_port }],
                        [ { 'name': '$PORT_NAME' }, { 'name': '$IS_VALID' } ])
                    if res is not None:
                        ## Now that we know the port is active, fetch
                        ## all fields.
                        port = self.t.port.entry_get(
                            [{ 'name': '$DEV_PORT', 'value': dev_port }])
                        name = port['$PORT_NAME']
                        config.ports[name] = {
                            'description': None,
                            'speed': port['$SPEED'],
                            'mtu': port['$RX_MTU'],
                            'fec': port['$FEC'],
                            'shutdown': not port['$PORT_ENABLE']
                        }
        self.config = config

    def _get_dev_port(self, port):
        info = self.t.port_str_info.entry_get(
            [{ 'name': '$PORT_NAME', 'value': port }])
        assert(info is not None)
        return info['$DEV_PORT']

    def _msgs_clear(self):
        self.msgs = []

    def _msg_add(self, msg, level = logging.INFO):
        self.msgs.append({
            'level': level,
            'msg': msg
        })

    def _info(self, msg):
        self._msg_add(msg)

    def _warning(self, msg):
        self._msg_add(msg, level = logging.WARNING)

    def _error(self, msg):
        self._msg_add(msg, level = logging.ERROR)

    def _dump_dynamic_source_filters(self):
        file = self.config_dir + "/source_filter_dynamic"
        try:
            f = open(file, "w")
        except Exception as e:
            raise Exception("Error opening {} for writing: {}".
                            format(file, e))
        f.write("## Automatically generated file. DO NOT EDIT.\n")
        for prefix in self.config.source_filter_d:
            f.write(prefix.compressed + "\n")
        try:
            f.close()
        except Exception as e:
            raise Exception("Error saving dynamic filters to {}: {}".
                            format(file, e))

    def _read_dynamic_source_filters(self, config):
        file = self.config_dir + "/source_filter_dynamic"
        if not os.path.exists(file):
            return
        try:
            f = open(file, "r")
        except Exception as e:
            raise Exception("Error opening {} for reading: {}".
                            format(file, e))
        for line in f:
            if re.match("^#", line):
                continue
            prefix = ipaddress.ip_network(line.rstrip().decode())
            if prefix in config.source_filter:
                ## Can only happen if the prefix has been added
                ## manually to the file
                self._warning("Igonring dynamic filter colliding with persistent " +
                              "filter: {} ".format(prefix.compressed))
            elif prefix in config.source_filter_d:
                self._warning("Igonring duplicate dynamic filter: {}".
                              format(prefix.compressed))
            else:
                config.source_filter_d.append(prefix)
        f.close()

    def _read(self):
        json_file = self.config_dir + '/config.json'
        try:
            json = json_load(json_file)
        except Exception as e:
            raise Exception("JSON parse error on {0:s}: {1:s}".
                  format(json_file, e))
        try:
            schema = json_load(self.config_dir + '/schema.json')
        except Exception as e:
            raise Exception("BUG: JSON parse error on schema: {}".format(e))
        try:
            jsonschema.validate(json, schema)
        except Exception as e:
            raise Exception("JSON validation error: {}".format(e))
        return json

    def _parse(self, json):
        config = Config()

        def add_port(port, port_config):
            if port in config.ports.keys():
                raise semantic_error("port {0:s} already defined".format(port))
            full_config = {
                'description': None,
                'fec': 'BF_FEC_TYP_NONE',
                'shutdown': False
            }
            full_config.update(port_config)
            config.ports[port] = full_config

        for group in json['ports']['egress']:
            id = group['group-id']
            if id in config.groups.keys():
                raise semantic_error("group id {0:d} already defined".format(id))
            
            config.groups[id] = {}
            for port, dict in sorted(group['members'].items()):
                add_port(port, dict['config'])
                config.groups[id][port] = {}

        for port, dict in sorted(json['ports']['ingress'].items()):
            add_port(port, dict['config'])
            egress_group = dict['egress-group']
            config.ingress[port] = {
                'vlans' : dict['vlans'],
                'egress_group' : egress_group
            }
            if not egress_group in config.groups.keys():
                raise semantic_error("Undefined egress group {0:d}".format(egress_group))
        
        for port, dict in sorted(json['ports']['other'].items()):
            add_port(port, dict['config'])

        if 'source-filter' in json.keys():
            for str in json['source-filter']:
                prefix = ipaddress.ip_network(str)
                if prefix in config.source_filter:
                    self._warning("Ignoring duplicate source filter: {0:s}"
                                  .format(prefix))
                else:
                    config.source_filter.append(prefix)

        try:
            self._read_dynamic_source_filters(config)
        except Exception as e:
            self._warning("Ignoring dynamic source filters: {}".format(e))
            config.source_filter_d = []
            
        if 'flow-mirror' in json.keys():
            def add_flow(flow_in):
                flow = flow_in.copy()
                flow.pop('bidir', None)
                flow.pop('enable', None)
                flow['src'] = ipaddress.ip_network(flow['src'])
                flow['dst'] = ipaddress.ip_network(flow['dst'])

                if flow['src'].version != flow['dst'].version:
                    raise semantic_error("Address family mismatch " +
                                         "in flow mirror rule: {}".
                                         format(JSON.dumps(flow_in)))

                if flow in config.flow_mirror:
                    self._warning("Ignoring duplicate flow mirror rule: {}".
                                  format(JSON.dumps(flow_in)))
                else:
                    config.flow_mirror.append(flow)

            for flow in json['flow-mirror']:
                if not flow.get('enable', True):
                    continue
                add_flow(flow)
                if flow.get('bidir', False):
                    add_flow({ 'src': flow['dst'],
                               'dst': flow['src'],
                               'src_port': flow['dst_port'],
                               'dst_port': flow['src_port'] })

        features = json.get('features', {})
        for feature, value in features.items():
            if feature == 'deflect-on-drop':
                if not re.match("^[0-9]+$", value):
                    value = self._get_dev_port(value)
                config.features['deflect-on-drop'] = int(value)

            if feature == 'flow-mirror':
                cfg = value

                port = cfg['port']
                if not re.match("^[0-9]+$", port):
                    port = self._get_dev_port(port)

                if 'max-packet-length' in cfg.keys():
                    max_pkt_len = cfg['max-packet-length']
                else:
                    max_pkt_len = 16384
                config.features['flow-mirror'] = {
                    'port': int(port),
                    'max_pkt_len': max_pkt_len
                }

            if feature == 'drop-non-initial-fragments' and value:
                config.features['drop-non-initial-fragments'] = True

            if feature == 'exclude-ports-from-hash' and value:
                config.features['exclude-ports-from-hash'] = True

        if len(config.flow_mirror) > 0 and 'flow-mirror' not in features.keys():
            raise semantic_error("Flow mirror feature configuration required " +
                                 "if enabled flow mirror rules are present")

        return config

    def _set_action_selector(self, method, group, members):
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

    def _push(self, config):
        get_dev_port = self._get_dev_port
        
        ### Action profile and selector
        ## Order matters here
        self.t.forward.clear()
        self.t.port_groups_sel.clear()
        self.t.port_groups.clear()
        
        member_id = 1
        for group, members in config.groups.items():
            ## Group is not referenced from
            ## the forwarding table
            config.groups_ref[group] = False
            for port, member in members.items():
                dev_port = get_dev_port(port)
                member['id'] = member_id
                member['status'] = False
                self.t.port_groups.entry_add(
                    [ { 'name': '$ACTION_MEMBER_ID', 'value': member_id } ],
                    'act_send',
                    [ { 'name': 'egress_port', 'val': dev_port } ])
                member_id += 1
            self._set_action_selector(self.t.port_groups_sel.entry_add, group, members)

        self.t.select_output.clear()
        self.t.ingress_untagged.clear()
        self.t.ingress_tagged.clear()
        for port, dict in sorted(config.ingress.items()):
            dev_port = get_dev_port(port)
            vlans = dict['vlans']
            egress_group = dict['egress_group']
            self.t.select_output.entry_add(
                [ { 'name': 'ingress_port', 'value': dev_port } ],
                'act_output_group',
                [ { 'name': 'group', 'val': egress_group } ])

            if 'push' in vlans:
                self.t.ingress_untagged.entry_add(
                    [ { 'name': 'ingress_port', 'value': dev_port } ],
                    'act_push_vlan',
                    [ { 'name': 'vid', 'val': vlans['push'] } ])

            if 'rewrite' in vlans:
                for rule in vlans['rewrite']:
                    self.t.ingress_tagged.entry_add(
                        [ { 'name': 'ingress_port', 'value': dev_port },
                          { 'name': 'ingress_vid', 'value': rule['in'] } ],
                        'act_rewrite_vlan',
                        [ { 'name': 'vid', 'val': rule['out'] } ])

        self.t.filter_ipv4.clear()
        self.t.filter_ipv6.clear()
        for prefix in (config.source_filter + config.source_filter_d):
            if prefix.version == 4:
                tbl = self.t.filter_ipv4
                ## Makes entry_add() accept "src_addr" as a string rather than
                ## a byte array
                tbl.table.info.key_field_annotation_add("src_addr", "ipv4")
            else:
                tbl = self.t.filter_ipv6
            tbl.table.info.key_field_annotation_add("src_addr", "ipv6")
            tbl.entry_add(
                [ { 'name': 'src_addr', 'value': prefix.network_address.exploded,
                    'prefix_len': prefix.prefixlen } ],
                'act_drop', [])

        self.t.mirror_ipv4.clear()
        self.t.mirror_ipv6.clear()
        if 'flow-mirror' in config.features.keys():
            for flow in config.flow_mirror:
                if flow['src'].version == 4:
                    tbl = self.t.mirror_ipv4
                    tbl.table.info.key_field_annotation_add("src_addr", "ipv4")
                    tbl.table.info.key_field_annotation_add("dst_addr", "ipv4")
                else:
                    tbl = self.t.mirror_ipv6
                    tbl.table.info.key_field_annotation_add("src_addr", "ipv6")
                    tbl.table.info.key_field_annotation_add("dst_addr", "ipv6")
                tbl.entry_add(
                    [ { 'name': 'src_addr',
                        'value': flow['src'].network_address.exploded,
                        'mask': int(flow['src'].netmask) },
                      { 'name': 'dst_addr',
                        'value': flow['dst'].network_address.exploded,
                        'mask': int(flow['dst'].netmask) },
                      { 'name': 'src_port',
                        'value': flow['src_port']['port'],
                        'mask': flow['src_port']['mask'] },
                      { 'name': 'dst_port',
                        'value': flow['dst_port']['port'],
                        'mask': flow['dst_port']['mask'] } ],
                    'act_mirror',
                    [ { 'name': 'mirror_session', 'val': MIRROR_SESSION_ID } ])
            
            flow_mirror = config.features['flow-mirror']
            self.t.mirror_cfg.entry_add(
                [ { 'name': '$sid', 'value': MIRROR_SESSION_ID } ],
                '$normal',
                [ { 'name': '$session_enable', 'bool_val': True },
                  { 'name': '$direction', 'str_val': 'INGRESS' },
                  { 'name': '$ucast_egress_port', 'val': flow_mirror['port'] },
                  { 'name': '$ucast_egress_port_valid', 'bool_val': True },
                  { 'name': '$max_pkt_len', 'val': flow_mirror['max_pkt_len'] } ])
            
        self.t.drop.default_entry_reset()
        self.t.maybe_drop_fragment.default_entry_reset()
        self.t.maybe_exclude_l4.default_entry_reset()

        if 'deflect-on-drop' in config.features.keys():
            self.t.drop.default_entry_set(
                'ig_ctl.ctl_drop_packet.send_to_port',
                [ { 'name': 'port',  'val': config.features['deflect-on-drop'] } ])

        if config.features['drop-non-initial-fragments']:
            self.t.maybe_drop_fragment.default_entry_set('act_mark_to_drop')

        if  config.features['exclude-ports-from-hash']:
            self.t.maybe_exclude_l4.default_entry_set('act_exclude_l4')

        for port, pconfig in sorted(config.ports.items()):
            dev_port = get_dev_port(port)

            if port in self.config.ports.keys():
                if self.config.ports[port] == pconfig:
                    method = None
                else:
                    method = self.t.port.entry_mod
                    if self.config.ports[port]['shutdown'] != pconfig['shutdown']:
                        self._info("port {0} administrative status changed to {1}".
                                   format(port, 'down' if pconfig['shutdown'] else 'up'))
                del self.config.ports[port]
            else:
                method = self.t.port.entry_add
            if method is not None:
                method([ { 'name': '$DEV_PORT', 'value': dev_port } ],
                       None,
                       [ { 'name': '$SPEED', 'str_val': pconfig['speed'].encode('ascii') },
                         { 'name': '$FEC', 'str_val':  pconfig['fec'].encode('ascii') },
                         { 'name': '$PORT_ENABLE', 'bool_val': not pconfig['shutdown'] },
                         { 'name': '$RX_MTU', 'val': pconfig['mtu'] },
                         { 'name': '$TX_MTU', 'val': pconfig['mtu'] } ])

                if dev_port not in self.ifmibs.keys():
                    self.ifmibs[dev_port] = mib.ifmib(self.ifmibs_dir+'/'+re.sub('/', '_', port))
                self.ifmibs[dev_port].set_properties(
                    { 'ifDescr': port,
                      'ifName': port.encode('ascii'),
                      'ifAlias': pconfig['description'].encode('ascii'),
                      'ifMtu': pconfig['mtu'],
                      'speed': if_speed[pconfig['speed']] }
                )

        for port in sorted(self.config.ports.keys()):
            dev_port = get_dev_port(port)
            self.t.port.entry_del([ { 'name': '$DEV_PORT', 'value': dev_port } ])
            self.ifmibs[dev_port].delete()
            self.ifmibs.pop(dev_port, None)
        self.config = config

    def update_stats(self):
        status = {}
        for dev_port, ifTable in self.ifmibs.items():
            port_t = self.t.port.entry_get(
                [ { 'name': '$DEV_PORT', 'value': dev_port } ])
            stat_t = self.t.port_stat.entry_get(
                [ { 'name': '$DEV_PORT', 'value': dev_port } ])
            old_oper_status, new_oper_status = ifTable.update(port_t, stat_t)
            port = port_t['$PORT_NAME']
            status[port] = port_t['$PORT_UP']
            if old_oper_status != new_oper_status:
                logger.info("port {0} operational status changed to {1}".
                      format(port, 'up' if new_oper_status == 1 else 'down'))

        for group, members in self.config.groups.items():
            update = False
            at_least_one_valid = False
            for port, member in members.items():
                at_least_one_valid = at_least_one_valid or status[port]
                if member['status'] != status[port]:
                   member['status'] = status[port]
                   logger.info("egress group {0} status of member port {1} changed to {2}".
                         format(group, port, 'up' if status[port] else 'down'))
                   update = True
            if update:
                if not at_least_one_valid:
                    ## All members are now invalid. We need to remove
                    ## the reference to the group from the forwarding
                    ## table before we can set this status for the
                    ## action selector
                    logger.warning("egress group {0} all member ports are down".format(group))
                    self.t.forward.entry_del([ { 'name': 'egress_group', 'value': group } ])
                    self.config.groups_ref[group] = False
                elif not self.config.groups_ref[group]:
                    self.t.forward.entry_add([ { 'name': 'egress_group', 'value': group } ],
                                        None,
                                        [ { 'name': '$SELECTOR_GROUP_ID', 'val': group } ])
                    self.config.groups_ref[group] = True

                self._set_action_selector(self.t.port_groups_sel.entry_mod,
                                          group, members)

    def handle_request(self, peer, req):
        self._msgs_clear()
        result = None

        command = req['command']
        handler = getattr(self, '_cmd_' + command, None)
        if handler is None:
            self._error("Invalid command '{}' from {}".format(command, peer[0]))
            success = False
        else:
            try:
                result = handler(req, peer[0])
                success = True
            except Exception as e:
                self._error("Command '{}' failed: {}".format(command, e))
                success = False

        for msg in self.msgs:
            logger.log(msg['level'], msg['msg'])

        return {
            'success': success,
            'msgs': self.msgs,
            'result': result
        }

    def _cmd_reload(self, req, peer):

        logger.info("Reload requested by {}".format(peer))
        try:
            json = self._read()
        except Exception as e:
            raise Exception("Error reading configuration: {}".format(e))

        if json is not None:
            try:
                config = self._parse(json)
            except Exception as e:
                raise Exception("Error parsing configuration: {}".format(e))

            try:
                self._push(config)
            except Exception as e:
                self._error("This is unexpected and may leave the hardware "
                            + "in an undefined state")
                raise Exception("Error pushing configuration: {}".format(e))
        return None

    def _cmd_show(self, req, peer):
        c = self.config
        items = {
            'ports': 'ports',
            'groups': 'groups',
            'ingress': 'ingress',
            'source-filter': 'source_filter',
            'source-filter-dynamic': 'source_filter_d',
            'flow-mirror': 'flow_mirror',
            'features': 'features'
        }
        result = {}

        for item in req['args']:
            result[item] = getattr(c, items[item])
        return result

    def _cmd_dump(self, req, peer):

        def filter(key, data, result):
            addr = key['src_addr']
            result.append({
                'prefix': addr['value']+'/'+str(addr['prefix_len']),
                'counters': {
                    'packets': data[u'$COUNTER_SPEC_PKTS'],
                    'bytes': data[u'$COUNTER_SPEC_BYTES']
                }
            })

        def mirror(key, data, result):
            result.append(key)

        def default(key, data, result):
            result.append({'key': key, 'data': data})

        funcs = {
            'filter_ipv4': filter,
            'filter_ipv6': filter,
            'mirror_ipv4': mirror,
            'mirror_ipv6': mirror
        }

        result = []
        for name in req['args']:
            for data, key in (getattr(self.t, name).
                              entry_get_iterator([], from_hw = True)):
                func = funcs.get(name, default)
                func(key.to_dict(), data.to_dict(), result)
        return result

    def _add_remove(self, mode, req, peer):
        config = self.config

        def source_filter(prefixes):
            tables = {
                4: self.t.filter_ipv4,
                6: self.t.filter_ipv6
            }
            for str in prefixes:
                prefix = ipaddress.ip_network(str)
                if mode == 'add':
                    if prefix in config.source_filter + config.source_filter_d:
                        raise Exception("Duplicate source filter: {}".
                                        format(prefix))
                    ## Makes entry_add() accept "src_addr" as a string rather than
                    ## a byte array
                    tables[prefix.version].table.info.key_field_annotation_add("src_addr", "ipv4")
                    tables[prefix.version].entry_add(
                        [ { 'name': 'src_addr',
                            'value': prefix.network_address.exploded,
                            'prefix_len': prefix.prefixlen } ],
                        'act_drop', [])
                    self._info("Added source filter {}".format(prefix))
                    config.source_filter_d.append(prefix)
                else:
                    if  prefix in config.source_filter:
                        raise Exception("Cannot remove persistent source " +
                                        "filter: {}".format(prefix))
                    if not prefix in config.source_filter_d:
                        raise Exception("Source filter does not exist: {}".
                                        format(prefix))
                    tables[prefix.version].entry_del(
                        [ { 'name': 'src_addr',
                            'value': prefix.network_address.exploded,
                            'prefix_len': prefix.prefixlen } ])
                    self._info("Removed source filter {}".format(prefix))
                    config.source_filter_d.remove(prefix)
                self._dump_dynamic_source_filters()

        items = {
            'source-filter': {
                'func': source_filter
            }
        }

        for item, data in req['args'].items():
            logger.info("{} {} requested by {}".format(mode, item, peer))
            items[item]['func'](data)
        return None

    def _cmd_add(self, req, peer):
        return self._add_remove('add', req, peer)

    def _cmd_remove(self, req, peer):
        return self._add_remove('remove', req, peer)
