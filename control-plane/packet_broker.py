import os
import logging
import re
import json as JSON
import jsonschema
import ipaddress
import mib

logger = logging.getLogger(__name__)

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
    ## Keys: none (only the default entry exists)
    ## The fully qualified name of this table depends on the Tofino
    ## version: "tf{1,2}.dev.device_configuration"
    ## The non-qualified name conveniently gives us the configuration
    ## without having to check what we're running on first.
    'dev_cfg': 'device_configuration',

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
    ## Keys: ingress_port
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

## Action data for the mirror_* tables to specify wheter packets
## should be mirrored on ingress or egress.
mirror_modes = {
    "ingress": 1,
    "egress":  2
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
        self.system = {}
        self.ports = {}
        self.groups = {}
        self.groups_ref = {}
        self.ingress = {}
        self.source_filter = []
        self.source_filter_d = []
        self.monitor_sessions = {}
        self.flow_mirror = []
        self.features = {
            'drop-non-initial-fragments': False,
            'exclude-ports-from-hash': False,
            'drop-non-ip': False
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
            annotations = field_annotations.get(name, None)
            if annotations is not None:
                for elts in annotations.get('key', []):
                    getattr(self.t, name).table.info.key_field_annotation_add(*elts)
                for elts in annotations.get('data', []):
                    getattr(self.t, name).table.info.data_field_annotation_add(*elts)

        ## Remove all shared memory segments to get rid of left-overs
        ## from previous runs
        for root, dirs, files in os.walk(self.ifmibs_dir):
            for file in files:
                os.unlink(self.ifmibs_dir+'/'+file)
        self.ifmibs = {}

        ## Build the mapping of front-panel port names to device port
        ## numbers and vice versa.

        ## NOTE: the port_str_info table also contains the Eth CPU
        ## ports. However, they might not show up when iterating over
        ## the full table at least for devices with the maximum number
        ## of serdes lanes, which is 260, including the quad for the
        ## Eth CPU ports. The sizes of the port tables are fixed at
        ## 256 entries in the SDE, which might be a bug: the iteration
        ## stops before reaching the very last four entries which tend
        ## to be the Eth CPU quad. In any case, these canonical names
        ## of the Eth CPU ports will be replaced by generic names that
        ## are the same for all platforms below.
        self.ports_name2dev = {}
        self.ports_dev2name = {}
        for _data, _key in self.t.port_str_info.entry_get_iterator(None):
            data = _data.to_dict()
            key = _key.to_dict()
            name = key['$PORT_NAME']['value']
            dev = data['$DEV_PORT']
            self.ports_name2dev[name] = dev
            self.ports_dev2name[dev] = name

        ## Get the device configuration and extract the dev ports of
        ## the PCIe and Eth CPU ports to generate identifiers for
        ## those ports.
        self.dev_cfg = self.t.dev_cfg.default_entry_get()
        n = 0
        for dev_port in self.dev_cfg['eth_cpu_port_list']:
            ## Replace the canonical name of the port. It might not
            ## have been registered due to the issue mentioned above
            name = self.ports_dev2name.pop(dev_port, None)
            if name is not None:
                self.ports_name2dev.pop(name)
            eth_cpu_port = f'EthCPU{n}'
            self.ports_name2dev[eth_cpu_port] = dev_port
            self.ports_dev2name[dev_port] = eth_cpu_port
            logger.info(f'Registering Eth CPU port {eth_cpu_port}' +
                        f' as device port {dev_port}')
            n += 1
        pcie_cpu_port = 'PCIeCPU'
        pcie_cpu_dev_port = self.dev_cfg['pcie_cpu_port']
        logger.info(f'Registering PCIe CPU port {pcie_cpu_port} as'
                    + f' device port {pcie_cpu_dev_port}')
        self.ports_name2dev[pcie_cpu_port] = pcie_cpu_dev_port
        self.ports_dev2name[pcie_cpu_dev_port] = pcie_cpu_port

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
        logger.info("Detecting active ports")
        config = Config()
        for _port, _key in self.t.port.entry_get_iterator(None):
            port = _port.to_dict()
            key = _key.to_dict()
            name = port['$PORT_NAME']
            dev_port = key['$DEV_PORT']['value']
            logger.info("Port {0}({1}), Enable {2}, Up {3}".format(
                name,
                dev_port,
                port['$PORT_ENABLE'],
                port['$PORT_UP']
            ))
            config.ports[dev_port] = {
                'description': '',
                'speed': port['$SPEED'],
                'mtu': port['$RX_MTU'],
                'fec': port['$FEC'],
                'shutdown': not port['$PORT_ENABLE']
            }
        self.config = config

    def _is_tf1(self):
        return 'T10' in self.dev_cfg['sku']

    def _is_tf2(self):
        return 'T20' in self.dev_cfg['sku']

    def _get_dev_port(self, port):
        try:
            port = self.ports_name2dev[port]
        except:
            raise semantic_error("invalid port {0:s}".format(port))
        return port

    def _get_port_name(self, dev_port):
        if dev_port in self.ports_dev2name:
            return self.ports_dev2name[dev_port]
        else:
            return str(dev_port)

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

        def inc_mac(mac_in):
            mac = int(mac_in.replace(":",""),16) + 1
            mac = (hex(mac).removeprefix("0x")).rjust(12,'0')
            return ":".join([ mac[i:i+2] for i in range(0, len(mac), 2)])

        def get_src_mac(dev_port, context):
            if 'port-macs' not in config.system:
                raise semantic_error(f'{context}: MAC address pool configuration required')
            if dev_port in config.system['port-macs']:
                return config.system['port-macs'][dev_port]
            try:
                mac = config.system['system-macs'].pop(0)
            except:
                raise semantic_error("Can't assign MAC address to port " +
                                     f'{dev_port}, system pool exhausted')
            return mac

        system = json.get('system', None)
        if system is not None:
            mac_pools = system.get('mac-address-pools', None)
            if mac_pools is not None:
                config.system['port-macs'] = {}
                config.system['system-macs'] = {}
                mac = mac_pools['port']['base']
                size = mac_pools['port']['size']
                ## Assign MAC addresses to external ports and Eth CPU ports
                for dev_port in self.dev_cfg['external_port_list'] + self.dev_cfg['eth_cpu_port_list']:
                    config.system['port-macs'][dev_port] = mac
                    mac = inc_mac(mac)
                if size < len(config.system['port-macs']):
                    logger.warn(f"Port MAC address pool exhausted: size {size}, assigned {len(config.system['port-macs'])}")

                mac = mac_pools['system']['base']
                size = mac_pools['system']['size']
                config.system['system-macs'] = []
                for i in range(1, size + 1):
                    config.system['system-macs'].append(mac)
                    mac = inc_mac(mac)

            ip = system.get('ip', None)
            if ip is not None:
                config.system['ipv4'] = ipaddress.IPv4Address(ip['addressv4'])
                config.system['ipv6'] = ipaddress.IPv6Address(ip['addressv6'])

        ## All ports in the parsed configuration are validated and
        ## translated to device ports to catch all related errors
        ## before the configuration is pushed to the hardware
        def add_port(port, port_config):
            dev_port = self._get_dev_port(port)
            if dev_port in config.ports:
                raise semantic_error("port {0:s} already defined".format(port))
            full_config = {
                'description': '',
                'fec': 'BF_FEC_TYP_NONE',
                'shutdown': False
            }
            full_config.update(port_config)
            config.ports[dev_port] = full_config
            return dev_port

        for group in json['ports']['egress']:
            id = group['group-id']
            if id in config.groups.keys():
                raise semantic_error("group id {0:d} already defined".format(id))
            
            config.groups[id] = {}
            for port, dict in sorted(group['members'].items()):
                dev_port = add_port(port, dict['config'])
                config.groups[id][dev_port] = {}

        for port, dict in sorted(json['ports']['ingress'].items()):
            dev_port = add_port(port, dict['config'])
            egress_group = dict['egress-group']
            config.ingress[dev_port] = {
                'vlans' : dict['vlans'],
                'egress_group' : egress_group
            }
            if not egress_group in config.groups.keys():
                raise semantic_error("Undefined egress group {0:d}".format(egress_group))
        
        for port, dict in sorted(json['ports']['other'].items()):
            add_port(port, dict['config'])

        for port, dict in config.ingress.items():
            dict['vlans'].setdefault('accept', [])
            dict['vlans'].setdefault('rewrite', [])
            rewrite_vids = []
            for rewrite in dict['vlans']['rewrite']:
                rewrite_vids.append(rewrite['in'])
            for accept in dict['vlans']['accept']:
                accept.setdefault('mask', 4095)
                vid = accept['vid']
                if accept['mask'] == 4095 and vid in rewrite_vids:
                    raise semantic_error("port {0:s}: VLAN {1:d}: collision "
                                         "of exact accept and rewrite rules"
                                         .format(port, vid))

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

        if 'monitor-sessions' in json.keys():
            if self._is_tf1() and len(json['monitor-sessions']) > 1023:
                raise semantic_error(f'Monitor session {id}: restricted to 1023 on Tofino1')
            if self._is_tf2() and len(json['monitor-sessions']) > 255:
                raise semantic_error(f'Monitor session {id}: restricted to 255 on Tofino2')
            sessions = {}
            erspan_sessions = []
            mirror_sessions = []
            for name, session_in in json['monitor-sessions'].items():
                session_in.setdefault('max-packet-length', 0)
                mirror_session = None
                if name in self.config.monitor_sessions:
                    ## Preserve the mirror session ID for existing sessions
                    mirror_session = self.config.monitor_sessions[name]['mirror_session']
                    mirror_sessions.append(mirror_session)
                session = {
                    'mirror_session': mirror_session,
                }
                egress_dev_port = self._get_dev_port(session_in['egress-port'])
                session['egress-port'] = egress_dev_port
                encap_overhead = 0
                if 'encapsulation' in session_in:
                    session['encapsulation'] = {}
                    ## ERSPAN is currently the only supported encapsulation
                    erspan_in = session_in['encapsulation']['erspan']
                    erspan_in['ip'].setdefault('ttl', 64)
                    erspan = {
                        "session-id": erspan_in['session-id'],
                        "reset-seq": True if mirror_session == None else False,
                        "ethernet": erspan_in['ethernet'].copy(),
                        "ip": erspan_in['ip'].copy()
                    }
                    erspan['ethernet']['src'] = get_src_mac(egress_dev_port,
                                                            'ERSPAN encapsulation')
                    erspan['ip']['dst'] = ipaddress.ip_address(erspan_in['ip']['dst'])
                    if erspan['ip']['dst'].version == 4:
                        erspan['ip']['src'] = config.system['ipv4']
                    else:
                        erspan['ip']['src'] = config.system['ipv6']
                    erspan['ip']['ttl'] = erspan_in['ip']['ttl']
                    session['encapsulation']['erspan'] = erspan

                    ## An ERSPAN session is uniquely identified by the
                    ## tuple (source, destination, session-id).
                    session_tuple =  (erspan['ip']['src'].exploded +
                                      erspan['ip']['dst'].exploded +
                                      f"{erspan['session-id']}")
                    if session_tuple in erspan_sessions:
                        raise semantic_error(f"ERSPAN session {erspan['ip']['src']}, " +
                                             f"{erspan['ip']['dst']}, {erspan['session-id']} " +
                                             "is not unique")
                    else:
                        erspan_sessions.append(session_tuple)

                    ## Ethernet + GRE + ERSPAN
                    encap_overhead = 14 + 8 + 8
                    if 'vlan' in erspan['ethernet']:
                        encap_overhead += 4
                    if erspan['ip']['src'].version == 4:
                        encap_overhead += 20
                    else:
                        encap_overhead += 40

                ## Cap the size of mirrored packets to not exceed the
                ## egress MTU.
                max_packet_len = session_in['max-packet-length']
                if egress_dev_port in config.ports:
                    ## Only the PCIe CPU port doesn't have an MTU
                    egress_mtu = config.ports[egress_dev_port]['mtu']
                    if max_packet_len == 0 or max_packet_len + encap_overhead > egress_mtu:
                        max_packet_len = egress_mtu - encap_overhead
                        logger.info(f"Monitor session {id} on egress interface "
                                    + f"{session_in['egress-port']}: clamping mirror "
                                    + f"packet size at {max_packet_len} bytes to fit MTU "
                                    + f"{egress_mtu}")
                session['max-packet-length'] = max_packet_len
                config.monitor_sessions[name] = session

            ## Allocate a mirror session ID for new monitor sessions
            sessions_avail = list(set([ i for i in range(1, 1024) ]) - set(mirror_sessions))
            for session in config.monitor_sessions.values():
                if session['mirror_session'] is None:
                    ## Mirror sessions are numbered from 1
                    session['mirror_session'] = sessions_avail.pop(0)

        if 'flow-mirror' in json:
            de_duplicate = []
            def add_flow(flow_in):
                flow = flow_in.copy()
                if flow['monitor-session'] not in config.monitor_sessions:
                    raise semantic_error(("Undefined monitor session {} " +
                                         "in flow mirror rule: {}").
                                         format(flow['monitor-session'], JSON.dumps(flow_in)))

                flow['src'] = ipaddress.ip_network(flow['src'])
                flow['dst'] = ipaddress.ip_network(flow['dst'])

                if flow['src'].version != flow['dst'].version:
                    raise semantic_error("Address family mismatch " +
                                         "in flow mirror rule: {}".
                                         format(JSON.dumps(flow_in)))

                flow['ingress-ports'] = [ self._get_dev_port(port) for port in
                                          sorted(flow.pop('ingress-ports', [])) ]

                _flow = flow.copy()
                _flow.pop('monitor-session')
                if _flow in de_duplicate:
                    self._warning("Ignoring duplicate flow mirror rule: {}".
                                  format(JSON.dumps(flow_in)))
                else:
                    de_duplicate.append(_flow)
                    config.flow_mirror.append(flow)

            for flow in json['flow-mirror']:
                flow.setdefault("mirror-mode", "ingress")
                flow.setdefault("non-ip", False)
                flow.setdefault("enable", True)
                flow.setdefault("bidir", False)
                flow.setdefault("src", "0.0.0.0/0")
                flow.setdefault("dst", "0.0.0.0/0")
                flow.setdefault("src_port", { 'mask': 0, 'port': 0 })
                flow.setdefault("dst_port", { 'mask': 0, 'port': 0 })
                add_flow(flow)
                if flow['bidir'] and not flow['non-ip']:
                    bidir_flow = flow.copy()
                    bidir_flow['src'] = flow['dst']
                    bidir_flow['dst'] = flow['src']
                    bidir_flow['src_port'] = flow['dst_port']
                    bidir_flow['dst_port'] = flow['src_port']
                    add_flow(bidir_flow)

        features = json.get('features', {})
        for feature, value in features.items():
            if feature == 'deflect-on-drop':
                config.features['deflect-on-drop'] = int(self._get_dev_port(value))

            if feature == 'drop-non-initial-fragments' and value:
                config.features['drop-non-initial-fragments'] = True

            if feature == 'exclude-ports-from-hash' and value:
                config.features['exclude-ports-from-hash'] = True

            if feature == 'drop-non-ip' and value:
                config.features['drop-non-ip'] = True

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

        ### Note: all ports have been validated and converted to
        ### device ports during parsing
        
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
            for dev_port, member in members.items():
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
        self.t.ingress_src_mac_rewrite.clear()
        self.t.ingress_dst_mac_rewrite.clear()
        self.t.ingress_tagged.clear()
        for dev_port, dict in sorted(config.ingress.items()):
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

            if 'accept' in vlans:
                for rule in vlans['accept']:
                    self.t.ingress_tagged.entry_add(
                        [ { 'name': 'ingress_port', 'value': dev_port },
                          { 'name': 'ingress_vid', 'value': rule['vid'],
                            'mask':  rule.get('mask', 4095) } ],
                        'NoAction')

            if 'rewrite' in vlans:
                for rule in vlans['rewrite']:
                    self.t.ingress_tagged.entry_add(
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
                            tbl = self.t.ingress_src_mac_rewrite
                        else:
                            tbl = self.t.ingress_dst_mac_rewrite
                        field = dir + "_mac_addr"
                        action = "act_rewrite_" + dir + "_mac"
                        for addr, new_addr in spec.items():
                            tbl.entry_add(
                                [ { 'name': 'ingress_port', 'value': dev_port },
                                  { 'name': 'ingress_vid', 'value': rule['in'] },
                                  { 'name': field, 'value': addr } ],
                                action,
                                [ { 'name': 'mac_addr', 'val': new_addr } ])

        self.t.filter_ipv4.clear()
        self.t.filter_ipv6.clear()
        for prefix in (config.source_filter + config.source_filter_d):
            if prefix.version == 4:
                tbl = self.t.filter_ipv4
            else:
                tbl = self.t.filter_ipv6
            tbl.entry_add(
                [ { 'name': 'src_addr', 'value': prefix.network_address.exploded,
                    'prefix_len': prefix.prefixlen } ],
                'act_drop', [])

        self.t.mirror_cfg.clear()
        self.t.mirror_ipv4.clear()
        self.t.mirror_ipv6.clear()
        self.t.mirror_non_ip.clear()
        self.t.mirror_encap_l2.clear()
        self.t.mirror_encap_l3.clear()
        self.t.mirror_encap_l4.clear()
        for session_name, session in config.monitor_sessions.items():
            ## Configure the mirror session parameters. We use BOTH as
            ## direction because a monitor session can contain
            ## flow-mirrors with either direction.
            mirror_session = session['mirror_session']
            self.t.mirror_cfg.entry_add(
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
                    self.t.mirror_encap_l2.entry_add(
                        [ { 'name': 'mirror_session', 'value': mirror_session } ],
                        'act_mirror_encap_l2',
                        [ { 'name': 'src_mac', 'val': encap['ethernet']['src'] },
                          { 'name': 'dst_mac', 'val': encap['ethernet']['dst'] },
                          { 'name': 'ethertype', 'val': ethertype } ])
                else:
                    self.t.mirror_encap_l2.entry_add(
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
                self.t.mirror_encap_l3.entry_add(
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
                    reg_name = tables['encap_sequence'].removeprefix('pipe.') + '.f1'
                    self.t.encap_sequence.entry_mod(
                        [ { 'name': '$REGISTER_INDEX', 'value': mirror_session } ],
                        None,
                        [ { 'name': reg_name, 'val': 0 } ]
                    )
                    logger.info(f'Reset sequence number for new ERSPAN session {session_name}')
                self.t.mirror_encap_l4.entry_add(
                    [ { 'name': 'mirror_session', 'value':   mirror_session} ],
                    'act_mirror_encap_erspan',
                    [ { 'name': 'session', 'val': int(encap['session-id']) } ])

        for flow in config.flow_mirror:
            if not flow['enable']:
                continue
            mirror_session = config.monitor_sessions[flow['monitor-session']]['mirror_session']
            ports = flow['ingress-ports']
            port_mask = 0x1ff;
            if len(ports) == 0:
                ports = [ 0 ]
                port_mask = 0
            if flow['src'].version == 4:
                tbl = self.t.mirror_ipv4
            else:
                tbl = self.t.mirror_ipv6
            mirror_mode = mirror_modes[flow['mirror-mode']]
            for port in ports:
                if flow.get('non-ip', False):
                    self.t.mirror_non_ip.entry_add(
                        [ { 'name': 'ingress_port',
                            'value': port,
                            'mask': port_mask } ],
                        'act_mirror',
                        [ { 'name': 'mirror_session', 'val': mirror_session },
                          { 'name': 'mirror_mode', 'val': mirror_mode } ])
                else:
                    tbl.entry_add(
                        [ { 'name': 'ingress_port',
                            'value': port,
                            'mask': port_mask },
                          { 'name': 'src_addr',
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
                        [ { 'name': 'mirror_session', 'val': mirror_session },
                          { 'name': 'mirror_mode' , 'val': mirror_mode } ])

            
        self.t.drop.default_entry_reset()
        self.t.maybe_drop_fragment.default_entry_reset()
        self.t.maybe_exclude_l4.default_entry_reset()
        self.t.maybe_drop_non_ip.default_entry_reset()

        if 'deflect-on-drop' in config.features.keys():
            self.t.drop.default_entry_set(
                'ig_ctl.ctl_drop_packet.send_to_port',
                [ { 'name': 'port',  'val': config.features['deflect-on-drop'] } ])

        if config.features['drop-non-initial-fragments']:
            self.t.maybe_drop_fragment.default_entry_set('act_mark_to_drop')

        if  config.features['exclude-ports-from-hash']:
            self.t.maybe_exclude_l4.default_entry_set('act_exclude_l4')

        if  config.features['drop-non-ip']:
            self.t.maybe_drop_non_ip.default_entry_set('act_mark_to_drop')

        for dev_port, pconfig in sorted(config.ports.items()):
            if dev_port in self.config.ports:
                if self.config.ports[dev_port] == pconfig:
                    method = None
                else:
                    method = self.t.port.entry_mod
                    if self.config.ports[dev_port]['shutdown'] != pconfig['shutdown']:
                        self._info("port {0} administrative status changed to {1}".
                                   format(dev_port, 'down' if pconfig['shutdown'] else 'up'))
                del self.config.ports[dev_port]
            else:
                method = self.t.port.entry_add
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
            if dev_port in self.ports_dev2name:
                port_name = self.ports_dev2name[dev_port]
                if dev_port not in self.ifmibs:
                    self.ifmibs[dev_port] = mib.ifmib(self.ifmibs_dir+'/'+re.sub('/', '_', port_name))
                self.ifmibs[dev_port].set_properties(
                    { 'ifDescr': port_name.encode('ascii'),
                      'ifName': port_name.encode('ascii'),
                      'ifAlias': pconfig['description'].encode('ascii'),
                      'ifMtu': pconfig['mtu'],
                      'speed': if_speed[pconfig['speed']] }
            )

        ## The old config now only contains ports that are not present
        ## in the new config
        for dev_port in sorted(self.config.ports.keys()):
            self.t.port.entry_del([ { 'name': '$DEV_PORT', 'value': dev_port } ])
            ## It is possible that a port exists but was not added by
            ## us (e.g. port added via bfshell, Tofino model starts up
            ## with all ports active). In that case, the port is not
            ## registered in the ifmib.
            if dev_port in self.ifmibs:
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
            port_name = port_t['$PORT_NAME']
            status[dev_port] = port_t['$PORT_UP']
            if old_oper_status != new_oper_status:
                logger.info("port {0} operational status changed to {1}".
                      format(port_name, 'up' if new_oper_status == 1 else 'down'))

        for group, members in self.config.groups.items():
            update = False
            at_least_one_valid = False
            for port, member in members.items():
                at_least_one_valid = at_least_one_valid or status[port]
                if member['status'] != status[port]:
                   member['status'] = status[port]
                   logger.info("egress group {0} status of member port {1} changed to {2}".
                         format(group, self._get_port_name(port), 'up' if status[port] else 'down'))
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

                self._set_action_selector(self.t.port_groups_sel.entry_mod,
                                          group, members)

                if at_least_one_valid and not self.config.groups_ref[group]:
                    self.t.forward.entry_add([ { 'name': 'egress_group', 'value': group } ],
                                             None,
                                             [ { 'name': '$SELECTOR_GROUP_ID', 'val': group } ])
                    self.config.groups_ref[group] = True

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
            'monitor-sessions': 'monitor_sessions',
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
