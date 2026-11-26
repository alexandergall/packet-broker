from abc import ABC, abstractmethod
from referencing import Registry, Resource
from functools import reduce
import jsonschema
import json
import ipaddress
from state import State
from copy import deepcopy
import logging

logger = logging.getLogger(__name__)

## IP protocols that carry a pair of 16-bit port numbers at the start
## of their headers (source first)
protocols_with_ports = [
    6,   # TCP
    17,  # UDP
    33,  # DCCP
    132, # SCTP
]

class semantic_error(Exception):
    def __init__(self, message):
        super().__init__("Semantic error: " + message)

class Config:
    def __init__(self, bfrt, dev, config_path=None, prev_config=None,
                 dyn_override={}):
        self.t = bfrt.tables
        self.dev = dev
        self.prev_config = prev_config
        self.state = State(bfrt, dev)

        ## NB: self.config_in is the raw, JSON validated user
        ## configuration. self.config is a copy of that with explicit
        ## defaults and dynamic configurations added.

        if prev_config is None:
            ## Bootstrap: the first Config instance has neither static
            ## nor dynamic configurations. Its only purpose is to
            ## provide an artificial ancestor for the first proper
            ## Config to pass to State.apply()
            self.config_in = {}
            self.dyn = {
                'source-filter': ConfigSourceFilter([], validate=True),
                'flow-mirror': ConfigFlowMirrorAdd([]),
            }
            ## Add state for currently active ports to avoid flaps
            ## when the control-plane is restarted.
            self.state.ports.update(dev.detect_ports())
            return

        ## Non-initial configuration, inherit dynamic configs from
        ## ancestor and apply overrides
        self.dyn = {}
        for name, inst in prev_config.dyn.items():
            self.dyn[name] = deepcopy(inst)
            if dyn_override.get(name, False):
                self.dyn[name].modify(*dyn_override[name])

        if config_path is not None:
            ## Load fresh configuration from file
            try:
                with open(config_path) as file:
                    self.config_in = json.load(file)
            except Exception as e:
                raise Exception(f"Error loading {config_path}: {e}")
        else:
            ## Inherit configuration from ancestor. Used for dynamic
            ## updates that instantiate a new Config without
            ## re-reading the static configuration.
            self.config_in = deepcopy(prev_config.config_in)

        ## Split the configuration into parts. Default settings are
        ## added during parsing.
        self.config = deepcopy(self.config_in)
        self.parts = []
        config_items = [
            (ConfigTopLevel, [], None),
            (ConfigSystem, [ 'system' ], None),
            (ConfigPorts, [ 'ports' ], None),
            (ConfigSourceFilter, [ 'source-filter' ], self.dyn['source-filter']),
            (ConfigMonitorSessions, [ 'monitor-sessions' ], None),
            (ConfigFlowMirror, [ 'flow-mirror' ], self.dyn['flow-mirror']),
            (ConfigFeatures, [ 'features' ], None)
        ]
        for cls, path, dyn in config_items:
            self.parts.append(cls(self.sub_config(path), dyn))

    ## Given a list of names, extract the object located at that
    ## point in the configuration hierarchy
    def sub_config(self, path, processed=True):
        return reduce(dict.get, path, self.config if processed else self.config_in)

    def validate(self):
        for part in self.parts:
            part.validate()

    def parse(self):
        for part in self.parts:
            part.parse(self.dev, self.state, self.prev_config.state)

    def apply(self, method='apply'):
        getattr(self.state, method)(self.prev_config.state)

class ConfigItem(ABC):
    ## Class-wide cache of loaded schemas
    uri_cache = {}

    @classmethod
    def schema_dir(self, dir):
        self._schema_dir = dir

    def __init__(self, config, other = None, validate = False):
        self.config = config
        if other is not None:
            self.merge_with(other)
        if validate:
            self.validate()

    def validate(self):
        cls = self.__class__
        if not hasattr(cls, 'validator'):
            def create_validator_for_schema(file_name):
                def retrieve_schema(uri):
                    if uri not in ConfigItem.uri_cache:
                        with open(self._schema_dir + "/" + uri) as file:
                            contents = json.load(file)
                        ConfigItem.uri_cache[uri] = Resource.from_contents(contents)
                    return ConfigItem.uri_cache[uri]

                path = self._schema_dir + "/" + file_name
                try:
                    with open(path) as file:
                        schema = json.load(file)
                except Exception as e:
                    raise Exception(f'BUG: JSON parse error on schema {path}: {e}')
                return jsonschema.Draft202012Validator(
                    schema, registry=Registry(retrieve=retrieve_schema))
            cls.validator = create_validator_for_schema(cls.schema)
        cls.validator.validate(self.config)

    def merge_with(self, other):
        assert(self.__class__ == other.__class__ or
               issubclass(other.__class__, self.__class__))

    @abstractmethod
    def parse(self, dev, state, prev_state):
        pass

class ConfigTopLevel(ConfigItem):
    schema = "main.json"

    def parse(self, *_):
        config = self.config
        config.setdefault('system', {})
        config.setdefault('source-filter', [])
        config.setdefault('monitor-sessions', {})
        config.setdefault('flow-mirror', [])
        config.setdefault('features', {})

class ConfigSystem(ConfigItem):
    schema = "system.json"

    def parse(self, dev, state, *_):
        config = self.config

        def inc_mac(mac_in):
            mac = int(mac_in.replace(":",""),16) + 1
            mac = (hex(mac).removeprefix("0x")).rjust(12,'0')
            return ":".join([ mac[i:i+2] for i in range(0, len(mac), 2)])

        for name, pool in config.get('mac-address-pools', {}).items():
            mac = pool['base']
            size = pool['size']
            if name == "port":
                state.system['port-macs'] = {}
                ## Assign MAC addresses to external ports and Eth CPU ports
                for dev_port in dev.cfg['external_port_list'] + dev.cfg['eth_cpu_port_list']:
                    state.system['port-macs'][dev_port] = mac
                    mac = inc_mac(mac)
                    if size < len(state.system['port-macs']):
                        logger.warn(f"Port MAC address pool exhausted: size {size}, "
                                    + f"assigned {len(state.system['port-macs'])}")
            else:
                state.system['system-macs'] = []
                for i in range(1, size + 1):
                    state.system['system-macs'].append(mac)
                    mac = inc_mac(mac)

        ip = config.get('ip', None)
        if ip is not None:
            state.system['ipv4'] = ipaddress.IPv4Address(ip['addressv4'])
            state.system['ipv6'] = ipaddress.IPv6Address(ip['addressv6'])

class ConfigPorts(ConfigItem):
    schema = "ports.json"

    def parse(self, dev, state, *_):
        config = self.config

        def add_port(port, port_config):
            dev_port = dev.get_dev_port(port)
            if dev_port in state.ports:
                raise semantic_error(f"port {port} already defined")
            port_config.setdefault('description', '')
            port_config.setdefault('fec', 'BF_FEC_TYP_NONE')
            port_config.setdefault('shutdown', False)
            state.ports[dev_port] = port_config
            return dev_port

        ## NB: assignment of member ids must be deterministic for
        ## dynamic configurations to work correctly, because the
        ## regular state.apply() method is skipped and thus the
        ## hardware configuration using the member ids from the
        ## previous configutation remains active.
        member_id = 1
        for group in config['egress']:
            id = group['group-id']
            if id in state.groups.keys():
                raise semantic_error(f"group id {id} already defined")

            state.groups[id] = {}
            for port, dict in sorted(group['members'].items()):
                dev_port = add_port(port, dict['config'])
                state.groups[id][dev_port] = {
                    "id": member_id,
                    "status": False
                }
                member_id += 1

        for port, dict in sorted(config['ingress'].items()):
            dev_port = add_port(port, dict['config'])
            egress_group = dict['egress-group']
            state.ingress[dev_port] = {
                'vlans' : dict['vlans'],
                'egress_group' : egress_group
            }
            if not egress_group in state.groups.keys():
                raise semantic_error(f"Port {port}: undefined egress group {egress_group}")

        for port, dict in sorted(config.get('other', []).items()):
            add_port(port, dict['config'])

        for port, dict in config['ingress'].items():
            dict['vlans'].setdefault('accept', [])
            dict['vlans'].setdefault('rewrite', [])
            rewrite_vids = []
            for rewrite in dict['vlans']['rewrite']:
                rewrite_vids.append(rewrite['in'])
            for accept in dict['vlans']['accept']:
                accept.setdefault('mask', "0xFFF")
                vid = accept['vid']
                if int(accept['mask'], 0) == 4095 and vid in rewrite_vids:
                    raise semantic_error("port {0:s}: VLAN {1:d}: collision "
                                         "of exact accept and rewrite rules"
                                         .format(port, vid))

class ConfigSourceFilter(ConfigItem):
    schema = "source-filter.json"

    def validate(self):
        super().validate()
        self.prefixes = []
        for str in self.config:
            try:
                prefix = ipaddress.ip_network(str)
            except Exception as e:
                raise semantic_error(f"Source filter: {e}")
            self.prefixes.append(ipaddress.ip_network(prefix))

    def parse(self, dev, state, *_):
        for prefix in self.prefixes:
            if prefix in state.source_filter:
                raise semantic_error(f"Duplicate source filter: {prefix}")
            else:
                state.source_filter.append(prefix)

    def merge_with(self, other):
        super().merge_with(other)
        self.config[:0] = other.config
        self.validate()

    def modify(self, mode, other):
        for prefix in other.prefixes:
            if mode == 'add':
                self.prefixes.append(prefix)
            else:
                if prefix not in self.prefixes:
                    raise semantic_error(f"Can't remove {prefix}: not present in dynamic source filters")
                self.prefixes.remove(prefix)
        self.config = []
        for prefix in self.prefixes:
            self.config.append(prefix.exploded)

class ConfigMonitorSessions(ConfigItem):
    schema = 'monitor-sessions.json'

    def parse(self, dev, state, prev_state):
        config = self.config

        if dev.is_tf1() and len(config) > 1023:
            raise semantic_error(f'Monitor session {id}: restricted to 1023 on Tofino1')
        if dev.is_tf2() and len(config) > 255:
            raise semantic_error(f'Monitor session {id}: restricted to 255 on Tofino2')
        sessions = {}
        erspan_sessions = []
        mirror_sessions = []
        for name, session_in in config.items():
            session_in.setdefault('max-packet-length', 0)
            mirror_session = None
            if name in prev_state.monitor_sessions:
                ## Preserve the mirror session ID for existing sessions
                mirror_session = prev_state.monitor_sessions[name]['mirror_session']
                mirror_sessions.append(mirror_session)
            session = {
                'mirror_session': mirror_session,
            }
            egress_dev_port = dev.get_dev_port(session_in['egress-port'])
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
                try:
                    erspan['ethernet']['src'] = state.get_src_mac(egress_dev_port)
                except Exception as e:
                    raise semantic_error(f"ERSPAN encapsulation: {e}")
                erspan['ip']['dst'] = ipaddress.ip_address(erspan_in['ip']['dst'])
                if erspan['ip']['dst'].version == 4:
                    src = state.system.get('ipv4', None)
                else:
                    src = state.system.get('ipv6', None)
                if src is None:
                    raise semantic_error(f"ERSPAN encapsulation: system IP address configuration required")
                erspan['ip']['src'] = src
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
            if egress_dev_port in state.ports:
                ## Only the PCIe CPU port doesn't have an MTU
                egress_mtu = state.ports[egress_dev_port]['mtu']
                if max_packet_len == 0 or max_packet_len + encap_overhead > egress_mtu:
                    max_packet_len = egress_mtu - encap_overhead
                    logger.info(f"Monitor session {name} on egress interface "
                                + f"{session_in['egress-port']}: clamping mirror "
                                + f"packet size at {max_packet_len} bytes to fit MTU "
                                + f"{egress_mtu}")
            session['max-packet-length'] = max_packet_len
            state.monitor_sessions[name] = session

        ## Allocate a mirror session ID for new monitor sessions
        sessions_avail = list(set([ i for i in range(1, 1024) ]) - set(mirror_sessions))
        for session in state.monitor_sessions.values():
            if session['mirror_session'] is None:
                ## Mirror sessions are numbered from 1
                session['mirror_session'] = sessions_avail.pop(0)

class ConfigFlowMirror(ConfigItem):
    schema = 'flow-mirror.json'

    def parse(self, dev, state, *_):
        config = self.config

        flow_rules = []
        for flow_in in config:
            def add_flow(flow):
                rs = json.dumps(flow['rules'], sort_keys = True)
                if rs in flow_rules:
                    raise semantic_error(f"Duplicate flow mirror rule: {json.dumps(flow_in)}")
                else:
                    flow_rules.append(rs)
                    state.flow_mirror.append(flow)

            if flow_in['monitor-session'] not in state.monitor_sessions:
                raise semantic_error(f"Undefined monitor session {flow_in['monitor-session']} " +
                                      f"in flow mirror rule: {json.dumps(flow_in)}")
            flow_in.setdefault('enable', True)
            flow_in.setdefault('bidir', False)
            flow_in.setdefault('mirror-mode', 'ingress')
            flow = {
                'monitor-session': flow_in['monitor-session'],
                'mirror-mode': flow_in['mirror-mode'],
                'enable': flow_in['enable'],
                'bidir': flow_in['bidir'],
                'ingress-ports': [ dev.get_dev_port(port) for port in
                                   sorted(flow_in.get('ingress-ports', [])) ]
            }

            for match_name, rules_in in flow_in['match'].items():
                if match_name == 'ethernet':
                    match_any = {
                        'address': '00:00:00:00:00:00',
                        'mask': '00:00:00:00:00:00'
                    }
                    rules_in.setdefault('src', match_any)
                    rules_in['src'].setdefault('mask', 'ff:ff:ff:ff:ff:ff')
                    rules_in.setdefault('dst', match_any)
                    rules_in['dst'].setdefault('mask', 'ff:ff:ff:ff:ff:ff')
                    rules_in.setdefault('type', None)
                    flow['rule-type'] = 'l2'
                    flow['rules'] = rules_in
                    add_flow(flow)
                    if flow['bidir']:
                        _flow = flow.copy()
                        _flow['rules']['src'] = rules_in['dst']
                        _flow['rules']['dst'] = rules_in['src']
                        add_flow(_flow)

                else:
                    af = { 'ipv4': 4, 'ipv6': 6}[match_name]
                    if af == 4:
                        rules_in.setdefault('src', "0.0.0.0/0")
                        rules_in.setdefault('dst', "0.0.0.0/0")
                    else:
                        rules_in.setdefault('src', "::/0")
                        rules_in.setdefault('dst', "::/0")

                    rules_in.setdefault('protocols', [])
                    any_port = { 'port': 0, 'mask': "0x0" }
                    rules_in.setdefault('src-port', any_port)
                    rules_in.setdefault('dst-port', any_port)
                    rules_in['src-port'].setdefault('mask', "0xffff")
                    rules_in['dst-port'].setdefault('mask', "0xffff")
                    if (int(rules_in['src-port']['mask'], 0) > 0 or
                        int(rules_in['dst-port']['mask'], 0) > 0):
                        ## Port rule is present, protocol must be a subset
                        ## of the list of supported protocols. Default is
                        ## all supported protocols. Missing port spec defaults to
                        ## any port, missing mask defaults to exact match.
                        if not rules_in['protocols']:
                            rules_in['protocols'] = protocols_with_ports
                        if not set(rules_in['protocols']) <= set(protocols_with_ports):
                            raise semantic_error(("Port rules are only supported for "
                                                  +"protocols {}, got {}, in flow {}").
                                                 format(protocols_with_ports,
                                                        rules_in['protocols'],
                                                        json.dumps(flow_in)))
                    flow['rule-type'] = 'l3'
                    rules = rules_in.copy()
                    src = ipaddress.ip_network(rules_in['src'])
                    dst = ipaddress.ip_network(rules_in['dst'])
                    if src.version != af or dst.version != af:
                        raise semantic_error("Address family mismatch " +
                                             "in {} match rule: {}".
                                             format(match_name, json.dumps(flow_in)))
                    rules['src'] = src.network_address.exploded
                    rules['src-mask'] = int(src.netmask)
                    rules['dst'] = dst.network_address.exploded
                    rules['dst-mask'] = int(dst.netmask)
                    rules['af'] = af
                    flow['rules'] = rules
                    add_flow(flow)
                    if flow['bidir']:
                        _flow = flow.copy()
                        _flow['rules'] = {
                            'af': rules['af'],
                            'src': rules['dst'],
                            'src-mask': rules['dst-mask'],
                            'dst': rules['src'],
                            'dst-mask': rules['src-mask'],
                            'protocols': rules['protocols'],
                            'src-port': rules['dst-port'],
                            'dst-port': rules['src-port']
                        }
                        add_flow(_flow)

    def merge_with(self, other):
        super().merge_with(other)
        self.config[:0] = other.config

    def modify(self, mode, other):
        def find(flow, config):
            for item in config:
                if flow['uuid'] == item['uuid']:
                    return item
            return None

        for flow in other.config:
            match = find(flow, self.config)
            if mode == "add":
                if match:
                    raise semantic_error(f"Can't add flow mirror {flow['uuid']}: duplicate UUID")
                self.config.append(flow)
            else:
                if not match:
                    raise semantic_error(f"Can't remove flow mirror {flow['uuid']}: UUID does not exist")
                self.config.remove(match)

class ConfigFlowMirrorAdd(ConfigFlowMirror):
    ## FIXME: This should be handled by a specialized JSON schema
    def validate(self):
        super().validate()
        for flow in self.config:
            if flow.get('uuid', None) is None:
                raise semantic_error(f"UUID missing for dynamic flow mirror {flow}")

## Pseudo flow mirror configuration used for the "brokerctl remove
## flow-mirror" command. These objects contain only "uuid" as single
## mandatory field.
class ConfigFlowMirrorRm(ConfigItem):
    schema = "flow-mirror-rm.json"

    def parse(self, *_):
        pass

class ConfigFeatures(ConfigItem):
    schema = 'features.json'

    def parse(self, dev, state, *_):
        config = self.config

        config.setdefault('drop-non-initial-fragments', False)
        config.setdefault('exclude-ports-from-hash', False)
        config.setdefault('drop-non-ip', False)

        for feature, value in config.items():
            if feature == 'deflect-on-drop':
                state.features['deflect-on-drop'] = int(dev.get_dev_port(value))
            else:
                state.features[feature] = value
