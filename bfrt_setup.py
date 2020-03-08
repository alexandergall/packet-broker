#### Terrible hack to get the jsonschema module, which is
#### missing in $SDE_INSTALL.  What we *really* should be
#### doing is to talk to bf_switchd via gRPC.  This would
#### certainly work for the P4 tables, but maybe not for
#### the port configurations.
import sys
sys.path.append('/usr/local/lib/python3.5/dist-packages')
sys.path.append('/usr/local/lib/python2.7/dist-packages/jsonschema-2.6.0-py2.7.egg')
import json
import jsonschema
import ipaddress

config_dir = '/etc/packet-broker'
ports_new = {}
ports_old = []
groups = {}
ingress = {}
source_filter = []
flow_mirror = []

MIRROR_SESSION = 1

bf_port = bfrt.port

p4 = bfrt.packet_broker
ig_ctl = p4.pipe.ig_ctl

ctls = {
    'vlan' : ig_ctl.ctl_push_or_rewrite_vlan,
    'forward' : ig_ctl.ctl_forward_packet,
    'filter_ipv4' : ig_ctl.ctl_filter_source_ipv4,
    'filter_ipv6' : ig_ctl.ctl_filter_source_ipv6,
    'mirror_ipv4' : ig_ctl.ctl_mirror_flows_ipv4,
    'mirror_ipv6' : ig_ctl.ctl_mirror_flows_ipv6,
    'maybe_exclude_l4_from_hash' : ig_ctl.ctl_maybe_exclude_l4_from_hash,
    'maybe_drop_fragment' : ig_ctl.ctl_maybe_drop_fragment,
    'drop' : ig_ctl.ctl_drop_packet
}

tbls = {
    'ingress_untagged' : ctls['vlan'].tbl_ingress_untagged,
    'ingress_tagged' : ctls['vlan'].tbl_ingress_tagged,
    'filter_ipv4' : ctls['filter_ipv4'].tbl_filter_source_ipv4,
    'filter_ipv6' : ctls['filter_ipv6'].tbl_filter_source_ipv6,
    'mirror_ipv4' : ctls['mirror_ipv4'].tbl_mirror_flows_ipv4,
    'mirror_ipv6' : ctls['mirror_ipv6'].tbl_mirror_flows_ipv6,
    'select_output' : ctls['forward'].tbl_select_output,
    'forward' : ctls['forward'].tbl_forward,
    'port_groups' : ctls['forward'].port_groups,
    'port_groups_sel' : ctls['forward'].port_groups_sel,
    'maybe_exclude_l4' : ctls['maybe_exclude_l4_from_hash'].tbl_maybe_exclude_l4,
    'drop' : ctls['drop'].tbl_drop,
    'maybe_drop_fragment' : ctls['maybe_drop_fragment'].tbl_maybe_drop_fragment
}

def semantic_error(msg):
    sys.tracebacklimit = None
    raise Exception(msg)

indent_level = 0

def indent(msg):
    global indent_level
    print(' ' * indent_level * 4 + msg)
        
def indent_up():
    global indent_level
    indent_level += 1
        
def indent_down():
    global indent_level
    indent_level -= 1
        
def get_dev_port(port):
    global bf_port
    return bf_port.port_str_info.get(port_name=port,
                                     print_ents=False).data[b'$DEV_PORT']
def format_port(port):
    if re.match("^[0-9]+$", port):
        return "physical port {0:d}".format(int(port))
    return "{0:s} (physical port {1:d})".format(port, get_dev_port(port))

def add_port(port, config):
    if port in ports_new.keys():
        semantic_error("port {0:s} already defined".format(port))
    ports_new[port] = config
    
def configure_port(port, config):
    global ports_old
    global ports_new
    global bf_port
    global get_dev_port
    global format_port
    global indent
    global indent_up
    global indent_down
    
    dev_port = get_dev_port(port)
    speed = config['speed']
    mtu = config['mtu']
    fec = config.get('fec', "BF_FEC_TYP_NONE")

    indent("Port " + format_port(port))
    indent_up()
    if 'description' in config.keys():
        indent("Description: {0}".format(config['description']))
    indent("Speed: {0}".format(speed))
    indent("MTU  : {0}".format(mtu))
    indent("FEC  : {0}".format(fec))
    indent_down()
    
    if port in ports_old:
        bf_port.port.mod(dev_port = dev_port, speed = speed, fec = fec)
        ports_old.remove(port)
    else:
        bf_port.port.add(dev_port = dev_port, speed = speed, fec = fec)

    bf_port.port.mod(dev_port = dev_port,
                     port_enable = True,
                     rx_mtu = mtu,
                     tx_mtu = mtu)

def clear_tables(tables):
    for table in tables:
        name = table.info(return_info=True, print_info=False)['table_name']
        table.clear()

def json_load(name):
    with open(name) as file:
        parsed = json.load(file)
    file.close()
    return parsed

config = json_load(config_dir + '/config.json')
schema = json_load(config_dir + '/schema.json')
jsonschema.validate(config, schema)

### Get the list of ports that are currently configured (i.e. that
### have been added previously via the port.add() method).
dump = bf_port.port.dump(return_ents=True)
if not dump is None:
    ports_old = [ port.data[b'$PORT_NAME'] for port in dump ]

indent("Setting up egress port groups")
indent_up()
for group in config['ports']['egress']:
    id = group['group-id']
    if id in groups.keys():
        semantic_error("group id {0:d} already defined".format(id))

    indent("Group {0:d}".format(id))
    indent_up()
    groups[id] = []
    for port, dict in sorted(group['members'].items()):
        indent("Port " + format_port(port))
        add_port(port, dict['config'])
        groups[id].append(port)
    indent_down()
indent_down()
        
indent("Setting up ingress ports")
indent_up()
for port, dict in sorted(config['ports']['ingress'].items()):
    indent("Port " + format_port(port))
    add_port(port, dict['config'])
    ingress[port] = {
        'vlans' : dict['vlans'],
        'egress_group' : dict['egress-group']
    }
indent_down()

indent("Setting up other ports")
indent_up()
for port, dict in sorted(config['ports']['other'].items()):
    indent("Port " + format_port(port))
    add_port(port, dict['config'])
indent_down()

if 'source-filter' in config.keys():
    indent("Setting source filters")
    indent_up()
    for str in config['source-filter']:
        prefix = ipaddress.ip_network(str)
        indent(prefix.with_prefixlen)
        source_filter.append(prefix)
    indent_down()

if 'flow-mirror' in config.keys():
    indent("Setting flow mirrors")
    indent_up()

    def format_l4_port(spec):
        return("port 0x{0:04X}({0:d}) mask 0x{1:04X}".format(
            spec['port'], spec['mask']))

    def add_flow(flow):
        global ipaddress
        global format_l4_port
        global flow_mirror
        global semantic_error

        src = ipaddress.ip_network(flow['src'])
        dst = ipaddress.ip_network(flow['dst'])
        src_port = flow['src_port']
        dst_port = flow['dst_port']

        indent("{0:s} {1:s} -> {2:s} {3:s}".format(
            src.with_prefixlen, format_l4_port(src_port),
            dst.with_prefixlen, format_l4_port(dst_port)))
        if src.version != dst.version:
            semantic_error("address family mismatch")
        flow_mirror.append([ src, dst, src_port, dst_port ])

    for flow in config['flow-mirror']:
        if 'enable' in flow.keys() and not flow['enable']:
            continue
        if (not 'features' in config.keys() or
            not 'flow-mirror' in config['features'].keys()):
            semantic_error("mirror destination missing")

        add_flow(flow)
        if not 'bidir' in flow.keys() or flow['bidir']:
            add_flow({ 'src': flow['dst'],
                       'dst': flow['src'],
                       'src_port': flow['dst_port'],
                       'dst_port': flow['src_port'] })
    indent_down()

### Feature defaults
tbls['drop'].set_default_with_real_drop()
tbls['maybe_drop_fragment'].set_default_with_NoAction()
tbls['maybe_exclude_l4'].set_default_with_NoAction()

if 'features' in config.keys():
    indent("Setting features")
    indent_up()
    
    for feature, value in config['features'].items():
        if feature == 'deflect-on-drop':
            indent("Deflect-on-drop to port " + format_port(value))
            if re.match("^[0-9]+$", value):
                tbls['drop'].set_default_with_send_to_port(port = value)
            else:
                tbls['drop'].set_default_with_send_to_port(port = get_dev_port(value))

        if feature == 'flow-mirror':
            indent("Flow mirror")
            indent_up()
            cfg = value

            port = cfg['port']
            indent("Destination port " + format_port(port))
            if not re.match("^[0-9]+$", port):
                port = get_dev_port(port)

            if 'max-packet-length' in cfg.keys():
                max_pkt_len = cfg['max-packet-length']
            else:
                max_pkt_len = 16384
            indent("Maximum packet length {0:d}".format(max_pkt_len))

            mirror = bfrt.mirror.cfg
            mirror.add_with_normal(
                sid = MIRROR_SESSION,
                session_enable = True,
                direction = 'INGRESS',
                ucast_egress_port = port,
                ucast_egress_port_valid = True,
                max_pkt_len = max_pkt_len
            )

            indent_down()

        if feature == 'drop-non-initial-fragments' and value:
            indent("Drop non-initial fragemnts")
            tbls['maybe_drop_fragment'].set_default_with_act_mark_to_drop()

        if feature == 'exclude-ports-from-hash' and value:
            indent("Exclude L4 ports from hash")
            tbls['maybe_exclude_l4'].set_default_with_act_exclude_l4()        

    indent_down()
        
indent("Programming tables")
indent_up()

### Action profile and selector
## Order is important here
clear_tables([tbls['forward'],
              tbls['port_groups_sel'],
              tbls['port_groups']])
member_id = 1
for group, ports in groups.items():
    member_list = []
    for port in ports:
        dev_port = get_dev_port(port)
        indent("Adding action profile member {0:d} port {1:s}".
               format(member_id, format_port(port)))
        member_list.append(member_id)
        tbls['port_groups'].add_with_act_send(action_member_id = member_id,
                                              egress_port = get_dev_port(port))
        member_id += 1

    indent("Adding action selector group #{0:d}".format(group))
    tbls['port_groups_sel'].add(
        selector_group_id = group,
        max_group_size=8,
        ## References action_member_ids from profile
        action_member_id = member_list,
        action_member_status = [ True ] * len(member_list))
    
    tbls['forward'].add(egress_group = group, selector_group_id = group)

clear_tables([tbls['ingress_untagged'],
              tbls['ingress_tagged'],
              tbls['select_output']])
for port, dict in sorted(ingress.items()):
    dev_port = get_dev_port(port)
    vlans = dict['vlans']
    egress_group = dict['egress_group']
    indent("Output group for port {0:s} is {1:d}".format(port, egress_group))
    if not egress_group in groups.keys():
        semantic_error("Undefined egress group {0:d}".format(egress_group))
        
    tbls['select_output'].add_with_act_output_group(ingress_port = dev_port,
                                                        group = egress_group)
    if 'push' in vlans:
        tbls['ingress_untagged'].add_with_act_push_vlan(ingress_port = dev_port,
                                                            vid = vlans['push'])
    if 'rewrite' in vlans:
        for rule in vlans['rewrite']:
            tbls['ingress_tagged'].add_with_act_rewrite_vlan(ingress_port = dev_port,
                                                                 ingress_vid = rule['in'],
                                                                 vid = rule['out'])

clear_tables([tbls['filter_ipv4'], tbls['filter_ipv6']])
for prefix in source_filter:
    if prefix.version == 4:
        tbl = tbls['filter_ipv4']
    else:
        tbl = tbls['filter_ipv6']
    tbl.add_with_act_drop(src_addr = prefix.network_address,
                          src_addr_p_length = prefix.prefixlen)

clear_tables([tbls['mirror_ipv4'], tbls['mirror_ipv6']])
for flow in flow_mirror:
    src = flow[0]
    dst = flow[1]
    src_port = flow[2]
    dst_port = flow[3]
    if src.version == 4:
        tbl = tbls['mirror_ipv4']
    else:
        tbl = tbls['mirror_ipv6']
    tbl.add_with_act_mirror(
        src_addr = src.network_address, src_addr_mask = int(src.netmask),
        dst_addr = dst.network_address, dst_addr_mask = int(dst.netmask),
        src_port = src_port['port'], src_port_mask = src_port['mask'],
        dst_port = dst_port['port'], dst_port_mask = dst_port['mask'],
        mirror_session = MIRROR_SESSION)

indent_down()
    
indent("Configuring ports")
indent_up()

for port, config in sorted(ports_new.items()):
    configure_port(port, config)

for port in sorted(ports_old):
    dev_port = get_dev_port(port)
    indent("Removing unsued port {0} (phys port {1})".format(port, dev_port))
    bf_port.port.delete(dev_port = dev_port)

indent_down()
