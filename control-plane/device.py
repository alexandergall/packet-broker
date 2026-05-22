import logging

### Internal tables
tables = {
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
}

logger = logging.getLogger(__name__)

class Device:
    def __init__(self, bfrt):
        self.bfrt = bfrt

        for name, loc in tables.items():
            bfrt.add_table(name, loc)

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
        for _data, _key in bfrt.tables.port_str_info.entry_get_iterator(None):
            data = _data.to_dict()
            key = _key.to_dict()
            name = key['$PORT_NAME']['value']
            dev = data['$DEV_PORT']
            self.ports_name2dev[name] = dev
            self.ports_dev2name[dev] = name

        ## Get the device configuration and extract the dev ports of
        ## the PCIe and Eth CPU ports to generate identifiers for
        ## those ports.
        self.cfg = bfrt.tables.dev_cfg.default_entry_get()
        n = 0
        for dev_port in self.cfg['eth_cpu_port_list']:
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
        pcie_cpu_dev_port = self.cfg['pcie_cpu_port']
        logger.info(f'Registering PCIe CPU port {pcie_cpu_port} as'
                    + f' device port {pcie_cpu_dev_port}')
        self.ports_name2dev[pcie_cpu_port] = pcie_cpu_dev_port
        self.ports_dev2name[pcie_cpu_dev_port] = pcie_cpu_port

    def detect_ports(self):
        logger.info("Detecting active ports")
        ports = {}
        for _port, _key in self.bfrt.tables.port.entry_get_iterator(None):
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
            ports[dev_port] = {
                'description': '',
                'speed': port['$SPEED'],
                'mtu': port['$RX_MTU'],
                'fec': port['$FEC'],
                'shutdown': not port['$PORT_ENABLE']
            }
        return ports

    def is_tf1(self):
        return 'T10' in self.cfg['sku']

    def is_tf2(self):
        return 'T20' in self.cfg['sku']

    def get_dev_port(self, port):
        try:
            port = self.ports_name2dev[port]
        except:
            raise Exception(f'invalid port {port}')
        return port

    def get_port_name(self, dev_port):
        if dev_port in self.ports_dev2name:
            return self.ports_dev2name[dev_port]
        else:
            return str(dev_port)
