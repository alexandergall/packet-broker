import logging
import json
from device import Device
from configuration import Config, ConfigItem, ConfigSourceFilter, ConfigFlowMirrorAdd, ConfigFlowMirrorRm
from program_tables import tables, field_annotations

logger = logging.getLogger(__name__)

class MessageBuffer:
    def __init__(self):
        self.clear()

    def clear(self):
        self.msgs = []

    def add(self, msg, logger, level = logging.INFO):
        self.msgs.append({
            'level': level,
            'msg': msg
        })
        if logger is not None:
            logger.log(level, msg)

    def info(self, msg, logger):
        self.add(msg, logger)

    def warning(self, msg, logger):
        self.add(msg, logger, level = logging.WARNING)

    def error(self, msg, logger):
        self.add(msg, logger, level = logging.ERROR)

class PacketBroker:
    def __init__(self, args, bfrt):
        self.bfrt = bfrt
        self.args = args
        self.dev = Device(bfrt, args)
        self.mb = MessageBuffer()
        self.cmd_dispatch = {
            'reload': self._cmd_reload,
            'show': self._cmd_show,
            'dump': self._cmd_dump,
            'add': self._cmd_add_remove,
            'remove': self._cmd_add_remove
        }

        ## Set base directory for JSON schemata in the base class of
        ## partial configurations
        ConfigItem.schema_dir(args.config_dir + "/schema")
        
        for name, loc in tables.items():
            bfrt.add_table(name, loc, field_annotations.get(name, {}))

        ## Initial empty configuration
        self.config = Config(bfrt, self.dev)

    def update_stats(self):
        self.config.state.update_stats()

    def handle_request(self, peer, req):
        self.mb.clear()
        result = None

        command = req['commands'][0]
        handler = self.cmd_dispatch.get(command, None)
        if handler is None:
            self.mb.error(f"Invalid command '{command}' from {peer[0]}", logger)
            success = False
        else:
            try:
                result = handler(req, peer[0])
                success = True
            except Exception as e:
                self.mb.error(f"Command '{command}' failed: {e}", logger)
                success = False

        return {
            'success': success,
            'msgs': self.mb.msgs,
            'result': result
        }

    def _rollback(self):
        ## Only empty for the initial configuration
        if self.config.config_in:
            self.mb.warning("Reverting to the previously active configuration.",
                            logger)
            try:
                self.config.apply()
            except Exception as e:
                self.mb.error(f"Application of previous configuration failed: {e}", logger)
                raise Exception("The hardware is in an undefined state")
            self.mb.warning("The running and stored configurations have diverged.",
                            logger)
        else:
            raise Exception("Invalid initial configuration")

    def _activate(self, config, apply_method='apply'):
        try:
            config.validate()
        except Exception as e:
            raise Exception(f"Error validating configuration: {e}")

        try:
            config.parse()
        except Exception as e:
            raise Exception(f"Error parsing configuration: {e}")

        try:
            config.apply(apply_method)
        except Exception as e:
            self.mb.warning("An unexpected error occured during the application "
                            + f"of the new configuration: {e}", logger)
            self._rollback()
        else:
            ## Commit new configuration
            self.config = config

    def _cmd_reload(self, req, peer):
        logger.info(f"Reload requested by {peer}")
        ## Tentative new configuration
        try:
            config = Config(self.bfrt, self.dev,
                            config_path=self.args.config_dir + "/config.json",
                            prev_config=self.config)
        except Exception as e:
            raise Exception(f"Error loading configuration: {e}")
        self._activate(config)
        return None

    def _cmd_show(self, req, peer):
        items = {
            'top-level': [],
            'system': [ 'system' ],
            'ports': [ 'ports' ],
            'source-filter': [ 'source-filter' ],
            'monitor-sessions': [ 'monitor-sessions' ],
            'flow-mirror': [ 'flow-mirror' ],
            'features': [ 'features' ]
        }
        item = req['commands'][1]
        return {
            item: self.config.sub_config(items[item],
                                         processed=req['args']['processed'])
        }

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

        cmd_tables = {
            'source-filter': [ 'filter_ipv4', 'filter_ipv6' ],
            'monitor-sessions': [ 'mirror_encap_l2', 'mirror_encap_l3', 'mirror_encap_l4' ],
            'flow-mirror': [ 'mirror_ipv4', 'mirror_ipv6' ],
            'ingress': [ 'ingress_tagged', 'ingress_untagged' ],
            'mac-rewrite': [ 'ingress_src_mac_rewrite', 'ingress_dst_mac_rewrite' ],
            'select-output': [ 'select_output' ],
            'forward': [ 'forward']
        }

        funcs = {
            'filter_ipv4': filter,
            'filter_ipv6': filter,
            'mirror_ipv4': mirror,
            'mirror_ipv6': mirror
        }

        result = []
        tables = cmd_tables[req['commands'][1]]
        for name in tables:
            for data, key in (getattr(self.bfrt.tables, name).
                              entry_get_iterator([], from_hw = True)):
                func = funcs.get(name, default)
                func(key.to_dict(), data.to_dict(), result)
        return result

    def _cmd_add_remove(self, req, peer):
        mode, item = req['commands']
        logger.info(f"{mode} {item} requested by {peer}")
        if mode == "add":
            config_items = {
                'source-filter': ConfigSourceFilter,
                'flow-mirror': ConfigFlowMirrorAdd
            }
        else:
            config_items = {
                'source-filter': ConfigSourceFilter,
                'flow-mirror': ConfigFlowMirrorRm
            }

        dyn_override = {}
        dyn_override[item] = (mode, config_items[item](json.loads(req['args']),
                                                       validate=True))
        config = Config(self.bfrt, self.dev, prev_config=self.config,
                        dyn_override=dyn_override)
        apply_method = {
            'source-filter': 'apply_source_filter',
            'flow-mirror': 'apply_flow_mirror'
        }[item]
        self._activate(config, apply_method)
        return None
