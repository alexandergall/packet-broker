import os
import sys
import re

SDE = os.environ.get('SDE')
SDE_INSTALL = os.environ.get('SDE_INSTALL', SDE + '/install')
BF_RUNTIME_LIB = SDE_INSTALL + '/lib/python2.7/site-packages/tofino/'
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
        './', BF_RUNTIME_LIB))
import bfrt_grpc.client as gc

class Table:
    def __init__(self, bfrt, name, loc):
        self.bfrt = bfrt
        self.name = name
        self.loc = loc
        self.table = bfrt.info.table_get(loc)
        ## Not used in the code. This dict contains the TableInfo
        ## object for the table. It can be used to inspect the
        ## properties, e.g. to find the names of all valid actions:
        ## self.table_info.action_name_list_get()
        self.table_info = bfrt.info.parsed_info.table_info_dict[loc]

    def _mk_key(self, keys):
        if keys is not None:
            return [ self.table.make_key(
                map(lambda key: gc.KeyTuple(**key), keys)) ]
        else:
            return None

    def _mk_data_tuple(self, data):
        return map(lambda elt: gc.DataTuple(**elt), data)

    def _mk_action(self, name, data):
        if name is not None:
            return self.table.make_data(
                self._mk_data_tuple(data),
                name)
        else:
            return self.table.make_data(
                self._mk_data_tuple(data))

    ### For debugging
    def dump(self):
        from pprint import pprint
        print("DUMP of table " + self.name)
        for data, key in self.entry_get_iterator(None):
            pprint(key.to_dict())
            pprint(data.to_dict())
        print("DUMP END")

    def clear(self):
        self.table.entry_del(self.bfrt.target, None)

    ### Look up a single key. Return the data dictionary of the
    ### result or None if no entries match.
    def entry_get(self, keys, data_fields = [], from_hw = False):
        resp = self.entry_get_iterator(keys, data_fields, from_hw)
        try:
            data = next(resp)[0].to_dict()
        except:
            return None
        return  data

    ### Like entry_get(), but just return the iterable object of
    ### results.
    def entry_get_iterator(self, keys, data_fields = [], from_hw = False):
        return self.table.entry_get(self.bfrt.target,
                                    self._mk_key(keys),
                                    { "from_hw": from_hw },
                                    self.table.make_data(
                                        self._mk_data_tuple(data_fields)))

    def entry_add(self, keys, action_name, action_data = []):
        self.table.entry_add(self.bfrt.target,
                             self._mk_key(keys),
                             [ self._mk_action(action_name, action_data) ])

    def entry_del(self, keys):
        self.table.entry_del(self.bfrt.target, self._mk_key(keys))

    def entry_mod(self, keys, action_name, action_data = []):
        self.table.entry_mod(self.bfrt.target,
                             self._mk_key(keys),
                             [ self._mk_action(action_name, action_data) ])

    def default_entry_set(self, action_name, action_data = []):
        self.table.default_entry_set(self.bfrt.target,
                                     self._mk_action(action_name, action_data))

    def default_entry_reset(self):
        self.table.default_entry_reset(self.bfrt.target)

class Bfrt:
    def __init__(self, program, retries, addr = 'localhost:50052',
                 client_id = 0, device_id = 0, is_master = True):
        ## Due to a bug in client.py, the num_tries parameter is currently
        ## fixed at 5.
        re_retries = int((retries-1)/5) + 1
        for i in range (0, re_retries):
            try:
                self.intf = gc.ClientInterface(addr, client_id = client_id,
                                               num_tries=retries, device_id = device_id,
                                               is_master = is_master)
            except:
                if i < re_retries - 1:
                    continue
                else:
                    raise Exception("connection attempts exceeded")
            else:
                break
        self.intf.bind_pipeline_config(program)
        self.target = gc.Target(device_id = device_id, pipe_id = 0xffff)
        self.info = self.intf.bfrt_info_get()

    ## Pseudo class to let us refer to tables via
    ## attributes
    class Tables:
        pass

    def register_table(self, name, loc):
        setattr(self.Tables, name, Table(self, name, loc))
