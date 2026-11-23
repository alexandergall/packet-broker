import os
import sys
import re
import inspect

import bfrt_grpc.client as gc

class Tables:
    def __init__(self):
        self.names = []

    def add(self, table):
        assert table.name not in self.names
        self.names.append(table.name)
        setattr(self, table.name, table)

class Table:
    def __init__(self, bfrt, name, loc, annotations = {}):
        self.bfrt = bfrt
        self.name = name
        self.loc = loc
        self.table = bfrt.info.table_get(loc)

        for elts in annotations.get('key', []):
            self.table.info.key_field_annotation_add(*elts)
        for elts in annotations.get('data', []):
            self.table.info.data_field_annotation_add(*elts)

        ## table_info is not used in the code. This dict contains the
        ## TableInfo object for the table. It can be used to inspect
        ## the properties, e.g. to find the names of all valid
        ## actions: self.table_info.action_name_list_get()
        ##
        ## The table_info_dict is keyed wih the fully-qualified table
        ## names, where as the table_get() method above also accepts
        ## non-qualified names as long as they are unique. This call
        ## to get the qualified name of a table seems to be
        ## non-public.
        qualified_loc = self.table.info.name_get()
        self.table_info = bfrt.info.parsed_info.table_info_dict[qualified_loc]

    def _mk_key(self, keys):
        if keys is not None:
            return [ self.table.make_key(
                list(map(lambda key: gc.KeyTuple(**key), keys))) ]
        else:
            return None

    def _mk_data_tuple(self, data):
        return list(map(lambda elt: gc.DataTuple(**elt), data))

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

    def default_entry_get(self):
        resp = self.table.default_entry_get(self.bfrt.target)
        try:
            data = next(resp)[0].to_dict()
        except:
            return None
        return data

    def default_entry_set(self, action_name, action_data = []):
        self.table.default_entry_set(self.bfrt.target,
                                     self._mk_action(action_name, action_data))

    def default_entry_reset(self):
        self.table.default_entry_reset(self.bfrt.target)

class Bfrt:
    def __init__(self, program, retries, addr = 'localhost:50052',
                 client_id = 0, device_id = 0):
        ## The connection logic in ClientInterface is buggy and
        ## doesn't work if the server is starting up while in this
        ## call. As a workaround, we set num_retries=1 and perform the
        ## call in a loop
        for i in range(0, retries):
            try:
                self.intf = gc.ClientInterface(addr, client_id = client_id,
                                               num_tries=1,
                                               device_id = device_id)
            except:
                if i == retries-1:
                    raise Exception("connection attempts exceeded")
            else:
                break
        self.intf.bind_pipeline_config(program)
        self.target = gc.Target(device_id = device_id, pipe_id = 0xffff)
        self.info = self.intf.bfrt_info_get()
        self.tables = Tables()

    def add_table(self, name, loc, annotations = {}):
        table = Table(self, name, loc, annotations)
        self.tables.add(table)
        return table
