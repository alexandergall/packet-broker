install: /etc/packet-broker/schema.json /etc/snmp/snmpd.conf /etc/snmp/interface.conf
	cd init.d && $(MAKE) install

remove:
	cd init.d && $(MAKE) remove

/etc/packet-broker/schema.json: schema.json
	mkdir -p $$(dirname $@)
	cp $< $@

/etc/snmp/snmpd.conf: snmpd.conf
	cp $< $@

/etc/snmp/interface.conf: interface.conf
	cp $< $@
