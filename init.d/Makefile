.DEFAULT_GOAL: install

install: /etc/init.d/packet-broker /etc/init.d/packet-broker-configd \
	/etc/init.d/if-snmp-agent /etc/default/packet-broker

/etc/init.d/packet-broker: packet-broker
	cp $< $@
	update-rc.d $< defaults

/etc/init.d/packet-broker-configd: packet-broker-configd
	cp $< $@
	update-rc.d $< defaults

/etc/init.d/if-snmp-agent: if-snmp-agent
	cp $< $@
	update-rc.d $< defaults

/etc/default/packet-broker: default
	cp $< $@

remove:
	update-rc.d packet-broker-configd remove
	rm /etc/init.d/packet-broker-configd
	update-rc.d packet-broker remove
	rm /etc/init.d/packet-broker
	update-rc.d if-snmp-agent remove
	rm /etc/init.d/if-snmp-agent
	rm /etc/default/packet-broker
