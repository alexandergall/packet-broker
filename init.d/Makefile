.DEFAULT_GOAL: install

install: /etc/init.d/packet-broker /etc/init.d/packet-broker-configure

/etc/init.d/packet-broker: packet-broker
	cp $< $@
	update-rc.d $< defaults

/etc/init.d/packet-broker-configure: packet-broker-configure
	cp $< $@
	update-rc.d $< defaults

remove:
	update-rc.d packet-broker-configure remove
	rm /etc/init.d/packet-broker-configure
	update-rc.d packet-broker remove
	rm /etc/init.d/packet-broker
