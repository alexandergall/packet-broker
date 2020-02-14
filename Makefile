/etc/packet-broker/schema.json: schema.json
	mkdir -p $$(dirname $@)
	cp $< $@
