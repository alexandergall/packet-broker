import setuptools
import sys

setuptools.setup(
    name="packet-broker-configd",
    version="0.0.1",
    scripts = [ "configd.py", "brokerctl" ],
    py_modules = [ "packet_broker",
                   "bfrt", "mib" ],
    install_requires = [
        "jsonschema"
    ] + [ module for module in  [ "ipaddress" ]
          if sys.version_info < (3, 0) ]
)
