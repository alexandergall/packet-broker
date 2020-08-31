import setuptools

setuptools.setup(
    name="packet-broker-configd",
    version="0.0.1",
    py_scripts = [ "configd.py", "brokerctl" ],
    py_modules = [ "packet_broker.py",
                   "bfrt.py", "mib.py" ]
)
                  
