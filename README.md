# packet-broker

A P4 program that provides "packet broker" functionality on a
Tofino-based system.  Access to the Barefoot SDE is required for
compiling and running the P4 program contained in this repository.
The SDE is provided by Intel (who acquired Barefoot Networks in 2019).
Currently, this requires going through an application process and
entering an NDA with Intel.

Contents

   * [Overview](#overview)
   * [Port Designations on Tofino Platforms](#tofino-ports)
   * [Architecture](#architecture)
   * [Building](#building)
   * [Running](#running)
   * [Header Parsing](#header-parsing)
   * [Configuration](#configuration)
   * [Interacting with the Control Plane with `brokerctl`](#brokerctl)

## <a name="overview"></a>Overview

The main purpose of the broker is to aggregate traffic from a set of
ingress ports to a group of egress ports.  The traffic is distributed
to the members of the egress port group based on its flow signature,
mapping all packets that belong to the same flow to the same port.

The definition of a flow depends on the type of packet.  For a IPv4 or
IPv6 packet (Ethertype `0x0800` and `0x86dd`, respectively), the basic
flow signature is composed of the source and destination IPv4/IPv6
addresses as well as the protocol identifier (the _IP protocol_ and
_next-header_ fields for IPv4 and IPv6, respectively).  If the
protocol is UDP or TCP, the source and destination ports are part of
the flow as well.

For non IPv4/IPv6 packets, the flow signature is composed of the
Ethernet source and destination addresses as well as the Ethertype
field.

The identity of the port on which a particular packet was received is
lost during the aggregation process.  The broker uses VLAN tags to
preserve this information as follows.

   * Untagged packets

     A VLAN header is inserted into the packet with a given VLAN
     ID. This action is called _push_.

   * Tagged packets

     The VLAN ID is replaced with a given value. This action is called
     _rewrite_.

In the current implementation, this functionality is mandatory. Every
ingress port must specify how VLAN tags are rewritten and/or pushed to
packets arriving on that port. Accordingly, all packets leaving the
broker contain a VLAN tag, i.e. each egress port group is effectively
a VLAN trunk.

In addition, the broker can optionally rewrite MAC source and
destination addresses for VLANs (addresses of untagged packets cannot
be rewritten) and drop incoming packets based on source IPv4/IPv6
addresses.  The latter functionality is referred to as a
_source-filter_.

Packets which do not match any of the VLAN actions (i.e. push
or rewrite) defined for the ingress port are dropped.  Instead of
actually dropping the packets, they can optionally be sent to a
specified port instead.  This feature is called _deflect-on-drop_.

Finally, the broker also provides the ability to create copies of
packets that match a specific flow pattern and send them to an
arbitrary port for inspection.  The mirroring takes place before the
packets are modified by any action described above as well as before
any of the source filters are applied.


## <a name="tofino-ports"></a>Port Designations on Tofino Platforms

The first-generation Tofino ASIC has 256 10/25G SerDes Lanes, grouped
into 64 ports with 4 lanes each. It has an additional port, referred
to as _CPU Eth_, which also supports 1G operation on each lane as well
as a PCIe interface, referred to as _CPU PCIe_, consisting of 4 Gen3
lanes.  The main purpose of the latter two ports is to exchange
packets with the host CPU, hence their names.

The ASIC has 4 packet-processing pipelines, numbered from 0 to 3, each
of which has 16 ports hardwired to it.  Each SerDes line is uniquely
identified by its _device id_ (also referred to as physical id in this
document). This ID is a 9-bit number whose two most-significant bits
denote the number of the pipe to which the lane is connected.  The
lower 7 bits denote the number of the SerDes lane within the pipe
starting with 0, i.e. the lanes on pipe 0 have device ids 0 through
63, those on pipe 1 have ids 128 through 191 etc.

The four lanes of the CPU Eth port are associated with pipe 0 and have
the device ids 64-67.

The CPU PCIe port is special in the sense that its device id depends
on whether the ASIC is used in a 4 pipe or a 2 pipe configuration.  In
the former, the port's id is 320 while in the latter it is 192.

How many of the pipelines are used and which of the ports are exposed
on the front plate of the chassis as physical connectors depends on
the device type.  Examples for such devices are the WEDGE100BF-64X and
WEDGE100BF-32X from Edgecore Networks.

The WEDGE100BF-64X uses all four pipes and exposes 64 QSFP ports for
all regular 256 SerDes Lanes.  On that model, the CPU Eth port is
exposed as an additional QSFP port on the front panel as well.

The WEDGE100BF-32X uses two pipes and exposes 32 QSFP ports on the
front panel.

The QSFP ports are numbered 1-65 and 1-32 on the 64X and the 32X,
respectively (port 65 on the 64X is the CPU Eth port).  Instead of
using device ids, the physical lanes within these ports are addressed
by specifying the port and lane number separated by a slash, where the
lane number ranges from 0 to 3.  For example, `2/3` refers to the
fourth lane in QSFP port 2.

This is also the notation used in the configuration file of the packet
broker wherever a QSFP ports needs to be referenced.

On the 32X, the CPU Eth port is not wired to the front panel as on the
64X.  Instead, two of its lanes are connected to a dual-port 10G Intel
NIC on the main board (note that it may be necessary to enable these
ports in the BIOS before they become available).  The port itself can
be addressed like one of the physical Ports with port id 33.  Once the
system has booted, there will be two 10G ports available as devices
`enp4s0f0` and `enp4s0f1`. The association with the ports on the ASIC
is as follows

   * 33/0 -> `enp4s0f1`
   * 33/2 -> `enp4s0f0`

They can be used like any other port in the packet broker
configuration.

In contrast to this, the CPU PCIe port can only be referred to by its
device id (320 or 192, see above).

## <a name="architecture"></a>Architecture

The P4 program provides the _data plane_ for the packet broker,
i.e. it applies the algorithm specified in the program to packets
entering the device.  An additional component called _control plane_
is needed to populate the tables that drive the match-action-units in
the processing pipelines according to a high-level configuration by
the user.

### Data Plane

The data plane consists of a process called `bf_switchd`, which takes
the artifacts of the P4 program produced by the compiler and loads
them onto the ASIC.  Apart from that, it provides two additional
services.  One is to listen to connections on a TCP port to
communicate with the control plane using gRPC. The other is to provide
a CLI (called `bfshell`) to interact with the various components of
the ASIC, e.g. to show the status of ports or information about QSFP
plugins.

The P4 compiler as well as the `bf_switchd` and `bfshell` programs are
part of the Barefoot SDE and are not provided by this repository.

### Control Plane

When the P4 program is launched by `bf_switchd`, it doesn't do
anything yet, because all match-action tables are empty and all ports
are physically shut down.

The task of the control plane is to take a configuration file and
translate it into instructions to manipulate ports and match-action
tables. These instructions are then sent to `bf_switchd` for execution
through an interface based on gRPC.  In addition to that, the control
plane also queries `bf_switchd` for information about the current
state of the device either from a request issued by a user or
periodically to update interface statistics in a SNMP MIB.

The control plane of the packet broker consists of a daemon called
`configd`, which is running permanently, and a program called
`brokerctl` which is used by the operator to interact with the daemon.

## <a name="building"></a>Building

### Data Plane

To compile `packet_broker.p4`, download, build and install the
Barefoot SDE according to the documentation.  The program has been
tested with versions 9.1.1, 9.2.0 and 9.3.0 of the SDE. Unfortunately,
it is not possible to publish any details about this process here due
to the NDA.

In the remainder of this documentation it is assumed that the
environment variables `SDE` and `SDE_INSTALL` are set correctly
according to the SDE documentation.

After a successful compilation, the build artifacts are stored in
`$SDE/install`.

### Control Plane

The control plane consists of a collection of Python scripts and
modules in the `control-plane` sub-directory of this repository. A
standard `setup.py` file is supplied for installation with
`setuptools`.  Dependencies on non-standard modules are declared in
`setup.py` but there is also an implicit dependence on Python modules
supplied by the SDE, which is covered below.  This dependency
currently forces the control plane to use Python version 2.7.

Assuming that `pip` and `virtualenv` are available, the following
procedure should successfully install the control plane in a Python
virtual environment

```
$ cd control-plane
$ virtualenv /usr/local/packet-broker
$ source /usr/local/packet-broker/bin/activate
$ pip install .
```

## <a name="running"></a>Running

### Data Plane

The `bf_switchd` process requires the kernel module `bf_kpkt` to be
loaded.  This module also makes the CPU PCIe port available as a
regular Linux network interface called `/dev/bf_pci0` (unless it is
being renamed by `udev`).  The module can be loaded with

```
$ sudo $SDE_INSTALL/bin/bf_kpkt_mod_load
```

The `packet_broker` P4 program is run with

```
$ sudo $SDE_INSTALL/bin/run_switchd.sh -p packet_broker
```

### Control Plane

The control plane daemon needs to be able to access the run time Python
modules from the SDE, which can be arranged with

```
$ source /usr/local/packet-broker/bin/activate
$ export PYTHONPATH=$SDE_INSTALL/lib/python2.7/site-packages/tofino
$ /usr/local/packet-broker/bin/configd.py
```

The following options are available

   * `--config-dir <dir>`

     Path of the directory containing configuration and schema files,
     default `/etc/packet-broker`

   * `--ifmibs-dir <dir>`

     Path of the directory where shared memory regions for interface
     MIBs are created, default `/var/run/packet-broker`. This
     directory must exist when `configd.py` is started.

   * `--stats-update-interval <number>`

     Interval in seconds, at which the interface statistics in the
     ifTable MIB are synchronized with the hardware, default 5

   * `--connect-retries <number>`

     The number of retries the gRPC client attempts to connect to the
     server at one-second intervals, default 30

   * `--listen-on <address>`

     The local addresses to listen on for communication with the
     `brokerctl` command, default is to listen on all local addresses

   * `--port <number>`

     The port to use for communication with the `brokerctl` command,
     default 7000


### SNMP Support

The `configd.py` process generates shared memory segments which are
compatible with [an implementation of a SNMP
subagent](https://github.com/alexandergall/snabb-snmp-subagent), which
uses the AgentX protocol to interface with a SNMP daemon to provide
the `ifTable` and `ifXTable` MIBs for the interfaces managed by the
packet broker. Details TBD.

## <a name="header-parsing"></a>Header Parsing

The packet broker classifies packets received on ingress according to
the [P4
parser](https://github.com/alexandergall/packet-broker/blob/master/include/parser.p4). To
summarize:

   * IPv4 and IPv6 in untagged or single-tagged packets with Ethertype
     0x8100. Packets with two or more VLAN tags are treated as non-IP
     packets.
   * Arbitrary IPv4 options are detected and skipped.
   * Only fragmentation headers are recognized and parsed for IPv6 and
     only if they are the first extension header after the base
     header. The presence of any other extension headers results in
     TCP/UDP ports to not be available for hash calculations when
     forwarding packets to a group of egress ports.
   * Non-initial fragments are recognized for IPv4 and IPv6.

## <a name="configuration"></a>Configuration

The packet broker is configured from a file called `config.json`
located in the directory specified with the `--config-dir` option of
`configd.py`.  By default, this is `/etc/packet-broker/config.json`.
The file must contain a valid JSON expression which validates against
the schema provided in `control-plane/schema.json`.  The schema file
itself must be present in the configuration directory,
e.g. `/etc/packet-broker/schema.json`.

The overall structure is the following

```
{
  "ports": {
    "ingress": {
    },
    "egress": {
    },
    "other": {
    }
  },
  "source-filter": [
  ],
  "flow-mirror": [
  ],
  "features": {
  }
}
```

Each of these blocks is described in detail in the following sections.

### Ports

The `ports` section defines which ports should be used by the packet
broker.  The ports are split into three functional groups `ingress`,
`egress` and `other` as described below.  The ports in all of the
groups share the following basic configuration

```
"<port>/<lane>": {
  "config": {
    "description": <description>,
    "speed": <speed>,
    "fec": <fec>,
    "mtu": <mtu>,
    "shutdown": true | false
  }
}
```

The interface is identified by its `<port>` and `<lane>` in the
slash-notation introduced above.  The `<port>` corresponds to the
labeling of the QSFP ports on the front panel of the device and
`<lane>` ranges from 0 to 3, e.g. `1/0` refers to lane 0 on QSFP port
1.

   * `description`, **optional**, default is an empty string

     An arbitrary string that identifies the purpose of the
     interface. This string will also appear as the `ifAlias` object
     of the row representing the interface in the `ifXTable` if the
     SNMP functionality is enabled.

   * `speed`, **mandatory**

     The bit rate at which to run the SerDes lane, must be one of

       * `BF_SPEED_1G`
       * `BF_SPEED_10G`
       * `BF_SPEED_25G`
       * `BF_SPEED_40G`
       * `BF_SPEED_40G_NB`
       * `BF_SPEED_40G_NON_BREAKABLE`
       * `BF_SPEED_50G`
       * `BF_SPEED_100G`

    Note that certain restrictions exist as to which lanes these
    setting can be applied to.  The most important restrictions are

       * `BF_SPEED_40G` and `BF_SPEED_100G` can only be applied to lane 0
       * `BF_SPEED_50G` can only be applied to lanes 0 and 2

   * `fec`, **optional**, default is `BF_FEC_TYP_NONE`

     The FEC algorithm to use, one of

        * `BF_FEC_TYP_NONE` to disable FEC
        * `BF_FEC_TYP_FC` to select the Fire code FEC
        * `BF_FEC_TYP_RS` to select the Reed Solomon FEC

   * `mtu`, **mandatory**

     The MTU, including all packet headers. Must be in the range 1200
     to 10240.

   * `shutdown`, **optional**, default is `false`

     A boolean (`true` or `false`) that determines the operational
     state of the interface.

#### Ingress

The `ingress` section is mandatory.  It contains a list of interfaces
on which the packet broker expects packets to arrive for processing.
Apart from the basic port configuration, each port requires additional
options that define the behavior with respect to VLAN tagging and MAC
rewriting as follows

```
"<port>/<lane>": {
  "config": {
  },
  "egress-group": <number>,
  "vlans": {
    "push": <vlanID>,
    "rewrite": [
    ]
  }
}
```

The `egress-group` field is mandatory and must reference a group of
ports defined in the `egress` section.  All packets arriving on this
port that pass the criteria set by the rules in the `vlans` section as
described below will be forwarded to one of the members of this port
group according to their flow signature.

The `push` and `rewrite` sections are both optional, but specifying
neither of them results in all packets being dropped.

If `push` is specified, a 802.1Q header (Ethertype `0x8100`) is added to
all untagged packets with the VLAN ID set to `<vlanID>` and all other
fields (`PCP`, `DEI`) set to zero.  It has no effect on packets that
already have a 802.1Q header.

The `rewrite` section, if specified, only applies to packets with a
802.1Q header. It has no effect on untagged packets.  This section
must contain a list of objects of the form

```
{
  "in": <vlanIDin>,
  "out": <vlanIDout>
  "mac-rewrite": {
    "src": {
      "<orig-mac>": "<new-mac>",
      ...
    },
    "dst": {
      "<orig-mac>": "<new-mac>",
      ...
    }
  }
}
```

The `in` and `out` fields are mandatory and have the following effect.
A packet whose VLAN ID matches `<vlanIDin>` is accepted and its VLAN
ID is replaced with `<vlanIDout>`.

The `mac-rewrite` section is optional.  If present, it rewrites source
and/or destination MAC addresses as specified by the `src` and `dst`
lists, respectively, for packets whose VLAN ID matches `<vlanIDin>`.
Addresses that do not appear as `<orig-mac>` in any of the `src` or
`dst` sections, remain unchanged.

Consider the following example

```
"vlans": {
  "rewrite": [
      { "in": 600,
        "out": 207
      },
      { "in": 333,
        "out": 211,
        "mac-rewrite": {
            "src": {
                "ac:4b:c8:40:e2:b9": "02:00:00:00:00:01"
            }
        }
      }
  ]
}
```

This will replace VLAN ID 600 by 207 without rewriting any addresses
in VLAN 600. It will also replace VLAN ID 333 by VLAN ID 211 and
replace all occurences of `ac:4b:c8:40:e2:b9` as the MAC source
address of packets with VLAN ID 333 with `02:00:00:00:00:01`.

All tagged packets whose VLAN ID doesn't match any of the `in` fields
are dropped.  To accept all packets for a VLAN without changing the
VLAN ID, an explicit `rewrite` clause must be present with
`<vlanIDout>` set to `<vlanIDin>`, e.g.

```
"vlans": }
  "rewrite": [
    {
      "in": 600,
      "out": 600
    }
  ]
}
```

#### Egress

The `egress` section is mandatory. It defines groups of interfaces to
which packets arriving on ingress interfaces can be sent to.

```
"egress": {
  "group-id": <number>,
  "members": {
  }
}
```

The `group-id` field is mandatory and must specify an integer by which
the group can be uniquely identified by the `egress-group` field of
ports defined in the `ingress` port section.

The `members` field is mandatory and must contain at least one
standard port definition.

#### Other

The `other` ports section is optional and contains only standard port
definition clauses.  These ports can be used as egress ports for the
`flow-mirror` and `deflect-on-drop` features.

### Source Filter

The `source-filter` section is optional. It contains a list of strings
which must represent valid IPv4 or IPv6 prefixes, for example

```
"source-filter": [
  "192.168.1.0/24",
  "2001:db8::/64"
]
```

The list is applied to all IPv4 and IPv6 packets (tagged or untagged)
received on any of the ingress ports.  All packets whose source IPv4
or IPv6 address match any of the prefixes specified in this list are
dropped.

### Flow Mirror

The `flow-mirror` section is optional.  It contains a list of flow
patterns for the purpose of packet mirroring. A copy of every packet
arriving on any of the ingress interfaces or a subset thereof which
matches any of the flow patterns in this list is sent to the port
specified in the `flow-mirror` section of the `features` section.

A flow pattern is defined as follows

```
{
  "ingress-ports": [ <port>, ... ],
  "non-ip": true|false,
  "src": <srcPrefix>,
  "dst": <dstPrefix>,
  "src_port": { "port": <src-port>, "mask": <src-mask> },
  "dst_port": { "port": <dst-port>, "mask": <dst-mask> },
  "bidir": true|false,
  "enable": true|false
}
```

The `ingress-ports` list is optional. If omitted, the mirroring rules
are applied to all ingress ports. Otherwise, the rules are only
applied to the ports in the list.

If the optional property `non-ip` is present and set to `true`, all
packets that are neither IPv4 (Ethertype `0x0800`) or IPv6 (Ethertype
`0x86dd`) are mirrored and all match fields are ignored.

If `non-ip` is omitted or set to `false`, the fields `src`, `dst`,
`src_port`, and `dst_port` must be present and determine which packets
are selected for mirroring.  The fields `bidir` and `enable` are
optional.  Ternary matches are used when comparing the patterns with
the corresponding fields in the packets arriving on the ingress ports.
This means that each pattern consists of a value and a mask, where the
mask is as wide as the value in terms of the number of bits.  Only
those bits whose corresponding bit in the mask is equal to 1 are
relevant. All bits in the value whose corresponding bit in the mask is
0 are ignored. A mask value of 0 effectively ignores the entire field.

The `src` and `dst` field must use standard prefix notation, e.g.
`"192.168.10.0/24"` or `"2001:db8:1::/64"`.  The mask is derived from
the prefix length.  The prefixes in both fields must belong to the
same address family (IPv4 or IPv6).

The `src_port` and `dst_port` fields match UDP or TCP port numbers,
which must be in the range from 0 to 65535.  The mask must be
specified explicitly as a decimal number in the same range.

If the `bidir` field is set to `true`, an additional flow pattern is
automatically generated with all source and destination fields
reversed.  The default is `false`.

If the `enable` field is set to `false`, the flow pattern is not
programmed into the hardware and is thus effectively ignored.  The
default is `true`.

### Features

This section is used to configure features that are not directly
associated with specific ports.  It is optional with default values
given below.  The basic structure is as follows

```
"features": {
  "deflect-on-drop": <port-spec>,
  "flow-mirror": {
    "port": <port-spec>,
    "max-packet-length": <packet-length>
  },
  "drop-non-initial-fragments": true | false,
  "exclude-ports-from-hash": true | false,
  "drop-non-ip": true | false
}
```

If the `deflect-on-drop` feature is configured, all packets that are
marked to be dropped are forwarded to the specified port instead.  The
port can be specified either as a string of the form `"<port>/<lane>"`
just as in the `ports` section or as a number representing the
[physical port id](#tofino-ports). The latter is really only needed to
select the CPU PCIe ports, which are the only ports that do not have a
representation as a `<port>/<lane>` pair (they are identified by 192
and 320 for the 32X and 64X platforms, respectively).

A packet is marked to be dropped if any of the following conditions
are met

   * The packet is untagged but the ingress port doesn't have a `push`
     directive
   * The packet is tagged but the ingress port either doesn't have a
     `rewrite` section or the VLAN ID does not match any of the `"in"`
     fields
   * The packet is an IPv4 or IPv6 packet and belongs to any of the
     prefixes specified in the `source-filter` section
   * The packet is a non-initial fragment of a fragmented IPv4 or IPv6
     packet and the `drop-non-initial-fragments` feature is enabled
   * The packet is neither a IPv4 or IPv6 packet (Ethertypes 0x0800 or
     0x86dd either tagged or untagged) and the `drop-non-ip` feature
     is enabled
   * The P4 parser is unable to parse the packet headers (e.g. if the
     header is truncated)

The `deflect-on-drop` feature is disabled by default.

The `flow-mirror` section sets parameters common to all flow mirror
rules.  The `port` field specifies the destination port for mirrored
packets and it accepts both logical and physical port ids like the
`defelect-on-drop` field.  If the `port` field is omitted, flow
mirroring is effectively disabled, which is the default.  Note that
the Tofino architecture mandates that the egress port for mirrored
packets must be a single port, i.e. hash-based distribution to a group
of ports is not supported.

The `max-packet-length` field is used to limit the size of mirrored
packets to the given number of bytes.  It must be in the range from 0
to 16384.  The default is 16384, i.e. mirrored packets are not
truncated.

If the `drop-non-initial-fragments` feature is enabled, non-initial
fragments of fragmented IPv4 or IPv6 packets are dropped.  A packet is
considered to be a non-initial fragment if the following condition
holds

   * IPv4:  The fragment offset field of the IPv4 header is non-zero
   * IPv6: The IPv6 packet contains a fragmentation header as first
     extension header and the fragment offset field in the header is
     non-zero

The default is to not drop non-initial fragments.

If the `exclude-ports-from-hash` feature is enabled, the TCP/UDP ports
are ignored when calculating the flow-based hash for IPv4 and IPv6
packets.  This is useful if `drop-non-initial-fragments` is disabled
and it is desired that non-initial fragments are mapped to the same
egress port as the initial fragments. The default is to include the
ports in the hash calculation.

If the `drop-non-ip` feature is enabled, all untagged or single-tagged
packets whose Ethertype field is not equal to either 0x0800 (IPv4) or
0x86dd (IPv6) are dropped.  The default is to not drop non-IP packets.

## <a name="brokerctl"></a>Interacting with the Control Plane with `brokerctl`

The `configd.py` process loads its initial configuration from the file
`conifg.json` in the directory specified by the `--config-dir` command
line option, `/etc/packet-broker` by default. It does not check the
configuration file for changes automatically after that.  Any
interaction with the daemon after startup must be performed by the
`brokerctl` command.  Its basic usage is as follows

```
usage: brokerctl [-h] [--port PORT] [--host HOST]
                 {reload,add,remove,dump,show} ...

Packet Broker controller

optional arguments:
  -h, --help            show this help message and exit
  --port PORT
  --host HOST

Available commands:
  {reload,add,remove,dump,show}
    reload              Reload configuration
    add                 Add dynamic table entries
    remove              Remove dynamic table entries
    dump                Dump tables from hardware
    show                Show running configuration
```

`brokerctl` connects to `configd.py` via TCP on port 7000 by
default. It uses a simple JSON encoding to submit a command to the
daemon and receive a completion message or error code from the daemon.
By default, `brokerctl` connects to a daemon listening on `127.0.0.1`
(IPv6 is currently not supported). A different address can be supplied
with the `--host` option to communicate with a daemon running on a
remote host.  There are currently no security mechanisms in place to
secure the connection, thus it is recommended to use a firewall or ACL
for protection.

A command can be sent to multiple daemons simultaneously by specifying
multiple `--host` options.  Hosts can either be specified as literal
IPv4 addresses or domain names which can be resolved to an IPv4
address.

After submitting a command, `brokerctl` waits until it receives a
reply from the daemon and displays it as a pretty-printed JSON object.
The format is as follows

```
{
  "<host1>": {
    "success": true | false,
    "msgs": [],
    "result": {}
  },
  "<host2>": {
    "success": true | false,
    "msgs": [],
    "result": {}
  },
  ...
}

```

The output contains one section for each address for which a `--host`
option was specified when `brokerctl` was invoked.  Each such section
contains an indicator whether the command completed successfully, an
optional list of messages and the result of the command itself.

The messages (if any) are essentially a copy of the log messages
generated by `configd.py` while executing the command.  In most cases,
no messages are generated when a command completes successfully.

A message is of the form

```
{
  "msg": <text>,
  "level": <log-level>
}
```

Here, `<text>` is an arbitrary string set by the daemon and
`<log-level>` is the numerical value of the logging level as used by
the Python `logging` module when the message was created by the
daemon.  In future versions of `brokerctl`, this could be used to feed
the daemon's response directly into another instance of the Python
`logging` module maintained by `brokerctl` itself.

For example:

```
$ brokerctl add source-filter "foo"
INFO:brokerctl: Trying 127.0.0.1
INFO:brokerctl: Connected
{
  "127.0.0.1": {
    "success": false,
    "msgs": [
      {
        "msg": "Command 'add' failed: u'foo' does not appear to be an IPv4 or IPv6 network",
        "level": 40
      }
    ],
    "result": null
  }
}
```

Each of the available commands is documented below.

### `reload`

This command doesn't take any arguments. It notifies `configd.py` to
re-load the configuration file and update the hardware tables
accordingly. Successful completion is indicated by the following
response:

```
{
  "success": true,
  "msgs": [],
  "result": null
}
```

Any syntactic or semantic error in the configuration will result in a
failure (`success` set to `false`) and a message which provides
details about the error (unfortunately, the Python JSON modules tend
to produce hard to understand messages in case of syntax errors and
failures to validate the configuration against the schema).

### `show`

The `show` command is used to display various components of the
currently active configuration. Its usage is

```
usage: brokerctl show [-h]
                      {ingress,features,flow-mirror,source-filter,groups,ports}
                      ...

optional arguments:
  -h, --help            show this help message and exit

  {ingress,features,flow-mirror,source-filter,groups,ports}
                        Show running configuration
    ingress             Ingress processing
    features            Features
    flow-mirror         Flow mirror rules
    source-filter       Source filters
    groups              Port configurations
    ports               Port configurations
```

The output is generated from the daemon's in-memory copy of the
configuration file. For the `flow-mirror` argument, only the entries
with `enable` set to `true` are displayed. The output for
`source-filter` includes the list of filters that have been added with
the `add` command as well.

### `add`

The `add` command is used to modify certain tables in a dynamic manner
(i.e. without modifying the configuration file). Its usage is given by

```

optional arguments:
  -h, --help       show this help message and exit

Available items to add:
  {source-filter}  Add dynamic table entries
    source-filter  Source filters
```

Currently, only source filters can be configured dynamically.  The
`source-filter` sub-command takes an IPv4 or IPv6 prefix as its only
argument, e.g.

```
$ brokerctl add 192.168.0.0/24
INFO:brokerctl: Trying localhost
INFO:brokerctl: Connected
{
  "localhost": {
    "success": true,
    "msgs": [
      {
        "msg": "Added source filter 192.168.0.0/24",
        "level": 20
      }
    ],
    "result": null
  }
}
```

Source filters added this way are persistent across restarts of
`configd.py` by writing them to the file `source_filter_dynamic`
located in the configuration directory, e.g.

```
$ cat /etc/packet-broker/source_filter_dynamic
## Automatically generated file. DO NOT EDIT.
192.168.0.0/24
$
```

Filters added in this manner are displayed by `brokerctl show
source-filter` in a separate table called `source-filter-dynamic`,
e.g.

```
$ brokerctl show source-filter
INFO:brokerctl: Trying localhost
INFO:brokerctl: Connected
{
  "localhost": {
    "success": true,
    "msgs": [],
    "result": {
      "source-filter": [],
      "source-filter-dynamic": []
    }
  }
}
```

### `remove`

The `remove` command removes items that have previously been added
with the `add` command. Its usage is

```
usage: brokerctl remove [-h] {source-filter} ...

optional arguments:
  -h, --help       show this help message and exit

  {source-filter}  Remove dynamic table entries
    source-filter  Source filters
```

For example

```
$ brokerctl remove source-filter 192.168.0.0/24
INFO:brokerctl: Trying localhost
INFO:brokerctl: Connected
{
  "localhost": {
    "success": true,
    "msgs": [
      {
        "msg": "Removed source filter 192.168.0.0/24",
        "level": 20
      }
    ],
    "result": null
  }
}
```

### `dump`

The `dump` command reads the key/data pairs of a given match-action
table from the hardware and displays them.  The names of key and data
fields in the output corresponds to the corresponding names used in
the definition of the table in the P4 source code.  The usage is

```
usage: brokerctl dump [-h]
                      {ingress,select-output,flow-mirror,source-filter,mac-rewrite,forward}
                      ...

optional arguments:
  -h, --help            show this help message and exit

  {ingress,select-output,flow-mirror,source-filter,mac-rewrite,forward}
                        Dump tables from hardware
    ingress             Ingress VLAN push/rewrite rules
    select-output       Ingress port to output group mapping
    flow-mirror         Flow mirror rules
    source-filter       Source filters
    mac-rewrite         Ingress source MAC rewrite rules
    forward             Output group to port mapping
```

An understanding of the source code is necessary to interpret the
result.

Depending on the type of table, the output can contain additional
fields which are maintained directly by the hardware.  For example,
the `source-filter` feature also collects the number of bytes and
packets dropped by a specific rule. For example

```
$ brokerctl dump source-filter
{
  "localhost": {
    "success": true,
    "msgs": [],
    "result": [
      {
        "prefix": "78.128.113.42/32",
        "counters": {
          "packets": 178863020,
          "bytes": 11447427238
        }
      }
    }
  }
}
```
