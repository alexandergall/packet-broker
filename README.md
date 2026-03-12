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

        * The VLAN ID is replaced with a given value. This action is
          called _rewrite_.

        * The VLAN ID is passed on unchanged. This action is called
          _accept_.

In the current implementation, this functionality is mandatory. Every
ingress port must specify how VLAN tags are accepted, rewritten or
pushed to packets arriving on that port. Accordingly, all packets
leaving the broker contain a VLAN tag, i.e. each egress port group is
effectively a VLAN trunk.

In addition, the broker can optionally rewrite MAC source and
destination addresses for VLANs (addresses of untagged packets cannot
be rewritten) and drop incoming packets based on source IPv4/IPv6
addresses.  The latter functionality is referred to as a
_source-filter_.

Packets which do not match any of the VLAN actions (i.e. accept, push
or rewrite) defined for the ingress port are dropped.  Instead of
actually dropping the packets, they can optionally be sent to a
specified port instead.  This feature is called _deflect-on-drop_.

Finally, the broker also provides the ability to create copies of
packets that match a specific flow pattern and send them to an
arbitrary port for inspection.  The mirroring can be applied either on
ingress or egress. The former provides a copy of the unmodified packet
as it arrives on the ingress port. The latter provides a copy of the
packet after processing, i.e. as it appears on the egress port.

## <a name="tofino-ports"></a>Port Designations on Tofino Platforms

### Tofino1

The first generation of the Tofino ASIC has 18 ports, numbered from 0
to 17, on each processing pipe with 4 SerDes lanes each, which is the
reason these ports are also referred to as *quads*. Quads 0 to 15
represent regular ports with SerDes lanes capable of 10/25Gbps and
quad #17 is always dedicated to packet recirculation. The function of
quad #16 depends on whether the ASIC has 2 or 4 pipes (numbered from 0
to 3) and can be one of the following

   * Recirculation port
   * Eth CPU port
   * PCIe CPU port

The Eth CPU port has four MACs capabale of 25/10/5/2.5/1Gbps and is
always located on pipe #0.

The PCIe CPU port has one PCIe link consisting of four Gen3 lanes with
8Gps each. On a 4-pipe ASIC it is located on pipe #2 while on a 2-pipe
ASIC it is located on pipe #1.

On a 4-pipe ASIC, quad #16 is configured as recirculation port on
pipes #1 and #3.

The main purpose of the CPU ports is to exchange packets with
the host CPU, hence their names.

Independent of their purpose, each SerDes line is uniquely identified
by its _device id_ (also referred to as physical id in this
document). This ID is a 9-bit number whose two most-significant bits
denote the number of the pipe to which the lane is connected.  The
lower 7 bits denote the number of the SerDes lane within the pipe
starting with 0, i.e. the lanes on pipe 0 have device ids 0 through
63, those on pipe 1 have ids 128 through 191 etc. The PCIe CPU port is
represented as a single physical id.

### Tofino2

The second generation of Tofino ASICs only comes in a 4-pipe
configuration. Each pipe has 9 groups with 8 SerDes lanes each. Groups
1 to 8 have 8 lanes capable of 50/25/10Gbps. Group #0 on pipes 1 to 3
has 8 recirculation ports. On pipe #0, group #0 has 3 recirculation
ports, 4 Eth CPU (40/25/10/5/2.5/1G) and one PCIe CPU port (4x8Gbps
Gen3 lanes)

The physical ids are assigned as for the Tofino1.

### Named ports

In an actual device, most of the SerDes ports are exposed as regular
network ports equipped with some kind of transciever, typically with
SFP+, QSFP or QSFP-DD form-factors. These ports are also called
"front-panel ports". Apart from their physical id, these lanes can
also be addressed with logical names pertaining to their location on
the front panel. The names are of the form `<connector>/<channel>`,
where `<connector>` enumerates the physical connector and `<channel>`
identifies the lane within that connector. The latter is in the range
from 0 to 3 and 0 to 7 for Tofino1 and Tofino2, respectively.

We refer to these ports as "named ports". For the Tofino SDE, all
ports have a name except for recirculation ports and the PCIe CPU
port, irrespective of the actual layout of a specific device. The
following table lists the assignment for three of the Tofino reference
platforms from Edge-corE networks

| Device    | ASIC         | Pipes | Connectors |Eth CPU Ports      |
|-----------|--------------|-------|------------|-------------------|
| DCS800    | BFN-T10-032D |   2   | 1 - 32     |33/0 33/1/33/2/33/3|
| DCS801    | BFN-T10-032Q |   4   | 1 - 32, 601 - 663 |33/0 33/1 33/2 33/3|
| DCS802    | BFN-T10-064Q |   4   | 1 - 64     |65/0 65/1 65/2 65/4|
| DCS810    | BFN-T20-128Q |   4   | 1 - 32     |33/0 33/1/33/2 33/3|

The Eth CPU ports of the DCS800, DSC801 and DCS810 are wired to 10G
ethernet adapters on the main board (actually, only two of them are
connected and usable) but on the DCS802 they are wired to the
front-plate as an additional 100G QSFP port.

On the DCS801, none of the ports of pipes 1 and 3 are wired to the
front-plate. Instead, they are fixed in a loopback configuration and
not connected to anything, essentially acting as 32 additional
recirculation ports. Nevertheless, they can still be addressed by
names with connector numbers starting with 601 and using only odd
numbers (i.e. 601, 603 etc. up to 663).

###  <a name="namedPorts"></a>Port Naming Conventions used by the Packet Broker

The packet broker configuration only allows named ports with the
exception of the PCIe CPU port, which can be referred to by the name
`PCIeCPU`. Even though the Eth CPU ports have a natural name, the
packet broker replaces them by the names `EthCPU<n>`, where `<n>`
ranges from 0 to 3. These names are the same irrespectve of the
platform while the natural names are not, thus simplifying the
configuration.

In addition, `PCIeCPU` can only be used as egrees port for
flow-mirrors and the `deflect-on-drop` feature (see below).

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
  "system": {
  },
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
  "monitor-sessions": [
  ],
  "flow-mirror": [
  ],
  "features": {
  }
}
```

Each of these blocks is described in detail in the following sections.

### System settings

The `system` section is optional and has the following format

```
"system": {
  "mac-address-pools": {
    "port": {
      "base": "<mac-base-address>",
      "size": <pool-size>
    },
    "system": {
      "base": "<mac-base-address>",
      "size": <pool-size>
    },
  },
  "ip": {
    "addressv4": "<system-ipv4-address>",
    "addressv6": "<system-ipv6-address>"
  }
}
```

The `mac-address-pools` section is optional unless monitor sessions
using the ERSPAN encapsulation exist. If present, it must include the
`port` and `system` subsections. The `port` section defines a
contigous block of MAC addresses which is large enough to assign a
unique address to each SerDes lane of the system. This block of
addresses is assigned by the manufacturer of the device and stored in
some kind of non-volatile memory. The control-plane software
(`bf_switchd` process) can access this information. Ideally, the P4
runtime system would be able to retreive it programmatically, which
would make the manual configuration described here
unnecessary. Unfortunately, this is not the case. However, the UCLI
accessible through the `bfshell` utility provides access to it from
the `bf_pltfm.chss_mgmt` context with the `eeprom_data` command:

```
bf-sde.bf_pltfm.chss_mgmt> eeprom_data
...
Extended MAC Address Size: 260
Extended MAC Base 14:44:8f:be:e4:99
...
```

In this example, the system is a Tofino2 platform from Edgecore
Networks (OUI `14:44:8f`) which provides 260 SerDes lanes (32 regular
ports with 8 lanes each and 4 lanes for Eth CPU ports). The vendor has
assigned 260 addresses from `14:44:8f:be:e4:99` to `14:44:8f:be:e5:9c`
(inclusive).

The `system` MAC address pool is an additional block of MAC addresses
provided by the vendor to be used by the control-plane, e.g. for
software interfaces. The base address and size of this block can be
obtained from the same UCLI context with the `sys_mac_get` command:

```
bf-sde.bf_pltfm.chss_mgmt> sys_mac_get
System Mac addr: 04:f8:f8:78:56:5c
Number of extended addr available 8
```

In this example, both blocks would be configured as

```
"ports": {
  "base": "14:44:8f:be:e4:99",
  "size": 260
},
"system": {
  "base": "04:f8:f8:78:56:5c",
  "size": 8
}
```

The `ip` subsection is optional unless monitor sessions using the
ERSPAN encapsulation exist. If present, it must define one IPv4 and
one IPv6 address assigned to the packet broker application. The
addresses are used as source addresses for monitor sessions that use
the ERSPAN encapsulation.

### Ports

The `ports` section defines which ports should be used by the packet
broker.  The ports are split into three functional groups `ingress`,
`egress` and `other` as described below.  The ports in all of the
groups share the following basic configuration

```
"<port>/<lane>|EthCPU{0,1,2,3}": {
  "config": {
    "description": <description>,
    "speed": <speed>,
    "fec": <fec>,
    "mtu": <mtu>,
    "shutdown": true | false
  }
}
```

The name of the port must be either in the form of `<port>/<lane>` or
name one of the Eth CPU ports. On Tofino1, `<lane>` ranges from 0 to 3
and on Tofino2 from 0 to 7. Note that the PCIe CPU port (named
`PCIeCPU`) can not be configured for any subsection of the `ports`
section.

   * `description`, **optional**, default is an empty string

     An arbitrary string that identifies the purpose of the
     interface. This string will also appear as the `ifAlias` object
     of the row representing the interface in the `ifXTable` if the
     SNMP functionality is enabled.

   * `speed`, **mandatory**

     For Tofino1, the bit rate at which to run the SerDes lane, must be
     one of

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

    In addition to these speeds, Tofino2 supports the following

       * 'BF_SPEED_200G'
       * 'BF_SPEED_400G'
       * 'BF_SPEED_50G_R1'
       * 'BF_SPEED_100G_R2'
       * 'BF_SPEED_200G_R8'

    The identifiers ending with `R<n>` select variants of a speed
    using different numbers of lanes as the standard setting for the
    same speed. E.g. `BF_SPEED_50G` uses two lanes of 25G while
    `BF_SPEED_50G_R1` uses a single lane.

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
    "accept: [
    ],
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

The `push`, `accept` and `rewrite` sections are optional, but
specifying neither of them results in all packets being dropped.

If `push` is specified, a 802.1Q header (Ethertype `0x8100`) is added to
all untagged packets with the VLAN ID set to `<vlanID>` and all other
fields (`PCP`, `DEI`) set to zero.  It has no effect on packets that
already have a 802.1Q header.

The `accept` and `rewrite` sections, if specified, only apply to
packets with a 802.1Q header. They have no effect on untagged packets.

The `accpet` section must contain a list of objects of the form

```
{
  "vid": <vlanID>,
  "mask": <mask>
}
```

The `vid` field is mandatory. The `mask` field is optional and must be
an integer between 0 and 4095 (`0xFFF`) with default value 4095. Only
those bits of `vid` that are set in the mask are considered for a
match in the table (ternary match). I.e. the default mask performs an
exact match on the VLAN tag. The rule

```
{
  "vid": 0,
  "mask": 0
}
```

accepts all tagged packets, irrespective of the VLAN tag.

The `rewrite` section must contain a list of objects of the form

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

The `accept` and `rewrite` actions are implemented by the same P4
table. A table miss results in the packet being marked to be dropped
(or sent to a port if the `deflect-on-drop` feature is enabled).

It is an error to specify an exact-match accept rule and a rewrite
rule for the same VLAN ID. If a wildcard accept rule overlaps with a
rewrite rule, the rewrite rule is ignored.

The `mac-rewrite` section is optional.  If present, it rewrites source
and/or destination MAC addresses as specified by the `src` and `dst`
lists, respectively, for packets whose VLAN ID matches `<vlanIDin>`.
Addresses that do not appear as `<orig-mac>` in any of the `src` or
`dst` sections, remain unchanged.

Consider the following example

```
"vlans": {
  "accept": [
      { "vid": 100 },
      { "vid": 0,
        "mask": 3840
      }
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

This will accept VLAN ID 100 and all VLAN IDs in the range 0-255 and
replace VLAN ID 600 by 207 without rewriting any addresses in VLAN
600. It will also replace VLAN ID 333 by VLAN ID 211 and replace all
occurences of `ac:4b:c8:40:e2:b9` as the MAC source address of packets
with VLAN ID 333 with `02:00:00:00:00:01`.

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

### Monitor Sessions

Monitor sessions are used to set parameters for packets generated by
the `flow-mirror` mechanism. The `monitor-sessions` section is a list
of elements of the form

```
"<session-name>": {
  "encapsulation": {
    "erspan": {
      "session-id": <session-id>,
      "ethernet": {
        "dst": <dst-mac-address>,
        "vlan": <vlan>
      },
      "ip": {
        "dst": "<dst-ip-address>",
        "ttl": <ttl>
      }
    }
  },
  "egress-port": "<port>",
  "max-packet-length": <max-packet-length>
}
```

The `<session-name>` may only contain letters, numbers, hyphens and
underscores. The number of sessions is restricted to 1023 on Tofino1
and 255 on Tofino2.

Each monitor session can be associated with any number of flow mirrors
(up to the number of supported flow rules).

The `encapsulation` section is optional. If omitted, mirrored packets
are emitted without any encapsulation.

Currently, the only supported encapsulation is ERSPAN Type II as
specified in an [informational Internet
draft](https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03). This
encapsulation consists of either a IPv4 or IPv6 header without options
or extension headers (20 or 40 bytes, respectively), a plain GRE
header with sequence number (8 bytes) and an ERSPAN header (8
bytes). Since the packet broker currently doesn't support any L3
functionality, a static Ethernet header is included as well.

The `session-id` element is required. It must be a number in the range
from 0 to 1023, inclusive, and must uniquely identifiy an ERSPAN
session with the same source and destination (see section 4.2 of the
ERSPAN specification). The sequence number carried in the ERSPAN
header is initialized to 0 when a session (identified by the 3-tuple
source, destination, `session-id`) is created and increases
monotonically with every mirrored packet until the session is removed.

The `ethernet` subsection is required. It must specify the MAC address
of the neighbor to which the packet needs to be sent. The `vlan` field
is optional. If present, the specified ID is added to the header as an
802.1Q VLAN tag. The source MAC address is selected automatically from
one of the system's MAC address pools based on the `egress-port`.

The `ip` subsection is required. It must specify either an IPv4 or
IPv6 address. The source address is the adress of matching address
family specified in the `ip` subsection of the `system` section. The
`ttl` field is optional and defaults to 64.

The `egress-port` is mandatory and must be a [named port](#namedPorts)
or `PCIeCPU` to select the PCIe CPU port.

The `max-packet-length` is optional and defaults to 16384. It
specifies the maximum number of bytes to which the mirrored packet
will be truncated. This value is automatically adjusted to the MTU of
the egress interface, taking into account the overhead of the
encapsulation headers.

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
patterns for the purpose of packet mirroring. Each flow is associated
with a monitor session defined in the `monitor-sessions` section. A
copy of every packet arriving on any of the ingress interfaces or a
subset thereof which matches any of the flow patterns in this list is
sent to the port specified in the referenced monitor session.

A flow pattern is defined as follows

```
{
  "monitor-session": <session-name>,
  "ingress-ports": [ <port>, ... ],
  "mirror-mode": "ingress"|"egress",
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

The `mirror-mode` property is optional. It must be either `"ingress"`
or `"egress"`. In ingress mode, the mirrored packet is a copy of the
original packet as it was received by the device. In egress mode, the
mirrored packet is a copy of the packet as it leaves the device,
i.e. containing all the modifications applied by the processing
pipeline. The default value is `"ingress"`.

If the optional property `non-ip` is present and set to `true`, all
packets that are neither IPv4 (Ethertype `0x0800`) or IPv6 (Ethertype
`0x86dd`) are mirrored and all match fields are ignored.

If `non-ip` is omitted or set to `false`, the fields `src`, `dst`,
`src_port`, and `dst_port` determine which packets are selected for
mirroring.  Ternary matches are used when comparing the patterns with
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

Any of the `src`, `dst`, `src_port` and `dst_port` fields can be
omitted and have the following defaults:

   * `src`: `"0.0.0.0/0"`
   * `dst`: `"0.0.0.0/0"`
   * `src_port`: `{ "port": 0, "mask": 0 }`
   * `dst_port`: `{ "port": 0, "mask": 0 }`

If the optional `bidir` field is set to `true`, an additional flow
pattern is automatically generated with all source and destination
fields reversed.  The default is `false`.

If the optional `enable` field is set to `false`, the flow pattern is
not programmed into the hardware and is thus effectively ignored.  The
default is `true`.

### Features

This section is used to configure features that are not directly
associated with specific ports.  It is optional with default values
given below.  The basic structure is as follows

```
"features": {
  "deflect-on-drop": <port-spec>,
  "drop-non-initial-fragments": true | false,
  "exclude-ports-from-hash": true | false,
  "drop-non-ip": true | false
}
```

If the `deflect-on-drop` feature is configured, all packets that are
marked to be dropped are forwarded to the specified port instead.
This must be a [named port](#namedPorts) or `PCIeCPU`.

A packet is marked to be dropped if any of the following conditions
are met

   * The packet is untagged but the ingress port doesn't have a `push`
     directive
   * The packet is tagged but it doesn't match any pattern in the list
     of accepted tags or the ingress port either doesn't have a
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
usage: brokerctl show [-h] {ports,groups,ingress,source-filter,monitor-sessions,flow-mirror,features} ...

options:
  -h, --help            show this help message and exit

  {ports,groups,ingress,source-filter,monitor-sessions,flow-mirror,features}
                        Show running configuration
    ports               Port configurations
    groups              Port configurations
    ingress             Ingress processing
    source-filter       Source filters
    monitor-sessions    Monitor sessions
    flow-mirror         Flow mirror rules
    features            Features
```

The output is generated from the daemon's in-memory copy of the
configuration file. The output for `source-filter` includes the list
of filters that have been added with the `add` command as well.

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
usage: brokerctl dump [-h] {source-filter,monitor-sessions,flow-mirror,ingress,mac-rewrite,select-output,forward} ...

options:
  -h, --help            show this help message and exit

  {source-filter,monitor-sessions,flow-mirror,ingress,mac-rewrite,select-output,forward}
                        Dump tables from hardware
    source-filter       Source filters
    monitor-sessions    Monitor sessions
    flow-mirror         Flow mirror rules
    ingress             Ingress VLAN push/rewrite rules
    mac-rewrite         Ingress source MAC rewrite rules
    select-output       Ingress port to output group mapping
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
