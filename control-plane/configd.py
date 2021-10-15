#!/usr/bin/env python2
import argparse
import sys
import os
import signal
import time
import logging
import socket, select
import json
import bfrt, packet_broker

class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'compressed'):
            return obj.compressed
        else:
            pprint.pprint(obj)
            raise TypeError

parser = argparse.ArgumentParser(description='Packet-broker configuration daemon')
parser.add_argument('--config-dir', help=
                    """Path of the directory containing configuration
                    and schema files""",
                    required=False, default="/etc/packet-broker")
parser.add_argument('--ifmibs-dir', help=
                    """Path of the directory where shared memory
                    regions for interface MIBs are created""",
                    required=False, default="/var/run/packet-broker")
parser.add_argument('--stats-update-interval', help=
                    """Interval in seconds, at which the interface
                    statistics in the ifTable MIB are synchronized
                    with the hardware counters""",
                    type=int, required=False, default=5)
parser.add_argument('--connect-retries', help=
                    """The number of retries the gRPC client attempts
                    to connect to the server at one-second intervals""",
                    type=int, required=False, default=30)
parser.add_argument('--listen-on', help=
                    """The addresses to listen on for communication with
                    the brokerctl command""",
                    type=str, default='')
parser.add_argument('--port', help=
                    """The port to use for communication with the
                    brokerctl command""",
                    type=int, default=7000)
args = parser.parse_args()

## Make outputs unbuffered for logging purposes
if sys.version_info < (3, 0):
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
    sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', 0)
else:
    sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', buffering=1)
    sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', buffering=1)

logging.basicConfig(level = logging.INFO,
                    format='%(asctime)s.%(msecs)03d %(levelname)s:%(name)s: %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger('configd')

## XXX: make dual-stack
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((args.listen_on, args.port))
s.listen(5)
logger.info("Listening on {}/{} for connections".
            format(args.listen_on if args.listen_on else 'any',
                   str(args.port)))

bfrt = bfrt.Bfrt("packet_broker", retries = args.connect_retries)
broker = packet_broker.PacketBroker(bfrt, args.config_dir, args.ifmibs_dir)

def tear_down_and_exit(rc):
    ## The method has been renamed in SDE 9.4.0
    if hasattr(bfrt.intf, '_tear_down_stream'):
        bfrt.intf._tear_down_stream()
    else:
        bfrt.intf.tear_down_stream()
    sys.exit(rc)

if not broker.handle_request(('self', 0), { 'command': 'reload'})['success']:
    tear_down_and_exit(1)

signals = dict((getattr(signal, n), n) \
               for n in dir(signal) if n.startswith('SIG') and '_' not in n )

def exit_handler(signal, frame):
    logger.info("Received {}, exiting".format(signals[signal]))
    s.close()
    tear_down_and_exit(0)

signal.signal(signal.SIGTERM, exit_handler)
signal.signal(signal.SIGINT, exit_handler)

stats_stamp = time.time()
while True:
    r, w, e = select.select([s], [], [], args.stats_update_interval)
    if s in r:
        c, peer = s.accept()
        f = c.makefile()
        line = f.readline()
        if not line:
            print("EOF")
            c.close()
            break
        resp = broker.handle_request(peer, json.loads(line))
        c.send(json.dumps(resp, cls = JSONEncoder) + "\n")
        c.close()

    now = time.time()

    if not r or now - stats_stamp >= args.stats_update_interval:
        stats_stamp = now
        broker.update_stats()
