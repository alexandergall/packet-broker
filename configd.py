#!/usr/bin/env python2
import argparse
import sys
import os
import signal
import time
import bfrt, config

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
args = parser.parse_args()

## Make outputs unbuffered for logging purposes
sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
sys.stderr = os.fdopen(sys.stderr.fileno(), 'w', 0)

bfrt = bfrt.Bfrt("packet_broker", retries = args.connect_retries)
config = config.Config(bfrt, args.config_dir, args.ifmibs_dir)
config.configure()

def sighup_handler(signal, frame):
    print("Received SIGHUP")
    config.configure()

signals = dict((getattr(signal, n), n) \
               for n in dir(signal) if n.startswith('SIG') and '_' not in n )

def exit_handler(signal, frame):
    print("Received {}, exiting".format(signals[signal]))
    bfrt.intf._tear_down_stream()
    sys.exit(0)

signal.signal(signal.SIGHUP, sighup_handler)
signal.signal(signal.SIGTERM, exit_handler)
signal.signal(signal.SIGINT, exit_handler)

while True:
    time.sleep(args.stats_update_interval)
    config.update_stats()