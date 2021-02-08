#!/usr/bin/python3

import argparse
import subprocess
import ipaddress
import json
import sys
import time
from uptime import boottime
from bcc import BPF
from netaddr import EUI

parser = argparse.ArgumentParser(description='arpwatch-ebpf')
parser.add_argument('--device', type=str, default='lo')
parser.add_argument('--attach', action='store_true')
parser.add_argument('--no-attach', dest='attach', action='store_false')
parser.add_argument('--json_logfile', type=str, default='/var/log/arpwatch-ebpf-json.log')
parser.set_defaults(attach=True)
args = parser.parse_args()

print('initializing')
b = BPF(src_file='arpwatch-ebpf.c')
fn = b.load_func('arpwatch_ebpf', BPF.XDP)
if not args.attach:
    sys.exit(0)

rb = b['buffer']
boot_ts = boottime().timestamp()

def callback(ctx, data, size):
    isat = rb.event(data)
    target_ip = ipaddress.ip_address(bytes(isat.target_ip)[:isat.target_iplen])
    target_mac = EUI(':'.join(['%2.2x' % i for i in isat.target_mac]))
    isat_json = json.dumps({
        'target_ip': str(target_ip),
        'target_mac': str(target_mac),
        'observed_time': boot_ts + (isat.observed_ktime / 1e9)})
    with open(args.json_logfile, 'a') as f:
        f.write(isat_json + '\n')

print('attaching to %s' % args.device)
b.attach_xdp(args.device, fn, 0)
rb.open_ring_buffer(callback)
# Need promisc as might receive packet with eth_dst not to us.
subprocess.check_call(['ip', 'link', 'set', args.device, 'promisc', 'on'])
print('attached')
try:
    while True:
        b.ring_buffer_poll()
        time.sleep(0.1)
except KeyboardInterrupt:
    pass
subprocess.check_call(['ip', 'link', 'set', args.device, 'promisc', 'off'])
b.remove_xdp(args.device, 0)
