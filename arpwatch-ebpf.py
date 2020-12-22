#!/usr/bin/python3

import argparse
import subprocess
from bcc import BPF

parser = argparse.ArgumentParser(description='arpwatch-ebpf')
parser.add_argument('--device', type=str, default='lo')
parser.add_argument('--attach', action='store_true')
parser.add_argument('--no-attach', dest='attach', action='store_false')
parser.set_defaults(attach=True)
args = parser.parse_args()

print('initializing')
b = BPF(src_file='arpwatch-ebpf.c')
fn = b.load_func('arpwatch_ebpf', BPF.XDP)
if args.attach:
    print('attaching to %s' % args.device)
    b.attach_xdp(args.device, fn, 0)
    # Need promisc as might receive packet with eth_dst not to us.
    subprocess.check_call(['ip', 'link', 'set', args.device, 'promisc', 'on'])
    print('attached')
    try:
        b.trace_print()
    except KeyboardInterrupt:
        pass
    subprocess.check_call(['ip', 'link', 'set', args.device, 'promisc', 'off'])
    b.remove_xdp(args.device, 0)
