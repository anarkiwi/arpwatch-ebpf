#!/usr/bin/python3

import datetime
import ipaddress
import json
import time
from netaddr import EUI

logfile = '/var/log/arpwatch-ebpf-json.log'
ip_to_mac = {}

with open(logfile) as f:
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.1)
            continue
        json_line = json.loads(line)
        observed_time = datetime.datetime.fromtimestamp(json_line['observed_time'])
        target_mac = EUI(json_line['target_mac'])
        target_ip = ipaddress.ip_address(json_line['target_ip'])
        ip_to_mac[target_ip] = (target_mac, observed_time)
        print()
        for target_ip, mac_entry in sorted(ip_to_mac.items()):
            mac, observed_time = mac_entry
            print('\t'.join([str(i) for i in (target_ip, mac, observed_time)]))
