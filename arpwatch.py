#!/usr/bin/python3

import ipaddress
import json
import re
import subprocess
import sys
import time
import psutil
from netaddr import EUI

MAP = 'isat_map'

map_out = subprocess.run(['bpftool', 'map', 'list'], capture_output=True)
map_re = re.compile(r'^(\d+):\s+hash\s+name\s+%s' % MAP)
stdout = map_out.stdout.decode('UTF-8')
map_match = map_re.match(stdout)
if not map_match:
    print('no map', stdout)
    sys.exit(-1)
map_id = map_match.group(1)

while True:
  print()
  dump_out = subprocess.run(['bpftool', 'map', 'dump', 'id', str(map_id)], capture_output=True)
  stdout = dump_out.stdout.decode('UTF-8')
  dump = json.loads(stdout)
  now = (time.time() - psutil.boot_time()) * 1e9
  for entry in dump:
      value = entry['value']
      ip = value['target_ip']
      if set(ip[4:]) == {0}:
        ip = ip[:4]
      ip = ipaddress.ip_address(int.from_bytes(bytes(ip), signed=False, byteorder='big'))
      mac = value['target_mac']
      mac = EUI(':'.join(['%2.2x' % i for i in mac]))
      ktime = value['observed_ktime']
      print('%16.16s %24.24s %10.1f sec' % (ip, mac, (now - ktime) / 1e9))
  time.sleep(1)

