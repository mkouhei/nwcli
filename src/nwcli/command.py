#!/usr/bin/env python
import getpass
import sys
import telnetlib
import argparse
from __init__ import __version__

prs = argparse.ArgumentParser(description='usage')
prs.add_argument('-v', '--version', action='version',
                 version=__version__)
prs.add_argument('--remotehost', action='store', required=True,
                 help='target network equipment')
args = prs.parse_args()

remotehost = args.remotehost
password = getpass.getpass()

tn = telnetlib.Telnet(remotehost)

# for cisco 3750
if password:
    tn.read_until("Password:")
    tn.write(password + "\n")

tn.write("terminal length 0\n")
tn.write("show int status\n")
#tn.write("show mac address-table dynamic\n")
tn.write("exit\n")

stream = tn.read_all()
for line in stream.splitlines():
    import re
    line_d = re.split('\s*', line)
    if re.match('^Gi', line_d[0]):
        print(line_d)
