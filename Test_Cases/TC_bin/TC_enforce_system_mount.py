#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_enforce_system_mount.py
# Purpose   : This script checks whether enforce_system_mount.py 
#             ensures to monitor the use of the mount system call.
# ********************************************************************
"""

import os
import time
import commands as c
import logging

def enforce_system_mount():

    if os.path.exists("/etc/audit/rules.d/50-mounts.rules") is False:
        print "/etc/audit/rules.d/50-mounts.rules"
        logging.info("/etc/audit/rules.d/50-mounts.rules not found")
        return "FAIL"

    data = open('/etc/audit/rules.d/50-mounts.rules', 'r').read().split('\n')
    if '-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts' in data and '-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts' in data:
        return "SUCCESS"
    else:
        return "FAIL"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_enforce_system_mount.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)


    status = os.system("/ericsson/security/bin/enforce_system_mount.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/enforce_system_mount.py file not found")
        exit()

    print enforce_system_mount()