#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_ensure_system_access.py
# Purpose   : This script checks whether ensure_system_access.py ensures 
#             the monitor of SELinux mandatory access controls.
# ********************************************************************
"""

import os
import time
import commands as c
import logging

def ensure_system_access():

    if os.path.exists("/etc/audit/rules.d/50-MAC_policy.rules") is False:
        print "/etc/audit/rules.d/50-MAC_policy.rules"
        logging.info("/etc/audit/rules.d/50-MAC_policy.rules not found")
        return "FAIL"

    data = open('/etc/audit/rules.d/50-MAC_policy.rules', 'r').read().split('\n')
    if '-w /etc/selinux/ -p wa -k MAC-policy' in data and '-w /usr/share/selinux/ -p wa -k MAC-policy' in data:
        return "SUCCESS"
    else:
        return "FAIL"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_ensure_system_access.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)


    status = os.system("/ericsson/security/bin/ensure_system_access.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/ensure_system_access.py file not found")
        exit()

    print ensure_system_access()