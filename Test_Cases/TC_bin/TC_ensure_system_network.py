#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_ensure_system_network.py
# Purpose   : This script checks whether ensure_system_network.py 
#             ensures the monitoring changes to network environment 
#             files or system calls.
#
#
# ********************************************************************
"""

import os
import time
import commands as c
import logging

def ensure_system_network():

    if os.path.exists("/etc/audit/rules.d/50-identity.rules") == False:
        print "/etc/audit/rules.d/50-identity.rules not found"
        logging.info("/etc/audit/rules.d/50-identity.rules not found")
        return "FAIL"

    data = open('/etc/audit/rules.d/50-identity.rules', 'r').read().split('\n')
    if '-w /etc/group -p wa -k identity' not in data and '-w /etc/passwd -p wa -k identity' not in data and '-w /etc/gshadow -p wa -k identity' not in data and '-w /etc/shadow -p wa -k identity' not in data and '-w /etc/security/opasswd -p wa -k identity' not in data:
        return "FAIL"
    else:
        return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_ensure_system_network.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)


    status = os.system("/ericsson/security/bin/ensure_system_network.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/ensure_system_network.py file not found")
        exit()

    print ensure_system_network()