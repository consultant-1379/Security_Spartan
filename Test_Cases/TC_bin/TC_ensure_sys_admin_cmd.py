#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_ensure_sys_admin_cmd.py
# Purpose   : This script checks whether ensure_sys_admin_cmd.py Monitors 
#             when an unprivileged user tends to use sudo command to 
#             undergo any elevated operartions.
# ********************************************************************
"""

import os
import time
import commands as c
import logging

def ensure_sys_admin_cmd():

    if os.path.exists("/etc/audit/rules.d/50-actions.rules") is False:
        print "/etc/audit/rules.d/50-actions.rules is not found"
        logging.info("/etc/audit/rules.d/50-actions.rules not found")
        return "FAIL"

    data = open('/etc/audit/rules.d/50-actions.rules', 'r').read().split('\n')
    if '-a always,exit -F arch=b64 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions' in data and '-a always,exit -F arch=b32 -C euid!=uid -F euid=0 -F auid>=1000 -F auid!=4294967295 -S execve -k actions' in data:
        return "SUCCESS"
    else:
        return "FAIL"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_ensure_sys_admin_cmd.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)


    status = os.system("/ericsson/security/bin/ensure_sys_admin_cmd.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/ensure_sys_admin_cmd.py file not found")
        exit()

    print ensure_sys_admin_cmd()