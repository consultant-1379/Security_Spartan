#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_ensure_sys_admin_scope.py
# Purpose   : This script checks whether ensure_sys_admin_scope.py Monitors 
#             the changes in /etc/sudo and etc/sudoers is collected.
# ********************************************************************
"""

import os
import time
import commands as c
import logging

def ensure_sys_admin_scope():

    if os.path.exists("/etc/audit/rules.d/50-scope.rules") is False:
        print "/etc/audit/rules.d/50-scope.rules is not found"
        logging.info("/etc/audit/rules.d/50-scope.rules not found")
        return "FAIL"

    data = open('/etc/audit/rules.d/50-scope.rules', 'r').read().split('\n')
    if '-w /etc/sudoers -p wa -k scope' in data and '-w /etc/sudoers.d/ -p wa -k scope' in data:
        return "SUCCESS"
    else:
        return "FAIL"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_ensure_sys_admin_scope.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)


    status = os.system("/ericsson/security/bin/ensure_sys_admin_scope.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/ensure_sys_admin_scope.py file is absent")
        exit()

    print ensure_sys_admin_scope()