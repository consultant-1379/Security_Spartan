#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_discretionary_access_control.py
# Purpose   : This script checks whether discretionary_access_control.py 
#             ensures to monitor changes to file permissions, attributes, 
#             ownership and group.
# ********************************************************************
"""

import os
import time
import commands as c
import logging

def discretionary_access_control():

    if os.path.exists("/etc/audit/rules.d/50-perm_mod.rules") is False:
        print "/etc/audit/rules.d/50-perm_mod.rules"
        logging.info("/etc/audit/rules.d/50-perm_mod.rules not found")
        return "FAIL"

    data = open('/etc/audit/rules.d/50-perm_mod.rules', 'r').read().split('\n')
    if '-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod' in data and '-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod' in data and '-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod' in data and '-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod' in data and '-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' in data and '-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod' in data:
        return "SUCCESS"
    else:
        return "FAIL"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_discretionary_access_control.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)


    status = os.system("/ericsson/security/bin/discretionary_access_control.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/discretionary_access_control.py file not found")
        exit()

    print discretionary_access_control()