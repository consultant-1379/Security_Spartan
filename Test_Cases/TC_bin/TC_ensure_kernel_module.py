#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_ensure_kernel_module.py
# Purpose   : This script checks whether ensure_kernel_module.py Monitors
#             the use of insmod , rmmod and modprobe
# ********************************************************************
"""

import os
import time
import commands as c
import logging

def ensure_kernel_module():

    if os.path.exists("/etc/audit/rules.d/50-modules.rules") is False:
        print "/etc/audit/rules.d/50-modules.rules"
        logging.info("/etc/audit/rules.d/50-modules.rules not found")
        return "FAIL"

    data = open('/etc/audit/rules.d/50-modules.rules', 'r').read().split('\n')
    if '-w /sbin/insmod -p x -k modules' in data and '-w /sbin/rmmod -p x -k modules' in data and '-w /sbin/modprobe -p x -k modules' in data and '-a always,exit -F arch=b64 -S init_module -S delete_module -k modules' in data:
        return "SUCCESS"
    else:
        return "FAIL"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_ensure_kernel_module.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)


    status = os.system("/ericsson/security/bin/ensure_kernel_module.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/ensure_kernel_module.py file not found")
        exit()

    print ensure_kernel_module()