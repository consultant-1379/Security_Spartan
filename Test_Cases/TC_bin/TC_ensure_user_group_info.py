#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_ensure_user_group_info.py
# Purpose   : This script checks whether ensure_user_group_info.py Monitors 
#             the changes in pam configuration files.
# ********************************************************************
"""

import os
import time
import commands as c
import logging

def ensure_user_group_info():

    if os.path.exists("/etc/audit/rules.d/50-identity.rules") is False:
        print "/etc/audit/rules.d/50-identity.rules is not found"
        logging.info("/etc/audit/rules.d/50-identity.rules not found")
        return "FAIL"

    data = open('/etc/audit/rules.d/50-identity.rules', 'r').read().split('\n')
    if '-w /etc/group -p wa -k identity' in data and '-w /etc/passwd -p wa -k identity' in data and '-w /etc/gshadow -p wa -k identity' in data and \
'-w /etc/shadow -p wa -k identity' in data and '-w /etc/security/opasswd -p wa -k identity' in data:
        return "SUCCESS"
    else:
        return "FAIL"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_ensure_user_group_info.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)


    status = os.system("/ericsson/security/bin/ensure_user_group_info.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/ensure_user_group_info.py is not present")
        exit()

    print ensure_user_group_info()