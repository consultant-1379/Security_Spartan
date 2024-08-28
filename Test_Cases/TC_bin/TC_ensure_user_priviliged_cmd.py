#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_ensure_user_priviliged_cmd.py
# Purpose   : This script checks whether ensure_user_priviliged_cmd.py 
#             Monitors privileged programs to determine if unprivileged 
#             users are running setuid and/or setgid commands.
# ********************************************************************
"""

import os
import time
import commands as c
import logging

def ensure_user_priviliged_cmd():

    if os.path.exists("/etc/audit/rules.d/50-privileged.rules") is False:
        print "/etc/audit/rules.d/50-privileged.rules"
        logging.info("/etc/audit/rules.d/50-privileged.rules not found")
        return "FAIL"

    data = open('/etc/audit/rules.d/50-privileged.rules', 'r').read().split('\n')
    if os.stat("/etc/audit/rules.d/50-privileged.rules").st_size != 0:
        return "SUCCESS"
    else:
        return "FAIL"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_ensure_user_priviliged_cmd.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)


    status = os.system("/ericsson/security/bin/ensure_user_priviliged_cmd.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/ensure_user_priviliged_cmd.py file not found")
        exit()

    print ensure_user_priviliged_cmd()