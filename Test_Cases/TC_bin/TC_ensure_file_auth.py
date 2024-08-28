#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_ensure_file_auth.py
# Purpose   : This script checks whether ensure_file_auth.py ensures 
#             to monitor for unsuccessful attempts to access files.
# ********************************************************************
"""

import os
import time
import commands as c
import logging

def ensure_file_auth():

    if os.path.exists("/etc/audit/rules.d/50-access.rules") is False:
        print "/etc/audit/rules.d/50-access.rules"
        logging.info("/etc/audit/rules.d/50-access.rules not found")
        return "FAIL"

    data = open('/etc/audit/rules.d/50-access.rules', 'r').read().split('\n')
    if '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access' in data and '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access' in data and '-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access' in data and '-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access' in data:
        return "SUCCESS"
    else:
        return "FAIL"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_ensure_file_auth.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)


    status = os.system("/ericsson/security/bin/ensure_file_auth.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/ensure_file_auth.py file not found")
        exit()

    print ensure_file_auth()