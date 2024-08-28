#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_ensure_file_deletion.py
# Purpose   : This script checks whether ensure_file_deletion.py ensures 
#             to monitor the use of system calls associated with the deletion 
#             or renaming of files and file attributes.
# ********************************************************************
"""

import os
import time
import commands as c
import logging

def ensure_file_deletion():

    if os.path.exists("/etc/audit/rules.d/50-deletion.rules") is False:
        print "/etc/audit/rules.d/50-deletion.rules"
        logging.info("/etc/audit/rules.d/50-deletion.rules not found")
        return "FAIL"

    data = open('/etc/audit/rules.d/50-deletion.rules', 'r').read().split('\n')
    if '-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete' in data and '-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete' in data:
        return "SUCCESS"
    else:
        return "FAIL"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_ensure_file_deletion.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)


    status = os.system("/ericsson/security/bin/ensure_file_deletion.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/ensure_file_deletion.py file not found")
        exit()

    print ensure_file_deletion()