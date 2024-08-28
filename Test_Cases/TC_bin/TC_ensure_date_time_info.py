#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_ensure_date_time_info.py
# Purpose   : This script checks whether ensure_date_time_info.py ensures 
#             where the system date and/or time has been modified.
#
# ********************************************************************
"""

import os
import time
import commands as c
import logging

def ensure_date_time():

    if os.path.exists("/etc/audit/rules.d/50-time_change.rules") == False:
        print "/etc/audit/rules.d/50-time_change.rules not found"
        logging.info("/etc/audit/rules.d/50-time_change.rules not found")
        return "FAIL"

    data = open('/etc/audit/rules.d/50-time_change.rules', 'r').read().split('\n')
    if '-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k timechange' not in data and '-a always,exit -F arch=b32 -S clock_settime -k time-change' not in data and '-w /etc/localtime -p wa -k time-change' not in data and '-a always,exit -F arch=b32 -S clock_settime -k time-change' not in data and '-w /etc/localtime -p wa -k time-change' not in data:
        return "FAIL"
    else:
        return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_TC_ensure_date_time_info.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)


    status = os.system("/ericsson/security/bin/ensure_date_time_info.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/ensure_date_time_info.py error")
        exit()

    print ensure_date_time()