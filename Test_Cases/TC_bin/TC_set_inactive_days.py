#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_set_inactive_days.py 
# Purpose   : Test script to check whether the account lockout for 30 days
#             is enabled.
# ********************************************************************
"""
import os
import time
import logging
import subprocess
import commands as c

def inactive_days():

    inactive_days = subprocess.check_output("useradd -D | grep INACTIVE", shell=True)
    if inactive_days.strip("\n") != "INACTIVE=30":
        return "FAIL"
    else: 
        return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_set_inactive_days.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/set_inactive_days.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/set_inactive_days.py error")
        exit()

    print inactive_days()
