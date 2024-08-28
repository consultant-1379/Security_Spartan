#!/usr/bin/python
"""
# ********************************************************************
# Name      : NTC_set_inactive_days.py 
# Purpose   : Test script to check whether TC_set_inactive_days.py is 
#             checking account lockout for 30 days is enabled or not.
# ********************************************************************
"""
import os
import time
import logging
import subprocess
import commands as c

def ntc_inactive_days():

    return_value = os.system("useradd -D -f 10")
    inactive_days = subprocess.check_output("useradd -D | grep INACTIVE", shell=True)
    os.system("useradd -D -f 30")
    if inactive_days.strip("\n") == "INACTIVE=10":
        return "SUCCESS"
    else:
        return "FAIL"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_enable_reverse_path_filter.log'
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

    print ntc_inactive_days()
    

