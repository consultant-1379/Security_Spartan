#!/usr/bin/python
""""
# ********************************************************************
# Name      : NTC_disable_access_suid.py
# Purpose   : Test case to verify that allowed directories are having suid.
#
# ********************************************************************
"""
import os
import commands as c
import logging
import time
from TC_disable_access_suid import check_suid

def change_suid():
    os.system("chmod u+s /tmp > /dev/null")
    r=check_suid()
    os.system("chmod u-s /tmp > /dev/null")
    if r=="FAIL":
	 return "SUCCESS"
    else:
	 return "FAIL"
if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_tcp_wrappers.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    print change_suid()
