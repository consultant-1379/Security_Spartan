#!/usr/bin/python
"""
# ********************************************************************
# Name      : NTC_autologout.py
# Purpose   : Automated negative test script to check TC_autologout.
#
# ********************************************************************
"""

import os
import time
import logging
import commands as c
from TC_autologout import logout

def change_logout_time():
    os.system("touch configcopy1.txt")
    os.system("cp /etc/profile configcopy1.txt")
    check1 = open("/etc/profile","r").read().split('\n')
    line1 = "TMOUT=900"
    line2 = "export TMOUT"

    with open("/etc/profile", "r") as f:
        lines = f.readlines()
    if(line2 in check1):
      with open("/etc/profile", "w") as fi:
         for line in lines:
            if line.strip("\n") != "export TMOUT":
              fi.write(line)
      r=logout()
    if(line1 in check1):
      with open("/etc/profile", "w") as fi:
         for line in lines:
            if line.strip("\n") != "TMOUT=900":
              fi.write(line)
      r=logout()
    os.system("cp configcopy1.txt /etc/profile")
    os.system("rm -rf configcopy1.txt")
    if r=="FAIL": 
	  return  "SUCCESS"
    else:
	   return "FAIL"
if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_autologout.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,filename=pwd+fname,format=format_str)
    if os.path.exists("/etc/profile") == False:
        print "FAIL"
        logging.info("/etc/profile not available")
        exit()


    print change_logout_time()
                                                            