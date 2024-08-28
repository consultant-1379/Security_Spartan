#!/usr/bin/python
"""
# ********************************************************************
# Name      : NTC_tcp_wrappers.py
# Purpose   : Test script to check sftp is enabled.
#
# ********************************************************************
"""

import os
import commands as c
import logging
import time
from TC_tcp_wrappers import FTP

def disable_FTP():

    if os.path.exists("/etc/hosts.deny") == False:
        print "/etc/hosts.allow not found"
        logging.info("/etc/hosts.allow not found")
        return "FAIL"
    os.system("touch copyetchosts.txt")
    os.system("cp /etc/hosts.deny copyetchosts.txt")

    with open("/etc/hosts.deny", "r") as f:
        lines = f.readlines()
    with open("/etc/hosts.deny", "w") as fi:
         for line in lines:
            if line.strip("\n") != "vsftpd: ALL":
              fi.write(line)

    r=FTP()
    os.system("cp  copyetchosts.txt /etc/hosts.deny")
    os.system("rm -rf  copyetchosts.txt")
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

    print disable_FTP()
