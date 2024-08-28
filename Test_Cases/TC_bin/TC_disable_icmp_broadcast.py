#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_disable_icmp_broadcast.py
# Purpose   : Test script to check whether  ICMP package broadcast is 
#				getting disabled by disable_icmp_broadcast.py
# ********************************************************************
"""

import os
import logging
import commands as c
import time

def icmp_broad():

    if os.path.exists("/etc/sysctl.conf") == False:
          logging.info("/etc/sysctl.conf not available")
          print "/etc/sysctl.conf not available"
          return "FAIL"

    data = open('/etc/sysctl.conf', 'r').read().split('\n')

    if ("net.ipv4.icmp_echo_ignore_broadcasts=1" not in data):
           print "ICMP package broadcast are not disabled in /etc/sysctl.conf"
           logging.info("ICMP package broadcast are not disabled in /etc/sysctl.conf")
           return "FAIL"
    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_TC_disable_icmp_broadcast.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/disable_icmp_broadcast.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/disable_icmp_broadcast.py error")
        exit()

    print icmp_broad()
