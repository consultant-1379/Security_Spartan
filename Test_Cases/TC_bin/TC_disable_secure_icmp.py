#!/usr/bin/python
"""
# ****************************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ****************************************************************************
#
#
# (c) Ericsson Radio Systems AB 2022 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : TC_disable_secure_icmp.py 
# Purpose   : Test script to check whether secure ICMP redirects  
#             are accepted or not.
# ********************************************************************
"""
import os
import time
import logging
import commands as c

def disable_secure_icmp():

    if os.path.exists("/etc/sysctl.conf") == False:
          logging.info("/etc/sysctl.conf not available")
          print "/etc/sysctl.conf not available"
          return "FAIL"

    data = open('/etc/sysctl.conf', 'r').read().split('\n')

    if ("net.ipv4.conf.all.secure_redirects=0" not in data or "net.ipv4.conf.default.secure_redirects=0" not in data):
           print "Secure ICMP redirects are not disabled in /etc/sysctl.conf"
           logging.info("Secure ICMP redirects are not disabled in /etc/sysctl.conf")
           return "FAIL"
    elif("net.ipv4.conf.all.secure_redirects=1" in data):
           print "net.ipv4.conf.all.secure_redirects = 1 is found in /etc/sysctl.conf"
           logging.info("net.ipv4.conf.all.secure_redirects = 1 is found in /etc/sysctl.conf")
           return "FAIL"
    elif("net.ipv4.conf.default.secure_redirects=1" in data):
           print "net.ipv4.conf.default.secure_redirects=1 is found in /etc/sysctl.conf"
           logging.info("net.ipv4.conf.default.secure_redirects=1 is found in /etc/sysctl.conf")

    return "SUCCESS"


if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_TC_disable_secure_icmp.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/disable_secure_icmp.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
        logging.info("/ericsson/security/bin/disable_secure_icmp.py error")
        exit()

    print disable_secure_icmp()
