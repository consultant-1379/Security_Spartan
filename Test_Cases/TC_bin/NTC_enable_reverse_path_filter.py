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
# Name      : NTC_enable_reverse_path_filter.py 
# Purpose   : Test script to check whether ipv6 router advertisements
#             are disabled or not.
# ********************************************************************
"""
import os
import time
import logging
import commands as c
from TC_enable_reverse_path_filter import enable_reverse_path_filter

def reverse_path_filter():

    if os.path.exists("/etc/sysctl.conf") == False:
        logging.info("/etc/sysctl.conf not available")
        print "/etc/sysctl.conf not available"
        return "FAIL"

    os.system("touch copyconf.txt")
    os.system("cp /etc/sysctl.conf  copyconf.txt")

    data = open('/etc/sysctl.conf', 'r').read().split('\n')
    newline = ''
    with open("/etc/sysctl.conf") as fin:
        if ("net.ipv4.conf.all.rp_filter=1" in data):
            newline = fin.read().replace('net.ipv4.conf.all.rp_filter=1', 'net.ipv4.conf.all.rp_filter=0')
        elif ("net.ipv4.conf.default.rp_filter=1" in data):
            newline = fin.read.replace('net.ipv4.conf.default.rp_filter=1', 'net.ipv4.conf.default.rp_filter=0')
        else:
            os.system("echo net.ipv4.conf.all.rp_filter=0 >> /etc/sysctl.conf")
            os.system("echo net.ipv4.conf.default.rp_filter=0 >> /etc/sysctl.conf")
    if newline:
        with open("/etc/sysctl.conf", "w") as fout:
            fout.write(newline)

    status=enable_reverse_path_filter()

    os.system("cp copyconf.txt /etc/sysctl.conf")
    os.system("rm -rf copyconf.txt")

    if status == 'SUCCESS':
       return "FAIL"
    else:
       return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_NTC_enable_reverse_path_filter.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    print reverse_path_filter()
