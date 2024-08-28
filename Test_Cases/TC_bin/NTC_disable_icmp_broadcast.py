#!/usr/bin/python
"""
# ********************************************************************
# Name      : NTC_disable_icmp_broadcast.py
# Purpose   : Test script to check whether TC_disable_icmp_broadcast.py is checking ICMP package broadcast 
#             is disabled or not.
# ********************************************************************
"""
import os
import commands as c
import logging
import time
from TC_disable_icmp_broadcast import icmp_broad
def disable_icmp():

    if os.path.exists("/etc/sysctl.conf") == False:
        logging.info("/etc/sysctl.conf not available")
        print "/etc/sysctl.conf not available"
        return "FAIL"

    os.system("touch copyconf.txt")
    os.system("cp /etc/sysctl.conf  copyconf.txt")

    data = open('/etc/sysctl.conf', 'r').read().split('\n')
    newline = ''
    with open("/etc/sysctl.conf") as fin:
        if ("net.ipv4.icmp_echo_ignore_broadcasts=1" in data):
            newline = fin.read().replace('net.ipv4.icmp_echo_ignore_broadcasts=1', 'net.ipv4.icmp_echo_ignore_broadcasts=0')
        else:
            os.system("net.ipv4.icmp_echo_ignore_broadcasts=0 >> /etc/sysctl.conf")
    if newline:
        with open("/etc/sysctl.conf", "w") as fout:
            fout.write(newline)

    status=icmp_broad()
    os.system("cp copyconf.txt /etc/sysctl.conf")
    os.system("rm -rf copyconf.txt")

    if status == 'SUCCESS':
       return "FAIL"
    else:
       return "SUCCESS"

if __name__ == '__main__':
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_NTC_disable_icmp_broadcast.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)
    print disable_icmp()
