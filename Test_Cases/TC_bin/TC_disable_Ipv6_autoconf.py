#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_disable_Ipv6_autoconf.py
# Purpose   : Test script to test that Ipv6 autoconf feature is 
#			   getting disabled by disable_Ipv6_autoconf.py
# ********************************************************************
"""
import os
import time
import commands as c
import logging

def disable_Ipv6():

    if os.path.exists("/etc/sysctl.conf") == False:
	print "/etc/sysctl.conf not found"
	logging.info("/etc/sysctl.conf not found")
        return "FAIL"

    data = open('/etc/sysctl.conf', 'r').read().split('\n')
    if "net.ipv6.conf.default.autoconf=0" not in data:
	print "net.ipv6.conf.default.autoconf=0 not found"
	logging.info("net.ipv6.conf.default.autoconf=0 not found")
        return "FAIL"

    if "net.ipv6.conf.default.autoconf=1" in data:
	print "net.ipv6.conf.default.autoconf=1 is found"
	logging.info("net.ipv6.conf.default.autoconf=1 is found")
        return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_disable_Ipv6_autoconf.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    if os.path.exists("/etc/sysctl.conf") == False:
        print "FAIL"
	logging.info("/etc/sysctl.conf not found")
        exit()
    check = open("/etc/sysctl.conf","r").read().split('\n')
    status = os.system("/ericsson/security/bin/disable_Ipv6_autoconf.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/disable_Ipv6_autoconf.py error")
        print "FAIL"
        exit()

    data = open('/etc/sysctl.conf', 'r').read().split('\n')

    for line in check:
        if line not in data and line != "net.ipv6.conf.default.autoconf=1":
	    logging.info("%s not found earlier" % line)
            print "FAIL"
            exit()

    print disable_Ipv6()
