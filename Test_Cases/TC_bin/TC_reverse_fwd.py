#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_reverse_fwd.py
# Purpose   : Test script to check reverse path forwarding is getting 
#				enforced with strict rpfilter by reverse_fwd.py.
# ********************************************************************
"""

import os
import time
import commands as c
import logging

def reverse():

    if os.path.exists("/proc/sys/net/ipv4/conf/default/rp_filter") == False:
	print "/proc/sys/net/ipv4/conf/default/rp_filter not found"
	logging.info("/proc/sys/net/ipv4/conf/default/rp_filter not found")
        return "FAIL"

    data = open('/proc/sys/net/ipv4/conf/default/rp_filter', 'r').read().split('\n')
    if data[0] != '1':
	print "RP filter not fit"
	logging.info("RP filter not fit")
        return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_reverse_fwd.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)


    status = os.system("/ericsson/security/bin/reverse_fwd.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/reverse_fwd.py error")
        print "FAIL"
        exit()

    print reverse()
