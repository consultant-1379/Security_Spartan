#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_autologout.py
# Purpose   : Test script to session time out is set to 900.
#
# ********************************************************************
"""

import os
import time
import logging 
import commands as c

def logout():

    if os.path.exists("/etc/profile") == False:
	logging.info("/etc/profile not available")
	print "/etc/profile not available"
        return "FAIL"

    check = c.getoutput('echo $TMOUT')
    if check != '900':
	print "TMOUT is "+check
	logging.info("TMOUT is not 900")
	return "FAIL"

    check1 = open("/etc/profile","r").read().split('\n')
    line1 = "TMOUT=900"
    line2 = "export TMOUT"
    if ((line1 not in check1) or (line2 not in check1)):
	logging.info("%s not in /etc/profile" % line1+line2)
	print "%s not in /etc/profile" % line1+line2
        return  "FAIL"

    return "SUCCESS"

if __name__ == '__main__':
    
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_autologout.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    if os.path.exists("/etc/profile") == False:
        print "FAIL"
	logging.info("/etc/profile not available")
        exit()
    check = open("/etc/profile","r").read().split('\n')

    status = os.system("/ericsson/security/bin/set_autologout.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
	logging.info("/ericsson/security/bin/set_autologout.py Error")
        exit()
    check1 = open("/etc/profile","r").read().split('\n')
    for line in check:
        if line not in check1:
	    logging.info("%s not in /etc/profile earlier" % line)
            print "FAIL"
            exit()

    print logout()

