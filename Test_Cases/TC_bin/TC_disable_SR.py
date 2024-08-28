#!/usr/bin/python
"""
# ********************************************************************
# Name      : TC_disable_SR.py
# Purpose   : Test script to check whether source routing is disabled.
#
# ********************************************************************
"""
import os
import time
import logging
import commands as c

def disable():
	
    if os.path.exists("/etc/sysctl.conf") == False:
	  logging.info("/etc/sysctl.conf not available")
	  print "/etc/sysctl.conf not available"
          return "FAIL"
		
    data = open('/etc/sysctl.conf', 'r').read().split('\n')
    if "net.ipv4.conf.all.send_redirects=0" not in data or "net.ipv4.conf.default.send_redirects=0" not in data or\
"net.ipv4.conf.all.accept_redirects=0" not in data or "net.ipv4.conf.default.accept_redirects=0" not in data or\
"net.ipv4.conf.all.accept_source_route=0" not in data or "net.ipv4.conf.default.accept_source_route=0" not in data:
	   print "Disabling packet redirection on the server failed"
	   logging.info("Disabling packet redirection on the server failed")
	   return "FAIL"
	
    return "SUCCESS"
	
	
if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_disable_SR.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    status = os.system("/ericsson/security/bin/disable_SR.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
	logging.info("/ericsson/security/bin/disable_SR.py error")
        exit()

    print disable()
