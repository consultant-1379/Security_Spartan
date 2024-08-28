#!/usr/bin/python

import os
import logging
import time
import commands as c

def disable_Gateway():

    data = open('/etc/ssh/ssh_config', 'r').read().split('\n')
    if "GatewayPorts no" not in data:
	print "Gateway ports is enabled"
	logging.info("Gateway ports is enabled")
        return "FAIL"
       
    if "GatewayPorts yes" in data:
	print "Gateway ports is enabled"
	logging.info("Gateway ports is enabled")
        return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_disable_GatewayPorts.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    if os.path.exists("/etc/ssh/ssh_config") == False:
        print "FAIL"
	logging.info("/etc/ssh/ssh_config no found")
        exit()
    check = open("/etc/ssh/ssh_config","r").read().split('\n')

    status = os.system("/ericsson/security/bin/disable_GatewayPorts.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
	logging.info("/ericsson/security/bin/disable_GatewayPorts.py error")
        exit()

    data = open('/etc/ssh/ssh_config', 'r').read().split('\n')

    for line in check:
        if line not in data and line != "GatewayPorts yes":
            print "FAIL"
	    logging.info("%s not found earlier in /etc/ssh/ssh_config" % line)
            exit()

    print disable_Gateway()
