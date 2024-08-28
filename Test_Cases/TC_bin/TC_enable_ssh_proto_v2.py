#!/usr/bin/python

import os
import time
import commands as c
import logging

def version():

    if os.path.exists("/etc/ssh/ssh_config") == False:
	print "/etc/ssh/ssh_config not found"
	logging.info("/etc/ssh/ssh_config not found")
        return "FAIL"
    
    data = open("/etc/ssh/ssh_config","r").read().split('\n')
    if "Protocol 2" not in data:
	print "protocol version not changed"
	logging.info("protocol version not changed")
	return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_enable_ssh_proto_v2.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)


    if os.path.exists("/etc/ssh/ssh_config") == False:
	logging.info("/etc/ssh/ssh_config not found")
        print "FAIL"
        exit()
    check = open("/etc/ssh/ssh_config","r").read().split('\n')

    status = os.system("/ericsson/security/bin/enable_ssh_proto_v2.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/enable_ssh_proto_v2.py error")
        print "FAIL"
        exit()

    data = open("/etc/ssh/ssh_config","r").read().split('\n')
    for line in check:
        if line not in data and line != '#Protocol 2' and line != '#   Protocol 2':
	    logging.info("%s not present earlier" % line)
            print "FAIL"
            exit()

    print version() 
