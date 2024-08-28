#!/usr/bin/python

import os
import commands as c
import logging
import time

def Agent():

    data = open('/etc/ssh/sshd_config', 'r').read().split('\n')
    if "AllowAgentForwarding no" not in data:
        logging.info("AllowAgentForwarding is allowed")
        print "AllowAgentForwarding is allowed"
        return "FAIL"

    if "AllowAgentForwarding yes" in data:
        logging.info("AllowAgentForwarding is allowed")
        print "AllowAgentForwarding is allowed"
        return "FAIL"
    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_configure_sshd.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    if os.path.exists("/etc/ssh/sshd_config") == False:
        print "FAIL"
	logging.info("/etc/ssh/sshd_config not available")
        exit()
    check = open("/etc/ssh/sshd_config","r").read().split('\n')

    status = os.system("/ericsson/security/bin/configure_sshd.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/configure_sshd.py error")
        print "FAIL"
        exit()

    data = open('/etc/ssh/sshd_config', 'r').read().split('\n')
    for line in check:
        if line not in data and line != "#AllowAgentForwarding yes":
            print "FAIL"
	    logging.info("%s not in /etc/ssh/sshd_config earlier" % line)
	    exit()

    print Agent()
