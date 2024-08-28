#!/usr/bin/python

import os
import logging
import time
import commands as c

def disable_TCP():

    if os.path.exists("/etc/ssh/sshd_config") == False:
	logging.info("/etc/ssh/sshd_config not found")
	print "/etc/ssh/sshd_config not found"
        return "FAIL"

    data = open('/etc/ssh/sshd_config', 'r').read().split('\n')
    if "AllowTcpForwarding no" not in data:
	print "AllowTcpForwarding not disabled"
        logging.info("AllowTcpForwarding not disabled")
        return "FAIL"

    if "AllowTcpForwarding yes" in data:
	print "AllowTcpForwarding not disabled"
	logging.info("AllowTcpForwarding not disabled")
        return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_disable_AllowTcpForwarding.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    if os.path.exists("/etc/ssh/sshd_config") == False:
        print "FAIL"
	logging.info("/etc/ssh/sshd_config not found")
        exit()
    check = open("/etc/ssh/sshd_config","r").read().split('\n')

    status = os.system("/ericsson/security/bin/disable_AllowTcpForwarding.py > /dev/null 2>&1")
    if status != 0:
	logging.info("/ericsson/security/bin/disable_AllowTcpForwarding.py error")
        print "FAIL"
	exit()

    data = open('/etc/ssh/sshd_config', 'r').read().split('\n')

    for line in check:
        if line not in data and line != "#AllowTcpForwarding yes":
            print "FAIL"
	    logging.info("%s not present earlier" % line)
            exit()

    print disable_TCP()
