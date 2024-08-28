#!/usr/bin/python

import os
import time
import logging
import commands as c

def disable_X11():

    if os.path.exists("/etc/ssh/sshd_config") == False:
        print "/etc/ssh/sshd_config not found"
        logging.info("/etc/ssh/sshd_config not found")
        return "FAIL"
    
    data = open('/etc/ssh/sshd_config', 'r').read().split('\n')
    if "X11Forwarding no" not in data:
        print "X11 Forwarding not disabled"
        logging.info("X11 Forwarding not disabled")
        return "FAIL"
        
    if "X11Forwarding yes" in data:
        print "X11 Forwarding not disabled"
        logging.info("X11 Forwarding not disabled")
        return "FAIL"
        
    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_disable_X11Forwarding.log'
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

    status = os.system("/ericsson/security/bin/disable_X11Forwarding.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
	logging.info("/ericsson/security/bin/disable_X11Forwarding.py error")
        exit()

    data = open('/etc/ssh/sshd_config', 'r').read().split('\n')
    for line in check:
        if line not in data and line != "#X11Forwarding yes":
            print "FAIL"
	    logging.info("%s is not found earlier in /etc/ssh/sshd_config" % line)
            exit()

    print disable_X11()
