#!/usr/bin/python

import os
import logging
import commands as c
import time

def enable_sshHostKey():

    if os.path.exists("/etc/ssh/ssh_config") == False:
	print "/etc/ssh/ssh_config not found"
        logging.info("/etc/ssh/ssh_config not found")
	return "FAIL"

    data = open('/etc/ssh/ssh_config', 'r').read().split('\n')
    if "Verifyhostkeydns ask" not in data:
	print "Verifyhostkeydns ask not found"
	logging.info("Verifyhostkeydns ask not found")
        return "FAIL"

    if "Verifyhostkeydns yes" in data or "Verifyhostkeydns no" in data:
	logging.info("Verifyhostkeydns yes is present")
	print "Verifyhostkeydns yes is present"
        return "FAIL"

    if "stricthostkeychecking ask" not in data:
	print "stricthostkeychecking ask not found"
	logging.info("stricthostkeychecking ask not found")
        return "FAIL"

    if "stricthostkeychecking yes" in data or "stricthostkeychecking no" in data:
	logging.info("stricthostkeychecking yes found")
	print "stricthostkeychecking yes found"
        return "FAIL"

    return "SUCCESS"

if __name__ == '__main__':

    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_enable_sshHostKey_verification.log'
    pwd = c.getoutput('pwd')+'/log/'
    os.system("mkdir -p "+pwd)
    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename=pwd+fname,
                        format=format_str)

    if os.path.exists("/etc/ssh/ssh_config") == False:
        print  "FAIL"
	logging.info("/etc/ssh/ssh_config not found")
        exit()
    check = open("/etc/ssh/ssh_config","r").read().split('\n')

    status = os.system("/ericsson/security/bin/enable_sshHostKey_verification.py > /dev/null 2>&1")
    if status != 0:
        print "FAIL"
	logging.info("/ericsson/security/bin/enable_sshHostKey_verification.py error")
        exit()

    data = open('/etc/ssh/ssh_config', 'r').read().split('\n')
    for line in check:
        if line not in data and line != "stricthostkeychecking yes" and line != "stricthostkeychecking no" and line != "Verifyhostkeydns yes" and line != "Verifyhostkeydns no":
            print "FAIL"
	    logging.info("%s not found earlier in /etc/ssh/ssh_config " % line) 
            exit()

    print enable_sshHostKey()
